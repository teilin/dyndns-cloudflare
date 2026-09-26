const std = @import("std");
const http = std.http;

const IPIFY_URL = "https://api.ipify.org";
const CLOUDFLARE_DNS_URL = "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}";
const ENV_TOKEN = "CLOUDFLARE_API_TOKEN";
const ENV_ZONE = "CLOUDFLARE_ZONE_ID";
const ENV_RECORD = "CLOUDFLARE_RECORD_ID";
const ENV_RECORD_NAME = "CLOUDFLARE_RECORD_NAME";
const STATE_FILE = "/config/previous_ip.txt";

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Fetch required env vars using init.environ (Environ type)
    const api_token = init.environ.getPosix(ENV_TOKEN) orelse {
        std.log.err("missing {s}", .{ENV_TOKEN});
        std.process.exit(1);
    };
    const zone_id = init.environ.getPosix(ENV_ZONE) orelse {
        std.log.err("missing {s}", .{ENV_ZONE});
        std.process.exit(1);
    };
    const record_id = init.environ.getPosix(ENV_RECORD) orelse {
        std.log.err("missing {s}", .{ENV_RECORD});
        std.process.exit(1);
    };
    const record_name = init.environ.getPosix(ENV_RECORD_NAME) orelse {
        std.log.err("missing {s}", .{ENV_RECORD_NAME});
        std.process.exit(1);
    };

    // Get current public IP
    const current_ip = try getCurrentIP(allocator);
    defer allocator.free(current_ip);
    std.log.info("current public IP: {s}", .{current_ip});

    // Load previous IP from state file (if it exists)
    const prev_ip = loadPreviousIP(allocator);
    defer if (prev_ip) |p| allocator.free(p);

    if (prev_ip) |prev| {
        if (std.mem.eql(u8, current_ip, prev)) {
            std.log.info("IP unchanged ({s}), no action needed", .{current_ip});
            return;
        }
        std.log.info("IP changed: {s} -> {s}", .{ prev, current_ip });
    } else {
        std.log.info("no previous IP on record, will update DNS", .{});
    }

    // Check current DNS record value on Cloudflare
    const dns_ip = try getDNSRecordIP(allocator, api_token, zone_id, record_id);
    defer if (dns_ip) |p| allocator.free(p);

    if (dns_ip) |dns| {
        if (std.mem.eql(u8, current_ip, dns)) {
            std.log.info("DNS record already correct ({s}), skipping update", .{dns});
            try savePreviousIP(allocator, current_ip);
            return;
        }
        std.log.info("DNS record mismatch: Cloudflare has {s}, expected {s}", .{ dns, current_ip });
    }

    // Update DNS record
    try updateDNSRecord(allocator, api_token, zone_id, record_id, record_name, current_ip);
    try savePreviousIP(allocator, current_ip);
    std.log.info("DNS record updated successfully", .{});
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build an http.Client with no proxy (suitable for container/NAS use)
fn makeClient(allocator: std.mem.Allocator) !http.Client {
    return http.Client{ .allocator = allocator };
}

/// GET current public IP from api.ipify.org (returns plaintext IP on 200)
fn getCurrentIP(allocator: std.mem.Allocator) ![]u8 {
    var client = try makeClient(allocator);
    defer client.deinit();

    const uri = try std.Uri.parse(IPIFY_URL);
    var req = try client.request(.GET, uri, .{
        .extra_headers = &.{
            .{ .name = "Accept", .value = "text/plain" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();
    var response = try req.receiveHead(&.{});
    defer response.deinit();

    if (response.status != 200) {
        std.log.err("ipify returned status {d}", .{@intFromEnum(response.status)});
        return error.IpifyFailed;
    }

    // Read body into a stack buffer then duplicate to heap
    var buf: [64]u8 = undefined;
    const n = try response.reader().readAll(&buf);
    return std.mem.trim(u8, try allocator.dupe(u8, buf[0..n]), "\n\r ");
}

/// GET the current DNS record content field from Cloudflare
fn getDNSRecordIP(allocator: std.mem.Allocator, api_token: []const u8, zone_id: []const u8, record_id: []const u8) !?[]u8 {
    var client = try makeClient(allocator);
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, CLOUDFLARE_DNS_URL, .{ .zone_id = zone_id, .record_id = record_id });
    defer allocator.free(url);
    const uri = try std.Uri.parse(url);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_token});
    defer allocator.free(auth);

    var req = try client.request(.GET, uri, .{
        .extra_headers = &.{
            .{ .name = "Authorization", .value = auth },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();
    var response = try req.receiveHead(&.{});
    defer response.deinit();

    if (response.status != 200) return null;

    var body = std.array_list.AlignedManaged(u8, null).init(allocator);
    defer body.deinit();
    try response.reader().readAllArrayList(&body, 8192);

    return parseJSONField(allocator, body.items, "content");
}

/// PATCH the DNS record to new_ip
fn updateDNSRecord(allocator: std.mem.Allocator, api_token: []const u8, zone_id: []const u8, record_id: []const u8, record_name: []const u8, new_ip: []const u8) !void {
    var client = try makeClient(allocator);
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, CLOUDFLARE_DNS_URL, .{ .zone_id = zone_id, .record_id = record_id });
    defer allocator.free(url);
    const uri = try std.Uri.parse(url);

    const body_str = try std.fmt.allocPrint(allocator,
        \\{{"type":"A","name":"{s}","content":"{s}"}}
    , .{ record_name, new_ip });
    defer allocator.free(body_str);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_token});
    defer allocator.free(auth);

    var req = try client.request(.PATCH, uri, .{
        .extra_headers = &.{
            .{ .name = "Authorization", .value = auth },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer req.deinit();

    try req.sendBodyComplete(body_str);
    var response = try req.receiveHead(&.{});
    defer response.deinit();

    if (response.status != 200) {
        std.log.err("Cloudflare returned status {d}", .{@intFromEnum(response.status)});
        return error.CloudflareUpdateFailed;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal JSON parser — no external deps
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the string value of top-level `"key":"value"` from JSON.
/// Returns owned slice (caller frees). Returns null if not found.
fn parseJSONField(allocator: std.mem.Allocator, json: []const u8, key: []const u8) !?[]u8 {
    const search = try std.mem.concat(allocator, u8, &.{ "\"", key, "\":" });
    defer allocator.free(search);
    const idx = std.mem.indexOf(u8, json, search) orelse return null;
    const val_start = idx + search.len;
    if (val_start >= json.len or json[val_start] != '"') return null;
    const val_body = json[val_start + 1 ..];
    const val_end = std.mem.indexOfScalar(u8, val_body, '"') orelse return null;
    return try allocator.dupe(u8, val_body[0..val_end]);
}

// ─────────────────────────────────────────────────────────────────────────────
// State file helpers  (std.c for 0.16.0)
// ─────────────────────────────────────────────────────────────────────────────

fn loadPreviousIP(allocator: std.mem.Allocator) !?[]u8 {
    const c = std.c;
    const path_z = try allocator.dupeZ(u8, STATE_FILE);
    defer allocator.free(path_z);
    const fd = c.openat(c.AT.FDCWD, path_z, c.O{ .ACCMODE = .RDONLY }, 0);
    if (fd == -1) return null;
    defer _ = c.close(fd);
    var buf: [64]u8 = undefined;
    const n = c.read(fd, &buf, buf.len);
    if (n <= 0) return null;
    return std.mem.trim(u8, try allocator.dupe(u8, buf[0..n]), "\n\r ");
}

fn savePreviousIP(allocator: std.mem.Allocator, ip: []const u8) !void {
    const c = std.c;
    _ = c.mkdirat(c.AT.FDCWD, "/config", 0o755);
    const path_z = try allocator.dupeZ(u8, STATE_FILE);
    defer allocator.free(path_z);
    const fd = c.openat(c.AT.FDCWD, path_z, c.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (fd == -1) return error.FileWriteFailed;
    defer _ = c.close(fd);
    _ = c.write(fd, ip.ptr, ip.len);
}
