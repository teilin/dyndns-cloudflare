const std = @import("std");
const http = std.http;
const c = std.c;

const IPIFY_URL = "https://api.ipify.org";
const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";
const ENV_TOKEN = "CLOUDFLARE_API_TOKEN";
const ENV_ZONE = "CLOUDFLARE_ZONE_ID";
const ENV_RECORD = "CLOUDFLARE_RECORD_ID";
const ENV_RECORD_NAME = "CLOUDFLARE_RECORD_NAME";
const STATE_FILE = "/config/previous_ip.txt";

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const env = init.minimal.environ;

    const api_token = env.getPosix(ENV_TOKEN) orelse {
        std.log.err("missing {s}", .{ENV_TOKEN});
        std.process.exit(1);
    };
    const zone_id = env.getPosix(ENV_ZONE) orelse {
        std.log.err("missing {s}", .{ENV_ZONE});
        std.process.exit(1);
    };
    const record_id = env.getPosix(ENV_RECORD) orelse {
        std.log.err("missing {s}", .{ENV_RECORD});
        std.process.exit(1);
    };
    const record_name = env.getPosix(ENV_RECORD_NAME) orelse {
        std.log.err("missing {s}", .{ENV_RECORD_NAME});
        std.process.exit(1);
    };

    // 1. Current public IP
    const current_ip = try httpBody(io, allocator, .GET, IPIFY_URL, null, null);
    defer allocator.free(current_ip);
    std.log.info("current public IP: {s}", .{current_ip});

    // 2. Previous known IP (local state file)
    const prev_ip = try loadPreviousIP(allocator);
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

    // 3. Build the Cloudflare DNS URL once
    const dns_url = try std.mem.concat(allocator, u8, &.{ CLOUDFLARE_API_BASE, "/zones/", zone_id, "/dns_records/", record_id });
    defer allocator.free(dns_url);

    // 4. Current DNS record value from Cloudflare
    const get_resp = try httpFetch(io, allocator, .GET, dns_url, api_token, null);
    defer if (get_resp.body) |b| allocator.free(b);

    if (get_resp.status == 200) {
        if (get_resp.body) |dns_json| {
            const dns_field = try parseJSONField(allocator, dns_json, "content");
            defer if (dns_field) |f| allocator.free(f);
            if (dns_field) |dns_val| {
                if (std.mem.eql(u8, current_ip, dns_val)) {
                    std.log.info("DNS record already correct ({s}), skipping update", .{dns_val});
                    try savePreviousIP(allocator, current_ip);
                    return;
                }
                std.log.info("DNS record mismatch: Cloudflare has {s}, expected {s}", .{ dns_val, current_ip });
            }
        }
    } else {
        std.log.info("Cloudflare GET returned HTTP {d}", .{get_resp.status});
    }

    // 5. Build PATCH body and update DNS record
    const body = try std.fmt.allocPrint(allocator,
        \\{{"type":"A","name":"{s}","content":"{s}"}}
    , .{ record_name, current_ip });
    defer allocator.free(body);

    const patch_resp = try httpFetch(io, allocator, .PATCH, dns_url, api_token, body);
    defer if (patch_resp.body) |b| allocator.free(b);

    if (patch_resp.status != 200) {
        std.log.err("Cloudflare PATCH returned {d}: {s}", .{ patch_resp.status, patch_resp.body orelse "" });
        return error.CloudflareUpdateFailed;
    }

    try savePreviousIP(allocator, current_ip);
    std.log.info("DNS record updated successfully", .{});
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP client via std.http.Client — handles TLS, redirects, chunking
// ─────────────────────────────────────────────────────────────────────────────

const HttpResponse = struct {
    status: u16,
    body: ?[]u8,
};

/// One-shot HTTP request; returns captured status and body.
fn httpFetch(io: std.Io, allocator: std.mem.Allocator, method: http.Method, url: []const u8, bearer: ?[]const u8, payload: ?[]const u8) !HttpResponse {
    var client = http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    // Build Authorization header if a token was provided.
    var headers = std.array_list.AlignedManaged(http.Header, null).init(allocator);
    defer headers.deinit();
    if (bearer) |token| {
        try headers.append(.{ .name = "Authorization", .value = token });
    }

    var response_writer: std.Io.Writer.Allocating = .init(allocator);
    defer response_writer.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .response_writer = &response_writer.writer,
        .extra_headers = headers.items,
    }) catch |err| {
        std.log.err("HTTP request to {s} failed: {any}", .{ url, err });
        return HttpResponse{ .status = 0, .body = null };
    };

    // Extract body from the allocating writer.
    var body_al = response_writer.toArrayList();
    defer body_al.deinit(allocator);
    const body_bytes = body_al.items;

    return HttpResponse{
        .status = @intFromEnum(result.status),
        .body = if (body_bytes.len > 0) try allocator.dupe(u8, body_bytes) else null,
    };
}

/// GET that returns the trimmed body, erroring on non-200.
fn httpBody(io: std.Io, allocator: std.mem.Allocator, method: http.Method, url: []const u8, bearer: ?[]const u8, payload: ?[]const u8) ![]u8 {
    const resp = try httpFetch(io, allocator, method, url, bearer, payload);
    defer if (resp.body) |b| allocator.free(b);
    if (resp.status != 200 or resp.body == null) {
        std.log.err("request to {s} returned HTTP {d}", .{ url, resp.status });
        return error.HttpRequestFailed;
    }
    return resp.body.?;
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal JSON parser — no external deps
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the string value of `"key":"value"` where value is a JSON string.
/// Returns owned slice (caller frees); null if not found.
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
    const path_z = try allocator.dupeZ(u8, STATE_FILE);
    defer allocator.free(path_z);
    const fd = c.openat(c.AT.FDCWD, path_z, c.O{ .ACCMODE = .RDONLY }, @as(c.mode_t, 0));
    if (fd == -1) return null;
    defer _ = c.close(fd);
    var buf: [64]u8 = undefined;
    const n = c.read(fd, &buf, buf.len);
    if (n <= 0) return null;
    return try allocator.dupe(u8, std.mem.trim(u8, buf[0..@intCast(n)], "\n\r "));
}

fn savePreviousIP(allocator: std.mem.Allocator, ip: []const u8) !void {
    _ = c.mkdirat(c.AT.FDCWD, "/config", 0o755);
    const path_z = try allocator.dupeZ(u8, STATE_FILE);
    defer allocator.free(path_z);
    const fd = c.openat(c.AT.FDCWD, path_z, c.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(c.mode_t, 0o644));
    if (fd == -1) return error.FileWriteFailed;
    defer _ = c.close(fd);
    _ = c.write(fd, ip.ptr, ip.len);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseJSONField root string" {
    const json = "{\"result\":{\"content\":\"1.2.3.4\"}}";
    const v = try parseJSONField(testing.allocator, json, "content");
    defer if (v) |x| testing.allocator.free(x);
    try testing.expect(v != null);
    try testing.expectEqualStrings("1.2.3.4", v.?);
}

test "parseJSONField missing" {
    const json = "{\"a\":1}";
    const v: ?[]u8 = try parseJSONField(testing.allocator, json, "content");
    try testing.expect(v == null);
}

test "parseJSONField nested key" {
    const json = "\"name\":\"vpn.devgeek.io\",\"content\":\"9.9.9.9\"";
    const v = try parseJSONField(testing.allocator, json, "name");
    defer if (v) |x| testing.allocator.free(x);
    try testing.expect(v != null);
    try testing.expectEqualStrings("vpn.devgeek.io", v.?);
}
