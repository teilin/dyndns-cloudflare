const std = @import("std");
const c = std.c;

const IPIFY_HOST = "api.ipify.org";
const IPIFY_PATH = "/";
const CLOUDFLARE_API = "api.cloudflare.com";
const CLOUDFLARE_DNS_PATH = "/client/v4/zones/{zone_id}/dns_records/{record_id}";
const ENV_TOKEN = "CLOUDFLARE_API_TOKEN";
const ENV_ZONE = "CLOUDFLARE_ZONE_ID";
const ENV_RECORD = "CLOUDFLARE_RECORD_ID";
const ENV_RECORD_NAME = "CLOUDFLARE_RECORD_NAME";
const STATE_FILE = "/config/previous_ip.txt";

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
    const current_ip = try httpGet(allocator, IPIFY_HOST, IPIFY_PATH, null, null);
    defer allocator.free(current_ip);
    std.log.info("current public IP: {s}", .{current_ip});

    // Load previous IP
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

    // Check current DNS record on Cloudflare
    const dns_url = try std.fmt.allocPrint(allocator, CLOUDFLARE_DNS_PATH, .{ .zone_id = zone_id, .record_id = record_id });
    defer allocator.free(dns_url);

    const dns_ip = try httpGet(allocator, CLOUDFLARE_API, dns_url, api_token, null);
    defer if (dns_ip) |p| allocator.free(p);

    if (dns_ip) |dns| {
        if (std.mem.eql(u8, current_ip, dns)) {
            std.log.info("DNS record already correct ({s}), skipping update", .{dns});
            try savePreviousIP(allocator, current_ip);
            return;
        }
        std.log.info("DNS record mismatch: Cloudflare has {s}, expected {s}", .{ dns, current_ip });
    }

    // Build PATCH body
    const body = try std.fmt.allocPrint(allocator,
        \\{{"type":"A","name":"{s}","content":"{s}"}}
    , .{ record_name, current_ip });
    defer allocator.free(body);

    const resp = try httpPatch(allocator, CLOUDFLARE_API, dns_url, api_token, body);
    defer if (resp.body) |b| allocator.free(b);

    if (resp.status != 200) {
        std.log.err("Cloudflare PATCH returned {d}: {s}", .{ resp.status, resp.body orelse "" });
        return error.CloudflareUpdateFailed;
    }

    try savePreviousIP(allocator, current_ip);
    std.log.info("DNS record updated successfully", .{});
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP client — std.c sockets + manual TLS via Zig's crypto
// ─────────────────────────────────────────────────────────────────────────────

const HttpResponse = struct {
    status: u16,
    body: ?[]u8,
};

/// Perform a GET request over a TLS socket.
fn httpGet(allocator: std.mem.Allocator, host: []const u8, path: []const u8, bearer: ?[]const u8, body: ?[]const u8) (error{} || std.mem.Allocator.Error || std.crypto.tls.Client.Error)!?[]u8 {
    const is_https = true;

    // Resolve host
    const addr = try dnsResolve(allocator, host);
    defer allocator.free(addr);
    if (addr.len == 0) return null;

    const port: u16 = if (is_https) 443 else 80;
    const sock = try tcpConnect(addr[0], port);
    defer _ = c.close(sock);

    var tls_client: ?std.crypto.tls.Client = null;
    var tls_buf: [8192]u8 = undefined;
    var tls_buf_offset: usize = 0;
    var tls_read_buf: [8192]u8 = undefined;

    if (is_https) {
        const socket = std.net.Stream{ .handle = sock };
        tls_client = std.crypto.tls.Client.init(socket, .{
            .ca_bundle = std.crypto.Certificate.Bundle{},
            .peer_name = host,
        }) catch return null;
    }

    defer if (tls_client) |*c2| c2.deinit();

    // Build and send HTTP request
    const req = buildHttpRequest(host, path, bearer, null, null);
    if (is_https) {
        if (tls_client) |*c2| {
            _ = c2.writer().writeAll(req) catch return null;
            c2.writer().flush() catch return null;
        }
    } else {
        _ = c.write(sock, req.ptr, req.len);
    }

    // Read response
    var response_buf = std.array_list.AlignedManaged(u8, null).init(allocator);
    defer response_buf.deinit();

    if (is_https) {
        if (tls_client) |*c2| {
            // Read until connection closes or we have enough
            var done = false;
            while (!done) {
                const n = c2.reader().read(&tls_read_buf) catch break;
                if (n == 0) done = true;
                response_buf.appendSliceAssumeCapacity(tls_read_buf[0..n]);
                // Simple EOF detection
                if (n < tls_read_buf.len) done = true;
            }
        }
    } else {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = c.read(sock, &buf, buf.len);
            if (n <= 0) break;
            response_buf.appendSliceAssumeCapacity(buf[0..n]);
            if (@as(u64, @intCast(n)) < buf.len) break;
        }
    }

    return parseHttpResponse(allocator, response_buf.items);
}

/// Perform a PATCH request.
fn httpPatch(allocator: std.mem.Allocator, host: []const u8, path: []const u8, bearer: []const u8, body: []const u8) (error{} || std.mem.Allocator.Error || std.crypto.tls.Client.Error)!HttpResponse {
    const addr = try dnsResolve(allocator, host);
    defer allocator.free(addr);
    if (addr.len == 0) return HttpResponse{ .status = 0, .body = null };

    const sock = try tcpConnect(addr[0], 443);
    defer _ = c.close(sock);

    const socket = std.net.Stream{ .handle = sock };
    var tls = std.crypto.tls.Client.init(socket, .{
        .ca_bundle = std.crypto.Certificate.Bundle{},
        .peer_name = host,
    }) catch return HttpResponse{ .status = 0, .body = null };
    defer tls.deinit();

    const content_len = body.len;
    const req = buildHttpRequest(host, path, bearer, "application/json", content_len);
    var w = tls.writer();
    w.writeAll(req) catch return HttpResponse{ .status = 0, .body = null };
    w.writeAll(body) catch return HttpResponse{ .status = 0, .body = null };
    w.flush() catch return HttpResponse{ .status = 0, .body = null };

    var response_buf = std.array_list.AlignedManaged(u8, null).init(allocator);
    errdefer response_buf.deinit();

    var tls_read_buf: [8192]u8 = undefined;
    var done = false;
    while (!done) {
        const n = tls.reader().read(&tls_read_buf) catch break;
        if (n == 0) done = true;
        response_buf.appendSliceAssumeCapacity(tls_read_buf[0..n]);
        if (@as(u64, @intCast(n)) < tls_read_buf.len) done = true;
    }

    return parseHttpResponseAlloc(allocator, response_buf.items);
}

fn buildHttpRequest(host: []const u8, path: []const u8, bearer: ?[]const u8, content_type: ?[]const u8, content_length: ?usize) []u8 {
    var req = std.ArrayList(u8).init(std.heap.page_allocator);
    req.appendSliceAssumeCapacity("GET ");
    req.appendSliceAssumeCapacity(path);
    req.appendSliceAssumeCapacity(" HTTP/1.1\r\nHost: ");
    req.appendSliceAssumeCapacity(host);
    req.appendSliceAssumeCapacity("\r\nUser-Agent: ipwatch/1.0\r\n");
    if (bearer) |tok| {
        req.appendSliceAssumeCapacity("Authorization: Bearer ");
        req.appendSliceAssumeCapacity(tok);
        req.appendSliceAssumeCapacity("\r\n");
    }
    if (content_type) |ct| {
        req.appendSliceAssumeCapacity("Content-Type: ");
        req.appendSliceAssumeCapacity(ct);
        req.appendSliceAssumeCapacity("\r\n");
    }
    if (content_length) |len| {
        req.appendSliceAssumeCapacity("Content-Length: ");
        const len_str = std.fmt.allocPrint(std.heap.page_allocator, "{d}", .{len}) catch "";
        req.appendSliceAssumeCapacity(len_str);
        req.appendSliceAssumeCapacity("\r\n");
    }
    req.appendSliceAssumeCapacity("Connection: close\r\n");
    req.appendSliceAssumeCapacity("\r\n");
    return req.toOwnedSlice() catch "";
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS resolution  (std.c getaddrinfo)
// ─────────────────────────────────────────────────────────────────────────────

fn dnsResolve(allocator: std.mem.Allocator, host: []const u8) ![]std.os.linux.sockaddr.in {
    const c2 = std.c;
    const hints = c2.addrinfo{
        .family = c2.AF.INET,
        .socktype = c2.SOCK.STREAM,
        .protocol = 0,
        .flags = 0,
        .address = undefined,
        .canonicalname = null,
        .next = null,
    };
    var result: [*]c2.addrinfo = undefined;
    const host_z = try allocator.dupeZ(u8, host);
    defer allocator.free(host_z);
    const rc = c2.getaddrinfo(host_z, null, &hints, &result);
    if (rc != 0) return error.DNSFailed;
    defer c2.freeaddrinfo(result);

    var addrs: [4]std.os.linux.sockaddr.in = undefined;
    var count: usize = 0;
    var it: [*]c2.addrinfo = result;
    while (it != null and count < addrs.len) : (it = it.?.next) {
        if (it.?.family == c2.AF.INET) {
            addrs[count] = @as(*const std.os.linux.sockaddr.in, @ptrCast(it.?.addr)).*;
            count += 1;
        }
    }
    return try allocator.dupe(std.os.linux.sockaddr.in, addrs[0..count]);
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP connect  (std.c socket + connect)
// ─────────────────────────────────────────────────────────────────────────────

fn tcpConnect(addr: std.os.linux.sockaddr.in, port: u16) !c_int {
    const c2 = std.c;
    const sock = c2.socket(c2.AF.INET, c2.SOCK.STREAM, 0);
    if (sock == -1) return error.SocketFailed;
    errdefer _ = c2.close(sock);

    var addr2 = addr;
    addr2.port = std.mem.nativeToBig(u16, port);
    const rc = c2.connect(sock, @ptrCast(&addr2), @sizeOf(std.os.linux.sockaddr.in));
    if (rc == -1) return error.ConnectFailed;

    return sock;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP response parser
// ─────────────────────────────────────────────────────────────────────────────

fn parseHttpResponse(allocator: std.mem.Allocator, data: []const u8) !?[]u8 {
    // Find status line
    const eoh = std.mem.indexOfScalar(u8, data, '\r') orelse return null;
    const status_line = data[0..eoh];
    const status = parseStatusCode(status_line) orelse return null;

    // Skip headers
    const body_start = std.mem.indexOfString(data, "\r\n\r\n") orelse return null;
    const body = data[body_start + 4 ..];

    if (status == 200) {
        return try allocator.dupe(u8, body);
    }
    return null;
}

fn parseHttpResponseAlloc(allocator: std.mem.Allocator, data: []const u8) !HttpResponse {
    const eoh = std.mem.indexOfScalar(u8, data, '\r') orelse return HttpResponse{ .status = 0, .body = null };
    const status = parseStatusCode(data[0..eoh]) orelse HttpResponse{ .status = 0, .body = null };
    const body_start = std.mem.indexOfString(data, "\r\n\r\n") orelse data.len;
    const body = if (body_start < data.len) data[body_start + 4 ..] else data[0..0];
    const body_copy = if (body.len > 0) try allocator.dupe(u8, body) else null;
    return HttpResponse{ .status = status, .body = body_copy };
}

fn parseStatusCode(line: []const u8) ?u16 {
    // "HTTP/1.1 200 OK" — find the 3-digit status code
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    const second_space = std.mem.indexOfScalar(u8, line[first_space + 1 ..], ' ') orelse return null;
    const code_str = line[first_space + 1 .. first_space + 1 + second_space];
    return std.fmt.parseInt(u16, code_str, 10) catch null;
}

// ─────────────────────────────────────────────────────────────────────────────
// State file helpers  (std.c for 0.16.0)
// ─────────────────────────────────────────────────────────────────────────────

fn loadPreviousIP(allocator: std.mem.Allocator) !?[]u8 {
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
    _ = c.mkdirat(c.AT.FDCWD, "/config", 0o755);
    const path_z = try allocator.dupeZ(u8, STATE_FILE);
    defer allocator.free(path_z);
    const fd = c.openat(c.AT.FDCWD, path_z, c.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (fd == -1) return error.FileWriteFailed;
    defer _ = c.close(fd);
    _ = c.write(fd, ip.ptr, ip.len);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseStatusCode" {
    try testing.expectEqual(@as(u16, 200), parseStatusCode("HTTP/1.1 200 OK").?);
    try testing.expectEqual(@as(u16, 201), parseStatusCode("HTTP/1.1 201 Created").?);
    try testing.expectEqual(@as(u16, 400), parseStatusCode("HTTP/1.0 400 Bad Request").?);
    try testing.expectEqual(@as(u16, 404), parseStatusCode("HTTP/1.1 404 Not Found").?);
    try testing.expectEqual(@as(u16, 200), parseStatusCode("HTTP/2 200 OK").?);
    try testing.expect(null, parseStatusCode("invalid"));
    try testing.expect(null, parseStatusCode("200 OK").?);
}

test "parseHttpResponse" {
    const data =
        \\HTTP/1.1 200 OK\r
        \\Content-Type: text/plain\r
        \\Content-Length: 7\r
        \\\r
        \\1.2.3.4
    ;
    const ip = try parseHttpResponse(testing.allocator, data);
    defer if (ip) |p| testing.allocator.free(p);
    try testing.expect(ip != null);
    try testing.expectEqualStrings("1.2.3.4", ip.?);
}

test "parseHttpResponseAlloc" {
    const data =
        \\HTTP/1.1 200 OK\r
        \\Content-Type: application/json\r
        \\\r
        \\{"result":{"content":"9.9.9.9"}}
    ;
    const resp = try parseHttpResponseAlloc(testing.allocator, data);
    defer if (resp.body) |b| testing.allocator.free(b);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.body != null);
    try testing.expectEqualStrings("{\"result\":{\"content\":\"9.9.9.9\"}}", resp.body.?);
}

test "buildHttpRequest GET" {
    const req = buildHttpRequest("example.com", "/", null, null, null);
    defer std.heap.page_allocator.free(req);
    try testing.expect(std.mem.indexOf(u8, req, "GET / HTTP/1.1").? >= 0);
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.com").? >= 0);
    try testing.expect(std.mem.indexOf(u8, req, "Connection: close").? >= 0);
}

test "buildHttpRequest with bearer" {
    const req = buildHttpRequest("api.cloudflare.com", "/test", "mytoken", null, null);
    defer std.heap.page_allocator.free(req);
    try testing.expect(std.mem.indexOf(u8, req, "Authorization: Bearer mytoken").? >= 0);
}

test "buildHttpRequest with content-length" {
    const req = buildHttpRequest("api.cloudflare.com", "/test", null, "application/json", 25);
    defer std.heap.page_allocator.free(req);
    try testing.expect(std.mem.indexOf(u8, req, "Content-Length: 25").? >= 0);
    try testing.expect(std.mem.indexOf(u8, req, "Content-Type: application/json").? >= 0);
}
