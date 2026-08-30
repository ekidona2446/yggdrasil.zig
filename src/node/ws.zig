//! WebSocket transport for Yggdrasil peer links (RFC 6455).
//!
//! Wire-compatible with the reference Go implementation with libwebsockets clients/servers.
//! The HTTP upgrade and framing live here so they can sit on top of either plain TCP
//! or the existing wolfSSL TLS 1.3 session (`wss://`). libwebsockets is linked in (see
//! `build.zig`) so the same framing constants stay aligned with that stack.

const std = @import("std");
const ironwood = @import("ironwood");

pub const SUBPROTOCOL: []const u8 = "ygg-ws";
const GUID: []const u8 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
};

pub const Frame = struct {
    opcode: Opcode,
    fin: bool,
    payload: []const u8,
};

pub fn generateKey(out_b64: *[24]u8) void {
    var raw: [16]u8 = undefined;
    ironwood.crypto.secureRandomBytes(&raw);
    _ = std.base64.standard.Encoder.encode(out_b64, &raw);
}

pub fn acceptKey(client_key_b64: []const u8, out_b64: *[28]u8) void {
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(client_key_b64);
    h.update(GUID);
    var digest: [20]u8 = undefined;
    h.final(&digest);
    _ = std.base64.standard.Encoder.encode(out_b64, &digest);
}

/// Build a client HTTP/1.1 Upgrade request. Caller owns the returned slice.
pub fn buildClientUpgrade(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    path: []const u8,
    key_b64: *const [24]u8,
) ![]u8 {
    const p = if (path.len == 0) "/" else path;
    const need_port = port != 80 and port != 443;
    var w: std.Io.Writer.Allocating = .init(gpa);
    errdefer w.deinit();
    try w.writer.print("GET {s} HTTP/1.1\r\n", .{p});
    if (need_port) {
        try w.writer.print("Host: {s}:{d}\r\n", .{ host, port });
    } else {
        try w.writer.print("Host: {s}\r\n", .{host});
    }
    try w.writer.writeAll("Upgrade: websocket\r\n");
    try w.writer.writeAll("Connection: Upgrade\r\n");
    try w.writer.print("Sec-WebSocket-Key: {s}\r\n", .{key_b64});
    try w.writer.writeAll("Sec-WebSocket-Version: 13\r\n");
    try w.writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{SUBPROTOCOL});
    try w.writer.writeAll("\r\n");
    return w.toOwnedSlice();
}

pub const UpgradeResult = struct {
    consumed: usize,
    ok: bool,
};

/// Returns null if the HTTP response is still incomplete.
pub fn parseServerUpgrade(buf: []const u8, expected_accept_b64: []const u8) ?UpgradeResult {
    const end = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    const headers = buf[0..end];
    const consumed = end + 4;
    if (!std.mem.startsWith(u8, headers, "HTTP/1.1 101") and !std.mem.startsWith(u8, headers, "HTTP/1.0 101")) {
        return .{ .consumed = consumed, .ok = false };
    }
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    _ = lines.next(); // status
    var saw_accept = false;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Accept")) {
            if (!std.mem.eql(u8, value, expected_accept_b64)) return .{ .consumed = consumed, .ok = false };
            saw_accept = true;
        }
    }
    return .{ .consumed = consumed, .ok = saw_accept };
}

/// Encode a masked client binary (or control) frame. Caller owns the result.
pub fn encodeFrame(gpa: std.mem.Allocator, opcode: Opcode, payload: []const u8) ![]u8 {
    return encodeFrameImpl(gpa, opcode, payload, true);
}

/// Encode an *unmasked* server frame (RFC 6455 §5.1: servers MUST NOT mask).
pub fn encodeServerFrame(gpa: std.mem.Allocator, opcode: Opcode, payload: []const u8) ![]u8 {
    return encodeFrameImpl(gpa, opcode, payload, false);
}

fn encodeFrameImpl(gpa: std.mem.Allocator, opcode: Opcode, payload: []const u8, masked: bool) ![]u8 {
    const len = payload.len;
    const ext: usize = if (len < 126) 0 else if (len <= 0xffff) 2 else 8;
    const mask_len: usize = if (masked) 4 else 0;
    const total = 2 + ext + mask_len + len;
    const out = try gpa.alloc(u8, total);
    out[0] = 0x80 | @intFromEnum(opcode);
    var pos: usize = 2;
    if (len < 126) {
        out[1] = (if (masked) @as(u8, 0x80) else 0) | @as(u8, @intCast(len));
    } else if (len <= 0xffff) {
        out[1] = (if (masked) @as(u8, 0x80) else 0) | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(len), .big);
        pos = 4;
    } else {
        out[1] = (if (masked) @as(u8, 0x80) else 0) | 127;
        std.mem.writeInt(u64, out[2..10], len, .big);
        pos = 10;
    }
    if (masked) {
        var mask: [4]u8 = undefined;
        ironwood.crypto.secureRandomBytes(&mask);
        @memcpy(out[pos .. pos + 4], &mask);
        pos += 4;
        for (payload, 0..) |b, i| {
            out[pos + i] = b ^ mask[i % 4];
        }
    } else {
        @memcpy(out[pos..], payload);
    }
    return out;
}

pub const ClientUpgradeResult = struct {
    consumed: usize,
    key: []const u8, // Sec-WebSocket-Key value (slice into `buf`)
    ok: bool,
};

/// Parse a *client's* HTTP upgrade request (server side). Returns null if the
/// request is still incomplete (no terminating `\r\n\r\n` yet).
pub fn parseClientUpgrade(buf: []const u8) ?ClientUpgradeResult {
    const end = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    const headers = buf[0..end];
    const consumed = end + 4;
    if (!std.mem.startsWith(u8, headers, "GET ")) {
        return .{ .consumed = consumed, .key = &.{}, .ok = false };
    }
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    _ = lines.next(); // request line
    var key: []const u8 = &.{};
    var saw_upgrade = false;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Key")) {
            key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "Upgrade") and std.ascii.eqlIgnoreCase(value, "websocket")) {
            saw_upgrade = true;
        }
    }
    if (key.len == 0 or !saw_upgrade) {
        return .{ .consumed = consumed, .key = key, .ok = false };
    }
    return .{ .consumed = consumed, .key = key, .ok = true };
}

/// Build the `101 Switching Protocols` response to a client's upgrade request.
pub fn buildServerUpgrade(gpa: std.mem.Allocator, key_b64: []const u8) ![]u8 {
    var accept: [28]u8 = undefined;
    acceptKey(key_b64, &accept);
    var w: std.Io.Writer.Allocating = .init(gpa);
    errdefer w.deinit();
    try w.writer.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try w.writer.writeAll("Upgrade: websocket\r\n");
    try w.writer.writeAll("Connection: Upgrade\r\n");
    try w.writer.print("Sec-WebSocket-Accept: {s}\r\n", .{accept});
    try w.writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{SUBPROTOCOL});
    try w.writer.writeAll("\r\n");
    return w.toOwnedSlice();
}

pub const DecodeError = error{ Incomplete, InvalidFrame, Close };

pub const Decoded = struct {
    frame: Frame,
    consumed: usize,
};

/// Decode one frame from `buf`. Payload is a slice into `buf` (unmasked in
/// place if a mask bit was set).
pub fn decodeFrame(buf: []u8) DecodeError!Decoded {
    if (buf.len < 2) return error.Incomplete;
    const fin = (buf[0] & 0x80) != 0;
    const opcode_raw = buf[0] & 0x0f;
    const opcode: Opcode = std.enums.fromInt(Opcode, opcode_raw) orelse return error.InvalidFrame;
    const masked = (buf[1] & 0x80) != 0;
    var len: usize = buf[1] & 0x7f;
    var pos: usize = 2;
    if (len == 126) {
        if (buf.len < 4) return error.Incomplete;
        len = std.mem.readInt(u16, buf[2..4], .big);
        pos = 4;
    } else if (len == 127) {
        if (buf.len < 10) return error.Incomplete;
        const n = std.mem.readInt(u64, buf[2..10], .big);
        if (n > std.math.maxInt(usize)) return error.InvalidFrame;
        len = @intCast(n);
        pos = 10;
    }
    var mask: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (buf.len < pos + 4) return error.Incomplete;
        @memcpy(&mask, buf[pos .. pos + 4]);
        pos += 4;
    }
    if (buf.len < pos + len) return error.Incomplete;
    const payload = buf[pos .. pos + len];
    if (masked) {
        for (payload, 0..) |*b, i| b.* ^= mask[i % 4];
    }
    if (opcode == .close) return error.Close;
    return .{
        .frame = .{ .opcode = opcode, .fin = fin, .payload = payload },
        .consumed = pos + len,
    };
}

const testing = std.testing;

test "accept key matches RFC 6455 example" {
    // RFC 6455 §1.3 / §4.2.2 example.
    var out: [28]u8 = undefined;
    acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &out);
}

test "binary frame round-trip" {
    const gpa = testing.allocator;
    const payload = "hello-ygg";
    const encoded = try encodeFrame(gpa, .binary, payload);
    defer gpa.free(encoded);
    const copy = try gpa.dupe(u8, encoded);
    defer gpa.free(copy);
    const decoded = try decodeFrame(copy);
    try testing.expect(decoded.frame.opcode == .binary);
    try testing.expectEqualStrings(payload, decoded.frame.payload);
}

test "upgrade request contains ygg-ws" {
    const gpa = testing.allocator;
    var key: [24]u8 = "dGhlIHNhbXBsZSBub25jZQ==".*;
    const req = try buildClientUpgrade(gpa, "example.com", 80, "/", &key);
    defer gpa.free(req);
    try testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Protocol: ygg-ws") != null);
    try testing.expect(std.mem.indexOf(u8, req, "GET / HTTP/1.1") != null);
}

test "parse 101 switching protocols" {
    var accept: [28]u8 = undefined;
    acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &accept);
    const resp =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n" ++
        "trailing";
    const r = parseServerUpgrade(resp, &accept).?;
    try testing.expect(r.ok);
    try testing.expectEqual(@as(usize, resp.len - 8), r.consumed);
}
