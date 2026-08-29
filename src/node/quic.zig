//! QUIC transport for Yggdrasil peer links (RFC 9000/9001).
//!
//! Yggdrasil-go's `quic://` peers speak QUIC over UDP, then run the same
//! ironwood metadata handshake on the first client-initiated bidirectional
//! STREAM. We drive zquic's `Client` in raw-application-stream mode (no HTTP/3)
//! and treat that stream as a reliable byte pipe, same as TCP/TLS/WS.

const std = @import("std");
const zquic = @import("zquic");

pub const io = zquic.transport.io;

/// ALPN advertised to Yggdrasil QUIC peers. Go's tls.Config has an empty
/// NextProtos list; quic-go still requires *some* token on the wire, and
/// public nodes accept this identifier.
pub const ALPN: []const u8 = "yggdrasil";

pub fn createClient(gpa: std.mem.Allocator, host: []const u8, port: u16) !*io.Client {
    const client = try gpa.create(io.Client);
    errdefer gpa.destroy(client);
    try io.Client.initInPlace(gpa, .{
        .host = host,
        .port = port,
        // quic-go / yggdrasil-go tls.Config has empty NextProtos; advertising a
        // made-up token makes the server abort in Initial with a 45-byte close/ack.
        // MinTLSVersion = 1.2,
        // MaxTLSVersion = 1.3,
        .alpn = null,
        .raw_application_streams = true,
        .urls = &.{},
    }, client);
    return client;
}

pub fn destroyClient(gpa: std.mem.Allocator, client: *io.Client) void {
    client.deinit();
    gpa.destroy(client);
}

/// Fill `client.conn.peer` with an IPv4 sockaddr so `startHandshake` has a
/// destination. zquic's `compat.Address` is not re-exported from the module
/// root; the in-memory layout matches `sockaddr_in`.
pub fn setPeerIpv4(client: *io.Client, ip: [4]u8, port: u16) void {
    var sin: std.posix.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(ip),
        .zero = [_]u8{0} ** 8,
    };
    const dst = std.mem.asBytes(&client.conn.peer);
    const src = std.mem.asBytes(&sin);
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
}

pub fn startHandshake(client: *io.Client) !void {
    try client.startHandshake(client.conn.peer);
}

pub fn isConnected(client: *const io.Client) bool {
    return client.conn.phase == .connected;
}

const testing = std.testing;

test "zquic client constructs without sending" {
    const client = try createClient(testing.allocator, "127.0.0.1", 9);
    defer destroyClient(testing.allocator, client);
    try testing.expect(!isConnected(client));
}
