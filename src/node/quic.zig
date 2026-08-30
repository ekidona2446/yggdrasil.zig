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

// ---------------------------------------------------------------------------
// QUIC listener (server side)
// ---------------------------------------------------------------------------
//
// The reference (quic-go / yggdrasil-go) builds its QUIC server certificate
// from the node's Ed25519 identity key and sets `InsecureSkipVerify` on the
// client, so peers never verify the certificate — node identity is proven by
// the ironwood handshake that follows, not by TLS. zquic's `Server` can only
// load RSA/ECDSA private keys (not Ed25519), so we use one static self-signed
// P-256 certificate for every listener. This is interoperable: Go's client
// accepts any cert (`InsecureSkipVerify: true`, `verifyTLSConnection` returns
// nil) and our own client does not verify peers either.

pub const serverCertPem: []const u8 =
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBoDCCAUegAwIBAgIUUJFV1k/38AIspj5EtrPYW1vG0PgwCgYIKoZIzj0EAwIw\n" ++
    "GDEWMBQGA1UEAwwNeWdnZHJhc2lsLnppZzAgFw0yNjA4MzAxMDM1MTVaGA8yMTI2\n" ++
    "MDgwNjEwMzUxNVowGDEWMBQGA1UEAwwNeWdnZHJhc2lsLnppZzBZMBMGByqGSM49\n" ++
    "AgEGCCqGSM49AwEHA0IABJ02Vhxglvma9gd/mG3yvcnY2G3efWwkSm6aYyoV5CDJ\n" ++
    "DVwIa+3JeLlNg1sQ7R8baIo1Vd25drdBAZXecxdzxjCjbTBrMB0GA1UdDgQWBBS/\n" ++
    "yx5d2ED+jsK2WXhhD/h749cFazAfBgNVHSMEGDAWgBS/yx5d2ED+jsK2WXhhD/h7\n" ++
    "49cFazAPBgNVHRMBAf8EBTADAQH/MBgGA1UdEQQRMA+CDXlnZ2RyYXNpbC56aWcw\n" ++
    "CgYIKoZIzj0EAwIDRwAwRAIgGgarw21L9vkBS01KudFCXzNrp0uVSpjBktwfQcCj\n" ++
    "o90CIGJplh1vV9dsEJeRvgAfmY6HthxT93S3azdaprC6wkG/\n" ++
    "-----END CERTIFICATE-----\n";

pub const serverKeyPem: []const u8 =
    "-----BEGIN EC PRIVATE KEY-----\n" ++
    "MHcCAQEEIJiyU0dbRES3F4xyvt1Bhn8y1nZXSSe9ULSU7JnTRkeHoAoGCCqGSM49\n" ++
    "AwEHoUQDQgAEnTZWHGCW+Zr2B3+YbfK9ydjYbd59bCRKbppjKhXkIMkNXAhr7cl4\n" ++
    "uU2DWxDtHxtoijVV3bl2t0EBld5zF3PGMA==\n" ++
    "-----END EC PRIVATE KEY-----\n";

/// Create a raw-application-stream QUIC server bound to `0.0.0.0:port`. The
/// caller drives it by `recvfrom` + `feedPacket` + `processPendingWork`, and
/// scans `server.conns` for accepted (`.connected`) connections.
pub fn createServer(gpa: std.mem.Allocator, port: u16) !*io.Server {
    return try io.Server.init(gpa, .{
        .port = port,
        .cert_pem = serverCertPem,
        .key_pem = serverKeyPem,
        .www_dir = "",
        .raw_application_streams = true,
        .alpn = null,
    });
}

pub fn destroyServer(gpa: std.mem.Allocator, server: *io.Server) void {
    server.deinit();
    gpa.destroy(server);
}

/// Cross-platform socket helpers, re-exported for the listener's recv loop.
pub const compat = zquic.compat;

/// Drain all currently-buffered UDP datagrams off the server socket and feed
/// them into zquic. Non-blocking (`MSG_DONTWAIT`) so a datagram-less socket
/// returns immediately instead of stalling the event loop — mirrors the
/// outbound client's `drainQuicUdp`.
pub fn serverDrainUdp(server: *io.Server, scratch: []u8) void {
    while (true) {
        var src: std.posix.sockaddr = undefined;
        var srclen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const n: isize = std.posix.system.recvfrom(
            server.sock,
            scratch.ptr,
            scratch.len,
            std.posix.MSG.DONTWAIT,
            &src,
            &srclen,
        );
        if (n <= 0) break;
        var addr: compat.Address = undefined;
        const copy = @min(@sizeOf(compat.Address), @sizeOf(std.posix.sockaddr));
        @memcpy(std.mem.asBytes(&addr)[0..copy], std.mem.asBytes(&src)[0..copy]);
        server.feedPacket(scratch[0..@intCast(n)], addr);
    }
}

/// One full server drive: reset per-drive send/recv budgets, drain inbound
/// UDP into zquic, then run pending work (STREAM sends, ACKs, loss recovery,
/// idle/handshake reaping). Call once per tick, in this order.
pub fn serverDrive(server: *io.Server, scratch: []u8) void {
    server.resetDriveSendBudgets();
    serverDrainUdp(server, scratch);
    server.processPendingWork();
}

/// Whether `conn` is still referenced by `server`'s connection table. zquic
/// frees a reaped `ConnState`, so an embedder holding a cached pointer MUST
/// check this before dereferencing it.
pub fn serverConnAlive(server: *io.Server, conn: *io.ConnState) bool {
    for (&server.conns) |slot| {
        if (slot) |c| {
            if (c == conn) return true;
        }
    }
    return false;
}

const testing = std.testing;

test "zquic client constructs without sending" {
    const client = try createClient(testing.allocator, "127.0.0.1", 9);
    defer destroyClient(testing.allocator, client);
    try testing.expect(!isConnected(client));
}
