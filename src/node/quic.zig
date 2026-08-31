//! QUIC transport for Yggdrasil peer links (RFC 9000/9001).
//!
//! Yggdrasil-go's `quic://` peers speak QUIC over UDP, then run the same
//! ironwood metadata handshake on the first client-initiated bidirectional
//! STREAM. We drive zquic's `Client` in raw-application-stream mode (no HTTP/3)
//! and treat that stream as a reliable byte pipe, same as TCP/TLS/WS.
//!
//! Earlier revisions of this file advertised `ALPN = "yggdrasil"`. That was
//! wrong. The reference never sets `NextProtos` — `linkQUIC` reuses
//! `l.core.config.tls.Clone()` verbatim, and `core.generateTLSConfig` leaves
//! `NextProtos` nil — so a Yggdrasil QUIC server sends no `application_layer_
//! protocol_negotiation` extension and a client offers none. Advertising a
//! made-up token makes the peer abort in the Initial, and worse, echoing an
//! ALPN the client did not offer violates RFC 9001 §8.1. Every `alpn` field
//! below is therefore `null`, matching the reference on the wire.

const std = @import("std");
const builtin = @import("builtin");
const zquic = @import("zquic");
const udp_io = @import("udp_io.zig");
const quic_identity = @import("quic_identity.zig");

pub const io = zquic.transport.io;
pub const QuicIdentity = quic_identity.QuicIdentity;

/// zquic's peer-address type (`compat.Address`). zquic does not re-export
/// `compat` from its module root, so instead of duplicating the layout we
/// recover the real type from a public signature that already uses it. This
/// keeps us honest: if zquic ever changes the type, this fails to compile
/// rather than silently passing a wrong-layout struct.
pub const Address = @typeInfo(@TypeOf(io.Server.feedPacket)).@"fn".params[2].type.?;

// ---------------------------------------------------------------------------
// Peer addresses
// ---------------------------------------------------------------------------

/// Convert a resolved IP address (either family) into zquic's sockaddr union.
pub fn addressFromIp(ip: std.Io.net.IpAddress) Address {
    return switch (ip) {
        .ip4 => |v| .{ .in = .{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, v.port),
            .addr = @bitCast(v.bytes),
            .zero = [_]u8{0} ** 8,
        } },
        .ip6 => |v| .{ .in6 = .{
            .family = std.posix.AF.INET6,
            .port = std.mem.nativeToBig(u16, v.port),
            .flowinfo = std.mem.nativeToBig(u32, v.flow),
            .addr = v.bytes,
            .scope_id = @intCast(v.interface.index),
        } },
    };
}

/// Address-family constant for `socket(2)`. Windows is spelled out because
/// `std.posix.AF` does not exist there.
fn socketDomain(ip: std.Io.net.IpAddress) u32 {
    if (comptime builtin.os.tag == .windows) {
        return switch (ip) {
            .ip4 => 2, // AF_INET
            .ip6 => 23, // AF_INET6
        };
    }
    return switch (ip) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };
}

const SOCK_DGRAM: u32 = if (builtin.os.tag == .windows) 2 else std.posix.SOCK.DGRAM;

/// Create a non-blocking, wildcard-bound UDP socket in `ip`'s family.
///
/// zquic's own `Client.initInPlace` / `Server.init` always create an
/// **IPv4** socket (`compat.socket(std.posix.AF.INET, …)`), which makes
/// `quic://[2a02:…]` peers undialable and the listener unreachable over IPv6.
/// Creating the socket here removes that restriction without touching zquic —
/// `initFromBoundSocketInPlace` / `initFromSocket` both accept an existing fd.
/// The socket is also switched to non-blocking mode, which is what lets the
/// drain loop use `flags = 0` portably instead of Linux's `MSG_DONTWAIT`.
pub fn createUdpSocket(gpa: std.mem.Allocator, family_ip: std.Io.net.IpAddress) !std.posix.socket_t {
    _ = gpa;
    const domain = socketDomain(family_ip);
    const rc = std.posix.system.socket(domain, SOCK_DGRAM, 0);
    if (rc < 0) return error.SocketCreateFailed;
    const sock: std.posix.socket_t = @intCast(rc);
    errdefer closeSocket(sock);

    // Allow several listeners on one port across interfaces, as the reference
    // effectively gets from Go's dual-stack socket.
    // SO_REUSEADDR's numeric value differs per OS (2 on Linux, 4 on the BSDs
    // and Darwin), so take it from std rather than spelling out a constant.
    const on: c_int = 1;
    if (builtin.os.tag != .windows) {
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&on)) catch {};
    }

    const wildcard = addressFromIp(switch (family_ip) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{ .bytes = [_]u8{0} ** 16, .port = 0 } },
    });
    const bind_rc = std.posix.system.bind(
        sock,
        @ptrCast(&wildcard),
        wildcard.getOsSockLen(),
    );
    if (bind_rc != 0) return error.BindFailed;

    try udp_io.setNonblocking(sock);
    return sock;
}

/// Create a non-blocking UDP socket bound to `0.0.0.0:port`.
pub fn createBoundUdpSocket(port: u16) !std.posix.socket_t {
    const rc = std.posix.system.socket(std.posix.AF.INET, SOCK_DGRAM, 0);
    if (rc < 0) return error.SocketCreateFailed;
    const sock: std.posix.socket_t = @intCast(rc);
    errdefer closeSocket(sock);

    const wildcard = addressFromIp(.{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } });
    if (std.posix.system.bind(sock, @ptrCast(&wildcard), wildcard.getOsSockLen()) != 0) {
        return error.BindFailed;
    }
    try udp_io.setNonblocking(sock);
    return sock;
}

pub fn closeSocket(sock: std.posix.socket_t) void {
    _ = std.posix.system.close(sock);
}

// ---------------------------------------------------------------------------
// Outbound client
// ---------------------------------------------------------------------------

/// An outbound `quic://` session: our own UDP socket plus the zquic client
/// driving it. The socket is owned by this handle, not by zquic
/// (`initFromBoundSocketInPlace` sets `owns_socket = false`), so [`destroyClient`]
/// closes it.
pub const Client = struct {
    quic: *io.Client,
    sock: std.posix.socket_t,
    peer: Address,
};

/// Build a client aimed at `peer`, owning a fresh non-blocking UDP socket in
/// the peer's address family. `host` is only used for diagnostics/qlog naming.
pub fn createClient(
    gpa: std.mem.Allocator,
    host: []const u8,
    peer: std.Io.net.IpAddress,
) !*Client {
    const sock = try createUdpSocket(gpa, peer);
    errdefer closeSocket(sock);

    const inner = try gpa.create(io.Client);
    errdefer gpa.destroy(inner);
    try io.Client.initFromBoundSocketInPlace(gpa, .{
        .host = host,
        .port = switch (peer) {
            .ip4 => |v| v.port,
            .ip6 => |v| v.port,
        },
        // See the module header: the reference advertises no ALPN.
        .alpn = null,
        .raw_application_streams = true,
        .urls = &.{},
        // Deliberately no `client_cert_pem` / `client_key_pem`: yggdrasil-go
        // dials with `ClientAuth: tls.NoClientCert`, so a client certificate is
        // never requested. Passing the node's Ed25519 PEM here would also panic
        // zquic's key parser (see `quic_identity.zig`).
    }, sock, inner);
    errdefer inner.deinit();

    const handle = try gpa.create(Client);
    errdefer gpa.destroy(handle);
    handle.* = .{ .quic = inner, .sock = sock, .peer = addressFromIp(peer) };
    return handle;
}

pub fn destroyClient(gpa: std.mem.Allocator, client: *Client) void {
    client.quic.deinit();
    gpa.destroy(client.quic);
    closeSocket(client.sock);
    gpa.destroy(client);
}

/// Send the first Initial and start the handshake.
pub fn startHandshake(client: *Client) !void {
    try client.quic.startHandshake(client.peer);
}

pub fn isConnected(client: *const Client) bool {
    return client.quic.conn.phase == .connected;
}

/// Drain every queued datagram off the client socket into zquic. Returns
/// `false` if the kernel reported a fatal socket error.
pub fn clientDrainUdp(client: *Client, scratch: []u8) bool {
    while (true) {
        const r = udp_io.recvFrom(client.sock, scratch);
        const n = r catch |err| switch (err) {
            error.WouldBlock => return true,
            error.ConnectionReset => return true, // peer went away; idle timeout reaps it
            error.Failed => return false,
        };
        client.quic.feedPacket(scratch[0..n.n]);
    }
}

// ---------------------------------------------------------------------------
// Listener (server side)
// ---------------------------------------------------------------------------

/// A `quic://` listener: our own non-blocking IPv4 UDP socket plus the zquic
/// `Server` driving it, authenticated with a wolfSSL-generated identity.
pub const Server = struct {
    quic: *io.Server,
    sock: std.posix.socket_t,
    identity: QuicIdentity,
};

/// Create a listener bound to `0.0.0.0:port`.
///
/// `identity` must outlive the returned server only for the duration of this
/// call — zquic copies the PEM blobs during `initFromSocket` — but we keep
/// ownership so [`destroyServer`] can free them.
pub fn createServer(
    gpa: std.mem.Allocator,
    port: u16,
    node_public_key_hex: []const u8,
) !*Server {
    var identity = try quic_identity.generate(gpa, node_public_key_hex);
    errdefer identity.deinit(gpa);

    const sock = try createBoundUdpSocket(port);
    errdefer closeSocket(sock);

    const inner = try io.Server.initFromSocket(gpa, .{
        .port = port,
        .cert_pem = identity.cert_pem,
        .key_pem = identity.key_pem,
        .www_dir = "",
        .raw_application_streams = true,
        .alpn = null,
    }, sock, false);
    errdefer inner.deinit();

    const server = try gpa.create(Server);
    errdefer gpa.destroy(server);
    server.* = .{ .quic = inner, .sock = sock, .identity = identity };
    return server;
}

pub fn destroyServer(gpa: std.mem.Allocator, server: *Server) void {
    // NOTE: `io.Server.deinit` frees the `Server` itself
    // (`self.allocator.destroy(self)`), unlike `io.Client.deinit` which leaves
    // the caller's allocation alone. Destroying it here too was a double free
    // that aborted the process whenever a `quic://` listener was torn down.
    server.quic.deinit();
    closeSocket(server.sock);
    server.identity.deinit(gpa);
    gpa.destroy(server);
}

/// Drain all currently-buffered UDP datagrams off the listener socket and feed
/// them into zquic. Non-blocking, so a datagram-less socket returns
/// immediately instead of stalling the event loop.
pub fn serverDrainUdp(server: *Server, scratch: []u8) void {
    while (true) {
        const r = udp_io.recvFrom(server.sock, scratch) catch break;
        var addr: Address = undefined;
        const copy = @min(@sizeOf(Address), @sizeOf(std.posix.sockaddr));
        @memcpy(std.mem.asBytes(&addr)[0..copy], std.mem.asBytes(&r.addr)[0..copy]);
        server.quic.feedPacket(scratch[0..r.n], addr);
    }
}

/// One full server drive: reset per-drive send/recv budgets, drain inbound
/// UDP into zquic, then run pending work (STREAM sends, ACKs, loss recovery,
/// idle/handshake reaping). Call once per tick, in this order.
pub fn serverDrive(server: *Server, scratch: []u8) void {
    server.quic.resetDriveSendBudgets();
    serverDrainUdp(server, scratch);
    server.quic.processPendingWork();
}

/// Whether `conn` is still referenced by `server`'s connection table. zquic
/// frees a reaped `ConnState`, so an embedder holding a cached pointer MUST
/// check this before dereferencing it.
pub fn serverConnAlive(server: *const Server, conn: *io.ConnState) bool {
    for (&server.quic.conns) |slot| {
        if (slot) |c| {
            if (c == conn) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "quic: Address type is recovered from zquic and matches sockaddr sizing" {
    // If this ever fails, zquic changed its peer-address representation and
    // `addressFromIp` / `serverDrainUdp` must be revisited.
    try testing.expect(@sizeOf(Address) >= @sizeOf(std.posix.sockaddr.in6));
    const a = addressFromIp(.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 1515 } });
    try testing.expectEqual(@as(u16, std.posix.AF.INET), a.any.family);
    try testing.expectEqual(@as(u16, 1515), a.getPort());
    try testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(std.posix.sockaddr.in)), a.getOsSockLen());
}

test "quic: IPv6 peer address round-trips through the sockaddr union" {
    const a = addressFromIp(.{ .ip6 = .{
        .bytes = .{ 0x21, 0x0e, 0xa5, 0x1c, 0x88, 0x5b, 0x7d, 0xb0, 0x16, 0x6e, 0x09, 0x27, 0x98, 0xcd, 0xd1, 0x86 },
        .port = 1515,
    } });
    try testing.expectEqual(@as(u16, std.posix.AF.INET6), a.any.family);
    try testing.expectEqual(@as(u16, 1515), a.getPort());
    try testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(std.posix.sockaddr.in6)), a.getOsSockLen());
}

test "quic: client constructs without sending, and owns a non-blocking socket" {
    const client = try createClient(testing.allocator, "127.0.0.1", .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9 } });
    defer destroyClient(testing.allocator, client);

    try testing.expect(!isConnected(client));
    // Drain must return "no data" rather than block, which is the whole point
    // of the non-blocking socket.
    var buf: [2048]u8 = undefined;
    try testing.expect(clientDrainUdp(client, &buf));
}

test "quic: listener starts with a WolfSSL-generated identity and no embedded cert" {
    // This is the test that would have caught the old hardcoded certificate:
    // a real zquic `Server` is built from WolfSSL output, so zquic's own PEM
    // parser (`parseCertDerFromPem` + `PrivateKey.parsePem`) has to accept it.
    const tls_wolfssl = @import("tls_wolfssl.zig");
    try tls_wolfssl.globalInit();
    defer tls_wolfssl.globalDeinit();

    const server = try createServer(testing.allocator, 0, "cd" ** 32);
    defer destroyServer(testing.allocator, server);

    // zquic parsed the certificate into DER...
    try testing.expect(server.quic.cert_der.len > 0);
    // ...and the SEC1 key into a signing key it can actually use. zquic's
    // `buildCertificateVerifyWithContext` implements exactly two arms; if this
    // is not `ecdsa_secp256r1_sha256` (0x0403) the listener would fail every
    // handshake at flight-build time with UnsupportedSignatureScheme.
    try testing.expectEqual(
        @as(u16, 0x0403),
        @intFromEnum(server.quic.private_key.signature_scheme),
    );
    // The identity's CN carries the node's Ed25519 public key.
    try testing.expect(std.mem.indexOf(u8, server.identity.cert_pem, "BEGIN CERTIFICATE") != null);
}
