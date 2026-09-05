//! SOCKS5 client (RFC 1928) with username/password authentication
//! (RFC 1929), used by `socks://` and `sockstls://` peer URIs.
//!
//! The reference implementation reaches a peer through a proxy with
//! `socks://[user:pass@]proxyhost:proxyport/peerhost:peerport` -- the proxy is
//! the URI's host, and the *peer* is named by the path (Go: `pathtokens[0]` of
//! `url.Path`). `sockstls://` additionally wraps the tunneled stream in TLS
//! once SOCKS reports success, with SNI defaulting to the proxy hostname and
//! overridable by `?sni=`.
//!
//! Everything here is pure protocol: building request bytes and parsing reply
//! bytes, with no sockets and no allocator. The event-loop state machine that
//! drives them lives in `network.zig` (it owns the libxev completions); keeping
//! this layer pure is what makes the handshake testable without a network.
//!
//! Reference: `yggdrasil-go/src/core/link_socks.go`.

const std = @import("std");
const net = std.Io.net;

pub const version: u8 = 5;

/// Authentication methods we offer, in the order we send them.
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USERPASS: u8 = 0x02;
/// Server's answer when it likes none of our methods.
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

/// `CMD` field of a request.
pub const CMD_CONNECT: u8 = 0x01;

/// `ATYP` values.
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// `REP` field of a reply.
pub const REP_SUCCEEDED: u8 = 0x00;

pub const Error = error{
    /// The path of a `socks://` URI is not `host:port`.
    InvalidTarget,
    /// Server answered with a version other than 5.
    BadVersion,
    /// Server refused every authentication method we offered.
    NoAcceptableMethods,
    /// Username/password authentication was rejected.
    AuthFailed,
    /// Malformed or truncated reply.
    TruncatedReply,
    /// The proxy could not connect to the requested peer.
    CommandFailed,
    /// The target address does not fit the buffer.
    BufferTooSmall,
};

/// The peer a `socks://` link is tunneled to: the `/host:port` path of the URI.
pub const Target = struct {
    host: []const u8,
    port: u16,
};

/// Parse the path half of a `socks://` URI (`/host:port`, `[v6host]:port`).
/// Leading slashes are ignored, so both `/a.b:1` and `a.b:1` work -- Go does
/// `strings.Trim(url.Path, "/")` and takes the first remaining token.
/// Only the first token is used, exactly like the reference: a path with more
/// segments is not something a Yggdrasil peer address can express.
pub fn parseTarget(path: []const u8) Error!Target {
    var s = path;
    while (s.len > 0 and s[0] == '/') s = s[1..];
    if (std.mem.indexOfScalar(u8, s, '/')) |slash| s = s[0..slash];
    if (s.len == 0) return error.InvalidTarget;

    if (s[0] == '[') {
        const close = std.mem.indexOfScalar(u8, s, ']') orelse return error.InvalidTarget;
        const after = s[close + 1 ..];
        if (after.len < 2 or after[0] != ':') return error.InvalidTarget;
        return .{
            .host = s[1..close],
            .port = std.fmt.parseInt(u16, after[1..], 10) catch return error.InvalidTarget,
        };
    }
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidTarget;
    if (colon == 0 or colon + 1 == s.len) return error.InvalidTarget;
    return .{
        .host = s[0..colon],
        .port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.InvalidTarget,
    };
}

/// Client greeting: version, number of methods, methods. We offer no-auth only
/// when no credentials were configured; Go builds the same list from
/// `url.User != nil`.
pub fn greeting(buf: []u8, has_credentials: bool) Error![]u8 {
    if (buf.len < 4) return error.BufferTooSmall;
    buf[0] = version;
    if (has_credentials) {
        buf[1] = 2;
        buf[2] = METHOD_NO_AUTH;
        buf[3] = METHOD_USERPASS;
        return buf[0..4];
    }
    buf[1] = 1;
    buf[2] = METHOD_NO_AUTH;
    return buf[0..3];
}

/// Which method the server picked, from the two-byte method selection message.
pub fn selectedMethod(reply: []const u8) Error!u8 {
    if (reply.len < 2) return error.TruncatedReply;
    if (reply[0] != version) return error.BadVersion;
    return switch (reply[1]) {
        METHOD_NO_AUTH, METHOD_USERPASS => reply[1],
        METHOD_NONE_ACCEPTABLE => error.NoAcceptableMethods,
        else => error.NoAcceptableMethods,
    };
}

/// RFC 1929 username/password authentication request.
pub fn authRequest(buf: []u8, user: []const u8, pass: []const u8) Error![]u8 {
    if (user.len > 255 or pass.len > 255) return error.BufferTooSmall;
    const need = 3 + user.len + pass.len;
    if (buf.len < need) return error.BufferTooSmall;
    buf[0] = 1; // VER of the sub-negotiation
    buf[1] = @intCast(user.len);
    @memcpy(buf[2 .. 2 + user.len], user);
    buf[2 + user.len] = @intCast(pass.len);
    @memcpy(buf[3 + user.len .. need], pass);
    return buf[0..need];
}

/// The sub-negotiation reply is `[VER, STATUS]`; STATUS 0 means success.
pub fn authSucceeded(reply: []const u8) Error!bool {
    if (reply.len < 2) return error.TruncatedReply;
    if (reply[0] != 1) return error.BadVersion;
    return reply[1] == 0;
}

/// CONNECT request. The address type follows RFC 1928: a literal IPv4/IPv6
/// address is sent as such (so a proxy that resolves names itself still gets a
/// literal when we have one), anything else as a domain name.
pub fn connectRequest(buf: []u8, target: Target) Error![]u8 {
    if (target.host.len == 0 or target.host.len > 255) return error.InvalidTarget;
    var atyp: u8 = ATYP_DOMAIN;
    var addr_len: usize = 1 + target.host.len; // domain: length byte + name
    var ip4: net.Ip4Address = undefined;
    var ip6: net.Ip6Address = undefined;
    if (net.Ip4Address.parse(target.host, 0)) |v4| {
        atyp = ATYP_IPV4;
        addr_len = 4;
        ip4 = v4;
    } else |_| if (net.Ip6Address.parse(target.host, 0)) |v6| {
        atyp = ATYP_IPV6;
        addr_len = 16;
        ip6 = v6;
    } else |_| {}

    const need = 4 + addr_len + 2;
    if (buf.len < need) return error.BufferTooSmall;
    buf[0] = version;
    buf[1] = CMD_CONNECT;
    buf[2] = 0; // RSV
    buf[3] = atyp;
    switch (atyp) {
        ATYP_IPV4 => @memcpy(buf[4..8], &ip4.bytes),
        ATYP_IPV6 => @memcpy(buf[4..20], &ip6.bytes),
        else => {
            buf[4] = @intCast(target.host.len);
            @memcpy(buf[5 .. 5 + target.host.len], target.host);
        },
    }
    const port_off = 4 + addr_len;
    std.mem.writeInt(u16, buf[port_off..][0..2], target.port, .big);
    return buf[0..need];
}

/// Bytes the reply needs before it can be interpreted: the four-byte header
/// plus the bound address (`4`/`16`, or `1 + N` for a domain) and the port.
pub fn replyLength(header: []const u8) Error!usize {
    if (header.len < 4) return error.TruncatedReply;
    const atyp = header[3];
    return 4 + switch (atyp) {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => blk: {
            if (header.len < 5) return error.TruncatedReply;
            break :blk 1 + @as(usize, header[4]);
        },
        else => return error.BadVersion,
    } + 2;
}

/// Check a complete CONNECT reply. Returns `CommandFailed` for any non-zero
/// `REP`, so the caller can log "proxy refused the target" and retry later
/// through the normal dial backoff.
pub fn replyOk(reply: []const u8) Error!void {
    if (reply.len < 4) return error.TruncatedReply;
    if (reply[0] != version) return error.BadVersion;
    if (reply[1] != REP_SUCCEEDED) return error.CommandFailed;
    if (reply[2] != 0) return error.TruncatedReply; // RSV must be zero
}

/// Human-readable text for a `REP` value, for the link error log.
pub fn replyText(rep: u8) []const u8 {
    return switch (rep) {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        else => "unassigned SOCKS error",
    };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test "parse socks target from uri path" {
    const testing = std.testing;

    const plain = try parseTarget("/203.0.113.5:12345");
    try testing.expectEqualStrings("203.0.113.5", plain.host);
    try testing.expectEqual(@as(u16, 12345), plain.port);

    // No leading slash, and extra path segments ignored like the reference.
    const trimmed = try parseTarget("peer.example.org:1234/extra");
    try testing.expectEqualStrings("peer.example.org", trimmed.host);
    try testing.expectEqual(@as(u16, 1234), trimmed.port);

    const v6 = try parseTarget("/[200:1::2]:1234");
    try testing.expectEqualStrings("200:1::2", v6.host);
    try testing.expectEqual(@as(u16, 1234), v6.port);

    try testing.expectError(error.InvalidTarget, parseTarget("/"));
    try testing.expectError(error.InvalidTarget, parseTarget("/no-port"));
    try testing.expectError(error.InvalidTarget, parseTarget("/host:notaport"));
    try testing.expectError(error.InvalidTarget, parseTarget("/[200:1::2]"));
}

test "greeting offers auth only when credentials are configured" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;

    const anon = try greeting(&buf, false);
    try testing.expectEqualSlices(u8, &.{ 5, 1, 0 }, anon);

    const auth = try greeting(&buf, true);
    try testing.expectEqualSlices(u8, &.{ 5, 2, 0, 2 }, auth);
}

test "method selection" {
    const testing = std.testing;
    try testing.expectEqual(@as(u8, METHOD_NO_AUTH), try selectedMethod(&.{ 5, 0 }));
    try testing.expectEqual(@as(u8, METHOD_USERPASS), try selectedMethod(&.{ 5, 2 }));
    try testing.expectError(error.NoAcceptableMethods, selectedMethod(&.{ 5, 0xff }));
    try testing.expectError(error.BadVersion, selectedMethod(&.{ 4, 0 }));
    try testing.expectError(error.TruncatedReply, selectedMethod(&.{5}));
}

test "username/password sub-negotiation" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    const req = try authRequest(&buf, "bob", "s3cr3t");
    try testing.expectEqualSlices(u8, &.{ 1, 3, 'b', 'o', 'b', 6, 's', '3', 'c', 'r', '3', 't' }, req);

    try testing.expect(try authSucceeded(&.{ 1, 0 }));
    try testing.expect(!try authSucceeded(&.{ 1, 1 }));
    try testing.expectError(error.TruncatedReply, authSucceeded(&.{1}));
}

test "connect request address types" {
    const testing = std.testing;
    var buf: [300]u8 = undefined;

    const v4 = try connectRequest(&buf, .{ .host = "203.0.113.5", .port = 12345 });
    try testing.expectEqual(@as(usize, 10), v4.len);
    try testing.expectEqual(ATYP_IPV4, v4[3]);
    try testing.expectEqualSlices(u8, &.{ 203, 0, 113, 5 }, v4[4..8]);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x39 }, v4[8..10]); // 12345

    const v6 = try connectRequest(&buf, .{ .host = "200:1::2", .port = 443 });
    try testing.expectEqual(@as(usize, 22), v6.len);
    try testing.expectEqual(ATYP_IPV6, v6[3]);
    try testing.expectEqual(@as(u8, 0x02), v6[19]); // last byte of 200:1::2
    try testing.expectEqualSlices(u8, &.{ 0x01, 0xbb }, v6[20..22]); // 443

    const name = try connectRequest(&buf, .{ .host = "peer.example.org", .port = 1 });
    try testing.expectEqual(ATYP_DOMAIN, name[3]);
    try testing.expectEqual(@as(u8, 16), name[4]);
    try testing.expectEqualStrings("peer.example.org", name[5..21]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, name[21..23]);
}

test "reply parsing" {
    const testing = std.testing;

    // IPv4 reply: 4 header bytes + 4 address + 2 port.
    const ok: []const u8 = &.{ 5, 0, 0, 1, 203, 0, 113, 5, 0x30, 0x39 };
    try testing.expectEqual(@as(usize, 10), try replyLength(ok[0..4]));
    try testing.expectEqual(@as(usize, 10), try replyLength(ok));
    try replyOk(ok);

    // Domain reply: length byte says 3.
    const dom: []const u8 = &.{ 5, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80 };
    try testing.expectEqual(@as(usize, 10), try replyLength(dom[0..5]));
    try replyOk(dom);

    const refused: []const u8 = &.{ 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.CommandFailed, replyOk(refused));
    try testing.expectEqualStrings("connection refused", replyText(5));
    try testing.expectError(error.TruncatedReply, replyOk(&.{ 5, 0, 0 }));
}
