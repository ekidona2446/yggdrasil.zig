//! Transport links: TCP/TLS connection setup, metadata handshake,
//! and peer connection lifecycle.
//!
//! Establishes connections to remote peers and accepts incoming ones.
//! Performs version handshake (Metadata exchange) and registers peers
//! with the Core.

const std = @import("std");
const ironwood = @import("ironwood");

const node = @import("node.zig");
const Core = node.core.Core;
const Metadata = node.version.Metadata;
const PublicKey = ironwood.PublicKey;

/// Timeout for version handshake.
pub const HANDSHAKE_TIMEOUT_NS: u64 = 6 * std.time.ns_per_s;

/// Timeout for dial attempts.
pub const DIAL_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;

/// Default maximum backoff for reconnection attempts (4096 s).
pub const DEFAULT_BACKOFF_LIMIT_NS: u64 = 4096 * std.time.ns_per_s;

/// Minimum backoff limit (5 s).
pub const MINIMUM_BACKOFF_LIMIT_NS: u64 = 5 * std.time.ns_per_s;

/// Type of link connection.
pub const LinkType = enum {
    persistent,
    ephemeral,
    incoming,
};

/// Options parsed from a peer URI.
pub const LinkOptions = struct {
    pinned_keys: []const PublicKey = &.{},
    priority: u8 = 0,
    password: []const u8 = &.{},
    max_backoff_ns: u64 = DEFAULT_BACKOFF_LIMIT_NS,
    tls_sni: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Peer URI parsing
// ---------------------------------------------------------------------------

/// Parse a peer URI like "tcp://host:port" or "tls://host:port" into
/// a scheme, host, and port.
pub fn parsePeerURI(uri: []const u8) !struct { scheme: []const u8, host: []const u8, port: u16, options: LinkOptions } {
    // Format: scheme://[host]:port?key=val...
    const scheme_end = std.mem.indexOf(u8, uri, "://") orelse return error.InvalidURI;
    const scheme = uri[0..scheme_end];
    const rest = uri[scheme_end + 3 ..];

    // Split on '?' for query params
    const addr_part = if (std.mem.indexOfScalar(u8, rest, '?')) |qpos| rest[0..qpos] else rest;

    // Extract host and port
    const hp = extractHostPort(addr_part) catch return error.InvalidURI;
    return .{
        .scheme = scheme,
        .host = hp.host,
        .port = hp.port,
        .options = LinkOptions{},
    };
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Perform the version handshake over a connection: send our metadata,
/// receive and verify the peer's metadata. Returns the peer's public key.
pub fn performHandshake(
    conn: anytype,
    our_id: *const ironwood.Crypto,
    our_priority: u8,
    password: []const u8,
    gpa: std.mem.Allocator,
) !PublicKey {
    // Build and send our metadata
    const our_meta = Metadata.init(our_id.public_key, our_priority);
    const our_msg = try our_meta.encode(our_id, password, gpa);
    defer gpa.free(our_msg);

    try conn.writeAll(our_msg);

    // Read and decode peer's metadata
    var header_buf: [6]u8 = undefined;
    try conn.readNoEof(&header_buf);

    const body_len = std.mem.readInt(u16, header_buf[4..6], .big);
    if (body_len > 8192) return error.OversizedMessage;

    const body = try gpa.alloc(u8, body_len);
    defer gpa.free(body);
    try conn.readNoEof(body);

    // Assemble full message
    var full = try gpa.alloc(u8, 6 + body_len);
    defer gpa.free(full);
    @memcpy(full[0..6], &header_buf);
    @memcpy(full[6..], body);

    const peer_meta = try Metadata.decode(full, password, gpa);
    if (!peer_meta.check()) return error.IncompatibleVersion;

    return peer_meta.public_key;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse peer uri tcp" {
    const uri = "tcp://example.com:1234";
    const parsed = try parsePeerURI(uri);
    try testing.expectEqualStrings("tcp", parsed.scheme);
    try testing.expectEqualStrings("example.com", parsed.host);
    try testing.expectEqual(@as(u16, 1234), parsed.port);
}

test "parse peer uri ipv6" {
    const uri = "tls://[::1]:9999";
    const parsed = try parsePeerURI(uri);
    try testing.expectEqualStrings("tls", parsed.scheme);
    try testing.expectEqualStrings("::1", parsed.host);
    try testing.expectEqual(@as(u16, 9999), parsed.port);
}

test "handshake success" {
    const gpa = testing.allocator;
    const id_a = ironwood.Crypto.generate();
    const id_b = ironwood.Crypto.generate();

    // Simulate handshake with in-memory pipes
    const a_meta = Metadata.init(id_a.public_key, 0);
    const a_msg = try a_meta.encode(&id_a, &.{}, gpa);
    defer gpa.free(a_msg);

    const b_meta = Metadata.init(id_b.public_key, 0);
    const b_msg = try b_meta.encode(&id_b, &.{}, gpa);
    defer gpa.free(b_msg);

    // Decode each other's messages
    const decoded_a = try Metadata.decode(a_msg, &.{}, gpa);
    const decoded_b = try Metadata.decode(b_msg, &.{}, gpa);

    try testing.expect(decoded_a.check());
    try testing.expect(decoded_b.check());
    try testing.expectEqualSlices(u8, &id_a.public_key, &decoded_a.public_key);
    try testing.expectEqualSlices(u8, &id_b.public_key, &decoded_b.public_key);
}


fn extractHostPort(addr_part: []const u8) !HostPort {
    if (addr_part[0] == '[') {
        const closing = std.mem.indexOfScalar(u8, addr_part, ']') orelse return error.InvalidURI;
        const after_bracket = addr_part[closing + 1 ..];
        if (after_bracket.len == 0 or after_bracket[0] != ':') return error.InvalidURI;
        const port_str = after_bracket[1..];
        return HostPort{ .host = addr_part[1..closing], .port = try std.fmt.parseInt(u16, port_str, 10) };
    } else {
        const colon = std.mem.lastIndexOfScalar(u8, addr_part, ':') orelse return error.InvalidURI;
        const port_str = addr_part[colon + 1 ..];
        return HostPort{ .host = addr_part[0..colon], .port = try std.fmt.parseInt(u16, port_str, 10) };
    }
}

const HostPort = struct { host: []const u8, port: u16 };
