//! Blocking DNS resolution via libc `getaddrinfo`.
//!
//! libxev doesn't provide async DNS resolution, and Zig 0.16's std.Io.net
//! resolve() requires a full Io implementation we don't otherwise need, so we
//! shell out to the platform resolver directly. Callers should perform
//! resolution on a background thread if they want to avoid blocking the event
//! loop (see `network.zig`'s dial logic).

const std = @import("std");
const c = std.c;

pub const ResolveError = error{
    ResolveFailed,
    NoAddresses,
    HostTooLong,
};

/// Resolve `host` to a list of IP addresses (caller owns the returned slice).
/// Both A and AAAA records are returned, in the order the resolver gives them.
pub fn resolve(gpa: std.mem.Allocator, host: []const u8, port: u16) ![]std.Io.net.IpAddress {
    // Fast path: literal IP addresses don't need a resolver round-trip.
    if (std.Io.net.IpAddress.parseLiteral(host)) |lit| {
        var addr = lit;
        addr.setPort(port);
        const out = try gpa.alloc(std.Io.net.IpAddress, 1);
        out[0] = addr;
        return out;
    } else |_| {}
    // parseLiteral expects `[addr]` bracket form for IPv6 with mandatory
    // brackets; also try a bare (bracket-less) literal for convenience.
    if (std.Io.net.Ip4Address.parse(host, port)) |ip4| {
        const out = try gpa.alloc(std.Io.net.IpAddress, 1);
        out[0] = .{ .ip4 = ip4 };
        return out;
    } else |_| {}
    if (std.Io.net.Ip6Address.parse(host, port)) |ip6| {
        const out = try gpa.alloc(std.Io.net.IpAddress, 1);
        out[0] = .{ .ip6 = ip6 };
        return out;
    } else |_| {}

    if (host.len > 253) return ResolveError.HostTooLong;
    var host_buf: [256]u8 = undefined;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    const host_z: [:0]const u8 = host_buf[0..host.len :0];

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrintZ(&port_buf, "{d}", .{port}) catch unreachable;

    var hints: c.addrinfo = std.mem.zeroes(c.addrinfo);
    hints.family = c.AF.UNSPEC;
    hints.socktype = c.SOCK.STREAM;
    var res: ?*c.addrinfo = null;
    const rc = c.getaddrinfo(host_z.ptr, port_str.ptr, &hints, &res);
    if (rc != @as(c.EAI, @enumFromInt(0))) return ResolveError.ResolveFailed;
    defer if (res) |r| c.freeaddrinfo(r);

    var list = std.ArrayListUnmanaged(std.Io.net.IpAddress).empty;
    errdefer list.deinit(gpa);

    var cur = res;
    while (cur) |cu| : (cur = cu.next) {
        if (cu.family == c.AF.INET and cu.addr != null) {
            const sin: *align(1) const c.sockaddr.in = @ptrCast(cu.addr.?);
            const bytes: [4]u8 = @bitCast(sin.addr);
            try list.append(gpa, .{ .ip4 = .{ .bytes = bytes, .port = port } });
        } else if (cu.family == c.AF.INET6 and cu.addr != null) {
            const sin6: *align(1) const c.sockaddr.in6 = @ptrCast(cu.addr.?);
            try list.append(gpa, .{ .ip6 = .{ .bytes = sin6.addr, .port = port } });
        }
    }
    if (list.items.len == 0) {
        list.deinit(gpa);
        return ResolveError.NoAddresses;
    }
    return list.toOwnedSlice(gpa);
}

const testing = std.testing;

test "resolve literal ipv4" {
    const gpa = testing.allocator;
    const addrs = try resolve(gpa, "127.0.0.1", 1234);
    defer gpa.free(addrs);
    try testing.expectEqual(@as(usize, 1), addrs.len);
    try testing.expectEqual(@as(u16, 1234), addrs[0].getPort());
}
