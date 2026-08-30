//! System-route installation for Crypto-Key Routing (CKR).
//!
//! Mirrors the Rust reference (`crates/yggdrasil/src/ckr.rs`
//! `install_routes` / `remove_routes`): for every `[tunnel_routing]`
//! `remote_subnets` entry whose key is not our own, expand the CIDR list
//! (honouring `inetv4`/`inetv6`/`!` exclusions, but skipping `~` tunnel-only
//! entries) and steer each resulting prefix at the TUN interface.
//!
//! Linux uses the netlink `NETLINK_ROUTE` socket directly (no external
//! `ip`/`route` binary). Other platforms are currently a best-effort no-op;
//! the operator can install routes manually.

const std = @import("std");
const builtin = @import("builtin");
const node = @import("node.zig");

const PublicKey = @import("ironwood").PublicKey;

/// Install system routes for all configured CKR subnets, pointing them at the
/// TUN interface. Best-effort: failures are counted and reported, not fatal.
pub fn installSystemRoutes(
    gpa: std.mem.Allocator,
    cfg: *const node.config.TunnelRoutingConfig,
    tun_name: []const u8,
    self_key: PublicKey,
) !void {
    if (!cfg.enable or !cfg.install_system_routes) return;
    switch (builtin.os.tag) {
        .linux => try installLinux(gpa, cfg, tun_name, self_key),
        else => {},
    }
}

/// Remove previously installed CKR system routes (best-effort).
pub fn removeSystemRoutes(
    gpa: std.mem.Allocator,
    cfg: *const node.config.TunnelRoutingConfig,
    tun_name: []const u8,
    self_key: PublicKey,
) void {
    if (!cfg.enable or !cfg.install_system_routes) return;
    switch (builtin.os.tag) {
        .linux => removeLinux(gpa, cfg, tun_name, self_key) catch {},
        else => {},
    }
}

/// The prefixes to steer at the TUN: all remote_subnets entries whose key is
/// not our own, minus `~` tunnel-only entries, expanded and de-duplicated.
fn collectRoutes(
    gpa: std.mem.Allocator,
    cfg: *const node.config.TunnelRoutingConfig,
    self_key: PublicKey,
) !std.ArrayListUnmanaged(node.ckr.Prefix) {
    var out = std.ArrayListUnmanaged(node.ckr.Prefix).empty;
    errdefer out.deinit(gpa);

    for (cfg.remote_subnets) |rs| {
        const dest = parseKey(rs.key_hex) orelse continue;
        if (std.mem.eql(u8, &dest, &self_key)) continue;

        // Drop `~` entries (tunnel-only, no system route).
        var filtered = std.ArrayListUnmanaged([]const u8).empty;
        defer filtered.deinit(gpa);
        for (rs.cidrs) |cidr| {
            const t = std.mem.trim(u8, cidr, " \t");
            if (t.len == 0) continue;
            if (t[0] == '~') continue;
            try filtered.append(gpa, cidr);
        }

        var expanded = try node.ckr.expandCidrs(gpa, filtered.items);
        defer expanded.deinit(gpa);
        for (expanded.items) |p| {
            // Set-based de-dupe preserving insertion order.
            var dup = false;
            for (out.items) |existing| {
                if (existing.v6 == p.v6 and existing.addr == p.addr and existing.len == p.len) {
                    dup = true;
                    break;
                }
            }
            if (!dup) try out.append(gpa, p);
        }
    }
    return out;
}

fn parseKey(hex: []const u8) ?PublicKey {
    if (hex.len != 64) return null;
    var key: PublicKey = undefined;
    _ = std.fmt.hexToBytes(&key, hex) catch return null;
    return key;
}

// ---------------------------------------------------------------------------
// Linux (netlink NETLINK_ROUTE)
// ---------------------------------------------------------------------------

const nlmsghdr = extern struct {
    len: u32,
    type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
};

const rtmsg = extern struct {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    type: u8,
    flags: u32,
};

const rtattr = extern struct {
    len: u16,
    type: u16,
};

const nlmsgerr = extern struct {
    error_code: i32,
    msg: nlmsghdr,
};

const NETLINK_ROUTE: c_int = 0;
const AF_NETLINK: c_int = 16;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLMSG_ERROR: u16 = 2;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const sockaddr_nl = extern struct {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
};

fn netlinkSocket() !std.posix.socket_t {
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0x80000;
    const fd = std.posix.system.socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return error.SocketFailed;
    return fd;
}

/// Round up to a 4-byte boundary (netlink attribute alignment).
fn rtaAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn sendRoute(fd: std.posix.socket_t, oif: u32, prefix: node.ckr.Prefix, del: bool) bool {
    const dst_len: usize = if (prefix.v6) 16 else 4;

    // Layout: nlmsghdr | rtmsg | RTA_DST | RTA_OIF
    const hdr_len = @sizeOf(nlmsghdr);
    const body_len = @sizeOf(rtmsg);
    const dst_attr_len = rtaAlign(@sizeOf(rtattr) + dst_len);
    const oif_attr_len = rtaAlign(@sizeOf(rtattr) + 4);
    const total = hdr_len + body_len + dst_attr_len + oif_attr_len;

    var buf: [128]u8 = [_]u8{0} ** 128;
    std.debug.assert(total <= buf.len);

    // nlmsghdr
    var hdr: nlmsghdr = .{
        .len = @intCast(total),
        .type = if (del) RTM_DELROUTE else RTM_NEWROUTE,
        .flags = NLM_F_REQUEST | NLM_F_ACK | (if (del) 0 else NLM_F_CREATE | NLM_F_EXCL),
        .seq = 1,
        .pid = 0,
    };
    @memcpy(buf[0..hdr_len], std.mem.asBytes(&hdr));

    // rtmsg
    const rt: rtmsg = .{
        .family = if (prefix.v6) AF_INET6 else AF_INET,
        .dst_len = prefix.len,
        .src_len = 0,
        .tos = 0,
        .table = RT_TABLE_MAIN,
        .protocol = RTPROT_BOOT,
        .scope = RT_SCOPE_UNIVERSE,
        .type = RTN_UNICAST,
        .flags = 0,
    };
    @memcpy(buf[hdr_len..][0..body_len], std.mem.asBytes(&rt));

    var off: usize = hdr_len + body_len;

    // RTA_DST — network address bytes. IPv4 addresses live in the low 32
    // bits of `prefixToBytes`'s 16-byte buffer (bytes 12..16), IPv6 in 0..16.
    const dst_attr: rtattr = .{ .len = @intCast(@sizeOf(rtattr) + dst_len), .type = RTA_DST };
    @memcpy(buf[off..][0..@sizeOf(rtattr)], std.mem.asBytes(&dst_attr));
    const dst_bytes = prefixToBytes(prefix);
    const dst_off: usize = if (prefix.v6) 0 else 12;
    @memcpy(buf[off + @sizeOf(rtattr) ..][0..dst_len], dst_bytes[dst_off..][0..dst_len]);
    off += dst_attr_len;

    // RTA_OIF — outbound interface index.
    const oif_attr: rtattr = .{ .len = @intCast(@sizeOf(rtattr) + 4), .type = RTA_OIF };
    @memcpy(buf[off..][0..@sizeOf(rtattr)], std.mem.asBytes(&oif_attr));
    std.mem.writeInt(u32, buf[off + @sizeOf(rtattr) ..][0..4], oif, .native);
    off += oif_attr_len;

    const sent = std.posix.system.send(fd, buf[0..total].ptr, total, 0);
    if (sent < 0) return false;

    // Read the ACK.
    var ack_buf: [256]u8 = undefined;
    const n = std.posix.system.recv(fd, ack_buf[0..].ptr, ack_buf.len, 0);
    if (n < @sizeOf(nlmsghdr)) return false;
    const ack: nlmsghdr = std.mem.bytesToValue(nlmsghdr, ack_buf[0..@sizeOf(nlmsghdr)]);
    if (ack.type != NLMSG_ERROR) return false;
    const err: nlmsgerr = std.mem.bytesToValue(nlmsgerr, ack_buf[@sizeOf(nlmsghdr)..][0..@sizeOf(nlmsgerr)]);
    if (err.error_code == 0) return true;
    // EEXIST (route already present) is not an error for our purposes.
    return err.error_code == -@as(i32, @intFromEnum(std.posix.E.EXIST));
}

fn prefixToBytes(p: node.ckr.Prefix) [16]u8 {
    var out: [16]u8 = [_]u8{0} ** 16;
    if (p.v6) {
        var v = p.addr;
        var i: usize = 16;
        while (i > 0) {
            i -= 1;
            out[i] = @truncate(v & 0xff);
            v >>= 8;
        }
    } else {
        const v: u32 = @truncate(p.addr);
        std.mem.writeInt(u32, out[12..16], v, .big);
    }
    return out;
}

fn installLinux(
    gpa: std.mem.Allocator,
    cfg: *const node.config.TunnelRoutingConfig,
    tun_name: []const u8,
    self_key: PublicKey,
) !void {
    var routes = try collectRoutes(gpa, cfg, self_key);
    defer routes.deinit(gpa);
    if (routes.items.len == 0) return;

    const oif = std.c.if_nametoindex(@ptrCast(tun_name.ptr));
    if (oif == 0) {
        std.debug.print("[ygg] CKR: cannot resolve TUN interface '{s}' for route install; skipping\n", .{tun_name});
        return;
    }

    const fd = netlinkSocket() catch {
        std.debug.print("[ygg] CKR: failed to open netlink socket; skipping route install\n", .{});
        return;
    };
    defer _ = std.posix.system.close(fd);

    var installed: usize = 0;
    var failed: usize = 0;
    for (routes.items) |p| {
        if (sendRoute(fd, @intCast(oif), p, false)) {
            installed += 1;
        } else {
            failed += 1;
        }
    }
    std.debug.print("[ygg] CKR: installed {d} system route(s) via '{s}' ({d} failed)\n", .{ installed, tun_name, failed });
}

fn removeLinux(
    gpa: std.mem.Allocator,
    cfg: *const node.config.TunnelRoutingConfig,
    tun_name: []const u8,
    self_key: PublicKey,
) !void {
    var routes = try collectRoutes(gpa, cfg, self_key);
    defer routes.deinit(gpa);
    if (routes.items.len == 0) return;

    const oif = std.c.if_nametoindex(@ptrCast(tun_name.ptr));
    if (oif == 0) return;

    const fd = netlinkSocket() catch return;
    defer _ = std.posix.system.close(fd);

    for (routes.items) |p| {
        _ = sendRoute(fd, @intCast(oif), p, true);
    }
}
