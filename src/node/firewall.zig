//! Stateful packet firewall for the Yggdrasil TUN bridge.
//!
//! When enabled, drops inbound mesh packets unless:
//! 1) source in open_all_for, 2) matches outbound flow (stateful),
//! 3) TCP SYN to open_tcp, 4) UDP to open_udp, 5) ICMPv6 echo,
//! 6) ICMPv6 errors (types 1-4). Outbound always allowed.

const std = @import("std");

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DEST_OPTS: u8 = 60;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const ICMP_ECHO_REQUEST: u8 = 128;

const TCP_SYN_TIMEOUT_NS: u64 = 30 * std.time.ns_per_s;
const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 300 * std.time.ns_per_s;
const TCP_CLOSE_TIMEOUT_NS: u64 = 10 * std.time.ns_per_s;
const UDP_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
const ICMP_TIMEOUT_NS: u64 = 30 * std.time.ns_per_s;
const GC_INTERVAL_NS: u64 = 30 * std.time.ns_per_s;

/// CIDR entry.
pub const CidrEntry = struct { ip: [16]u8, prefix: u8 };

const FlowKey = struct { proto: u8, our_ip: [16]u8, our_port: u16, peer_ip: [16]u8, peer_port: u16 };
const TcpState = enum { syn_sent, established, fin_seen, closed };
const FlowEntry = struct { last_seen_ns: u64, tcp_state: ?TcpState };
const Parsed = struct { proto: u8, src_ip: [16]u8, dst_ip: [16]u8, src_port: u16, dst_port: u16, tcp_flags: u8, icmp_type: u8 };

pub const Firewall = struct {
    enable: bool,
    open_tcp: std.AutoHashMapUnmanaged(u16, void),
    open_udp: std.AutoHashMapUnmanaged(u16, void),
    open_all_for: std.ArrayListUnmanaged(CidrEntry),
    allow_icmp_echo: bool,
    table: std.AutoHashMapUnmanaged(FlowKey, FlowEntry),
    last_gc_ns: u64,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, cfg: anytype) !Firewall {
        var fw = Firewall{
            .enable = cfg.enable,
            .open_tcp = .{},
            .open_udp = .{},
            .open_all_for = .empty,
            .allow_icmp_echo = cfg.allow_icmp_echo,
            .table = .{},
            .last_gc_ns = monotonicNs(),
            .gpa = gpa,
        };
        for (cfg.open_tcp) |p| try fw.open_tcp.put(gpa, p, {});
        for (cfg.open_udp) |p| try fw.open_udp.put(gpa, p, {});
        for (cfg.open_all_for) |cidr_str| {
            const slash = std.mem.indexOfScalar(u8, cidr_str, '/') orelse {
                var ip: [16]u8 = undefined;
                if (parseIPv6(cidr_str, &ip))
                    try fw.open_all_for.append(gpa, .{ .ip = ip, .prefix = 128 });
                continue;
            };
            const prefix = std.fmt.parseInt(u8, cidr_str[slash + 1 ..], 10) catch continue;
            var ip: [16]u8 = undefined;
            if (parseIPv6(cidr_str[0..slash], &ip))
                try fw.open_all_for.append(gpa, .{ .ip = ip, .prefix = prefix });
        }
        return fw;
    }

    pub fn deinit(self: *Firewall) void {
        self.open_tcp.deinit(self.gpa);
        self.open_udp.deinit(self.gpa);
        self.open_all_for.deinit(self.gpa);
        self.table.deinit(self.gpa);
    }

    pub fn enabled(self: *const Firewall) bool { return self.enable; }

    pub fn gc(self: *Firewall) void {
        const now = monotonicNs();
        if (now - self.last_gc_ns < GC_INTERVAL_NS) return;
        self.last_gc_ns = now;
        var to_remove = std.ArrayListUnmanaged(FlowKey).empty;
        defer to_remove.deinit(self.gpa);
        var it = self.table.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.last_seen_ns >= timeoutFor(entry.key_ptr.proto, entry.value_ptr.tcp_state))
                to_remove.append(self.gpa, entry.key_ptr.*) catch {};
        }
        for (to_remove.items) |k| _ = self.table.remove(k);
    }

    pub fn observeOutbound(self: *Firewall, pkt: []const u8) void {
        const p = parse(pkt) orelse return;
        if (!isTracked(p.proto)) return;
        const key = FlowKey{ .proto = p.proto, .our_ip = p.src_ip, .our_port = p.src_port, .peer_ip = p.dst_ip, .peer_port = p.dst_port };
        const now = monotonicNs();
        const gop = self.table.getOrPut(self.gpa, key) catch return;
        gop.value_ptr.last_seen_ns = now;
        gop.value_ptr.tcp_state = if (p.proto == PROTO_TCP) advanceTcp(gop.value_ptr.tcp_state, p.tcp_flags) else null;
    }

    pub fn checkInbound(self: *Firewall, pkt: []const u8) bool {
        const p = parse(pkt) orelse return false;
        for (self.open_all_for.items) |net| {
            if (matchPrefix(&p.src_ip, &net.ip, net.prefix)) return true;
        }
        if (p.proto == PROTO_ICMPV6) {
            if (1 <= p.icmp_type and p.icmp_type <= 4) return true;
            if (p.icmp_type == ICMP_ECHO_REQUEST) return self.allow_icmp_echo;
        }
        const key = FlowKey{ .proto = p.proto, .our_ip = p.dst_ip, .our_port = p.dst_port, .peer_ip = p.src_ip, .peer_port = p.src_port };
        if (self.table.getPtr(key)) |entry| {
            entry.last_seen_ns = monotonicNs();
            if (p.proto == PROTO_TCP) entry.tcp_state = advanceTcp(entry.tcp_state, p.tcp_flags);
            return true;
        }
        switch (p.proto) {
            PROTO_TCP => {
                const is_syn = (p.tcp_flags & TCP_FLAG_SYN) != 0 and (p.tcp_flags & TCP_FLAG_ACK) == 0;
                if (is_syn and self.open_tcp.contains(p.dst_port)) {
                    self.table.put(self.gpa, key, .{ .last_seen_ns = monotonicNs(), .tcp_state = .syn_sent }) catch {};
                    return true;
                }
            },
            PROTO_UDP => {
                if (self.open_udp.contains(p.dst_port)) {
                    self.table.put(self.gpa, key, .{ .last_seen_ns = monotonicNs(), .tcp_state = null }) catch {};
                    return true;
                }
            },
            else => {},
        }
        return false;
    }
};

fn isTracked(proto: u8) bool { return proto == PROTO_TCP or proto == PROTO_UDP or proto == PROTO_ICMPV6; }

fn advanceTcp(prev: ?TcpState, flags: u8) ?TcpState {
    if (flags & TCP_FLAG_RST != 0) return .closed;
    if (flags & TCP_FLAG_FIN != 0) return .fin_seen;
    const syn = flags & TCP_FLAG_SYN != 0;
    const ack = flags & TCP_FLAG_ACK != 0;
    return switch (prev orelse return .syn_sent) {
        .closed, .fin_seen => prev.?,
        .established => .established,
        .syn_sent => if (ack and !syn) .established else if (syn and ack) .established else .syn_sent,
    };
}

fn timeoutFor(proto: u8, tcp_state: ?TcpState) u64 {
    return switch (proto) {
        PROTO_TCP => switch (tcp_state orelse return TCP_SYN_TIMEOUT_NS) {
            .syn_sent => TCP_SYN_TIMEOUT_NS,
            .established => TCP_ESTABLISHED_TIMEOUT_NS,
            .fin_seen, .closed => TCP_CLOSE_TIMEOUT_NS,
        },
        PROTO_UDP => UDP_TIMEOUT_NS,
        PROTO_ICMPV6 => ICMP_TIMEOUT_NS,
        else => UDP_TIMEOUT_NS,
    };
}

fn matchPrefix(ip: *const [16]u8, net: *const [16]u8, prefix: u8) bool {
    const bytes: usize = @intCast(prefix / 8);
    const bits: u3 = @intCast(prefix % 8);
    for (0..bytes) |i| if (ip[i] != net[i]) return false;
    if (bits > 0) {
        const shift: u3 = @intCast(8 - @as(u8, bits));
        const mask: u8 = @as(u8, 0xFF) << shift;
        return (ip[bytes] & mask) == (net[bytes] & mask);
    }
    return true;
}

fn parse(pkt: []const u8) ?Parsed {
    if (pkt.len < 40) return null;
    if (pkt[0] >> 4 != 6) return null;
    var src_ip: [16]u8 = undefined;
    var dst_ip: [16]u8 = undefined;
    @memcpy(&src_ip, pkt[8..24]);
    @memcpy(&dst_ip, pkt[24..40]);
    var next: u8 = pkt[6];
    var off: usize = 40;
    for (0..8) |_| {
        switch (next) {
            HOP_BY_HOP, ROUTING, DEST_OPTS => {
                if (off + 2 > pkt.len) return null;
                next = pkt[off];
                off += (@as(usize, pkt[off + 1]) + 1) * 8;
                if (off > pkt.len) return null;
            },
            FRAGMENT => {
                if (off + 8 > pkt.len) return null;
                const frag_off = @as(u16, pkt[off + 2]) << 8 | pkt[off + 3];
                if ((frag_off & 0xFFF8) != 0 and (frag_off & 0x0001) == 0) return null;
                next = pkt[off];
                off += 8;
            },
            PROTO_TCP, PROTO_UDP, PROTO_ICMPV6 => {
                if (off + 4 > pkt.len) return null;
                return Parsed{
                    .proto = next,
                    .src_ip = src_ip,
                    .dst_ip = dst_ip,
                    .src_port = std.mem.readInt(u16, pkt[off..][0..2], .big),
                    .dst_port = std.mem.readInt(u16, pkt[off + 2 ..][0..2], .big),
                    .tcp_flags = if (next == PROTO_TCP and off + 14 <= pkt.len) pkt[off + 13] else 0,
                    .icmp_type = if (next == PROTO_ICMPV6 and off < pkt.len) pkt[off] else 0,
                };
            },
            else => return null,
        }
    }
    return null;
}

fn parseIPv6(s: []const u8, out: *[16]u8) bool {
    var groups: [8]u16 = [_]u16{0} ** 8;
    var gi: usize = 0;
    var i: usize = 0;
    var compression: ?usize = null;
    while (i < s.len) {
        if (s[i] == ':') {
            if (i + 1 < s.len and s[i + 1] == ':') { compression = gi; i += 2; continue; }
            i += 1;
            gi += 1;
            if (gi > 7) return false;
            continue;
        }
        const start = i;
        while (i < s.len and s[i] != ':') : (i += 1) {}
        const val = std.fmt.parseInt(u16, s[start..i], 16) catch return false;
        if (gi > 7) return false;
        groups[gi] = val;
    }
    if (compression) |comp| {
        var j: usize = 7;
        var ri: usize = gi;
        while (ri >= comp) : (ri -= 1) {
            groups[j] = groups[ri];
            if (j == 0) break;
            j -= 1;
        }
        while (j >= comp) : (j -= 1) { groups[j] = 0; }
    }
    for (groups, 0..) |g, idx| {
        out[idx * 2] = @truncate(g >> 8);
        out[idx * 2 + 1] = @truncate(g & 0xFF);
    }
    return true;
}

fn monotonicNs() u64 {
    if (@import("builtin").os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.MONOTONIC, &ts) == 0)
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }
    return 0;
}

const testing = std.testing;

test "firewall disabled" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = false, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();
    try testing.expect(!fw.enabled());
}

test "parse ipv6 ok" {
    var pkt: [60]u8 = [_]u8{0} ** 60;
    pkt[0] = 0x60;
    pkt[6] = PROTO_UDP;
    try testing.expect(parse(&pkt) != null);
}

test "icmp echo passes" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();
    var pkt: [48]u8 = [_]u8{0} ** 48;
    pkt[0] = 0x60;
    pkt[6] = PROTO_ICMPV6;
    pkt[40] = ICMP_ECHO_REQUEST;
    try testing.expect(fw.checkInbound(&pkt));
}
