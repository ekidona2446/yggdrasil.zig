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
const ICMP_ECHO_REPLY: u8 = 129;

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
        // Reject IPv4 / malformed open_all_for entries like the reference
        // (only IPv6 CIDRs are supported).
        for (cfg.open_all_for) |cidr_str| {
            const slash = std.mem.indexOfScalar(u8, cidr_str, '/');
            const addr_part = if (slash) |s| cidr_str[0..s] else cidr_str;
            if (std.mem.indexOfScalar(u8, addr_part, '.') != null) {
                std.debug.print("firewall: open_all_for entry '{s}' is IPv4, only IPv6 is supported\n", .{cidr_str});
                return error.InvalidFirewallCidr;
            }
            const prefix: u8 = if (slash) |s|
                std.fmt.parseInt(u8, cidr_str[s + 1 ..], 10) catch {
                    std.debug.print("firewall: invalid open_all_for entry '{s}'\n", .{cidr_str});
                    return error.InvalidFirewallCidr;
                }
            else
                128;
            if (prefix > 128) {
                std.debug.print("firewall: invalid open_all_for prefix in '{s}'\n", .{cidr_str});
                return error.InvalidFirewallCidr;
            }
            var ip: [16]u8 = undefined;
            if (!parseIPv6(addr_part, &ip)) {
                std.debug.print("firewall: invalid open_all_for entry '{s}'\n", .{cidr_str});
                return error.InvalidFirewallCidr;
            }
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

    pub fn enabled(self: *const Firewall) bool {
        return self.enable;
    }

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
        self.gc(); // opportunistically evict stale conntrack entries
        const p = parse(pkt) orelse return;
        if (!isTracked(p.proto)) return;
        const key = FlowKey{ .proto = p.proto, .our_ip = p.src_ip, .our_port = p.src_port, .peer_ip = p.dst_ip, .peer_port = p.dst_port };
        const now = monotonicNs();
        const gop = self.table.getOrPut(self.gpa, key) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.last_seen_ns = now;
            gop.value_ptr.tcp_state = if (p.proto == PROTO_TCP) .syn_sent else null;
        }
        gop.value_ptr.last_seen_ns = now;
        if (p.proto == PROTO_TCP)
            gop.value_ptr.tcp_state = advanceTcp(gop.value_ptr.tcp_state, p.tcp_flags);
    }

    pub fn checkInbound(self: *Firewall, pkt: []const u8) bool {
        self.gc(); // opportunistically evict stale conntrack entries
        const p = parse(pkt) orelse return false;
        for (self.open_all_for.items) |net| {
            if (matchPrefix(&p.src_ip, &net.ip, net.prefix)) return true;
        }
        if (p.proto == PROTO_ICMPV6) {
            if (1 <= p.icmp_type and p.icmp_type <= 4) return true;
            if (p.icmp_type == ICMP_ECHO_REQUEST) {
                if (self.allow_icmp_echo) return true;
                // else fall through to conntrack (matching the reference).
            }
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

fn isTracked(proto: u8) bool {
    return proto == PROTO_TCP or proto == PROTO_UDP or proto == PROTO_ICMPV6;
}

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
    // Walk extension headers up to a small bound.
    for (0..8) |_| {
        switch (next) {
            HOP_BY_HOP, ROUTING, DEST_OPTS => {
                if (off + 2 > pkt.len) return null;
                const nxt = pkt[off];
                const hdr_len = (@as(usize, pkt[off + 1]) + 1) * 8;
                if (off + hdr_len > pkt.len) return null;
                next = nxt;
                off += hdr_len;
            },
            FRAGMENT => {
                if (off + 8 > pkt.len) return null;
                // Bytes 2-3: fragment offset (high 13 bits) | res (2) | M (1).
                const frag_word = (@as(u16, pkt[off + 2]) << 8) | pkt[off + 3];
                const frag_offset = frag_word >> 3;
                if (frag_offset != 0) return null; // non-first fragment
                next = pkt[off];
                off += 8;
            },
            else => break,
        }
    }
    const proto = next;
    if (!isTracked(proto)) return null;

    var src_port: u16 = 0;
    var dst_port: u16 = 0;
    var tcp_flags: u8 = 0;
    var icmp_type: u8 = 0;

    switch (proto) {
        PROTO_TCP => {
            if (off + 14 > pkt.len) return null;
            src_port = std.mem.readInt(u16, pkt[off..][0..2], .big);
            dst_port = std.mem.readInt(u16, pkt[off + 2 ..][0..2], .big);
            tcp_flags = pkt[off + 13];
        },
        PROTO_UDP => {
            if (off + 8 > pkt.len) return null;
            src_port = std.mem.readInt(u16, pkt[off..][0..2], .big);
            dst_port = std.mem.readInt(u16, pkt[off + 2 ..][0..2], .big);
        },
        PROTO_ICMPV6 => {
            if (off + 8 > pkt.len) return null;
            icmp_type = pkt[off];
            // Echo Request/Reply mirror the identifier unchanged, so use it as
            // the port-equivalent on both sides of the flow key.
            if (icmp_type == ICMP_ECHO_REQUEST or icmp_type == ICMP_ECHO_REPLY) {
                const id = std.mem.readInt(u16, pkt[off + 4 ..][0..2], .big);
                src_port = id;
                dst_port = id;
            }
        },
        else => return null,
    }
    return Parsed{
        .proto = proto,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .tcp_flags = tcp_flags,
        .icmp_type = icmp_type,
    };
}

fn parseIPv6(s: []const u8, out: *[16]u8) bool {
    var groups: [8]u16 = [_]u16{0} ** 8;
    var n: usize = 0; // groups parsed (compression collapsed into a gap)
    var dc_at: ?usize = null; // index of the "::" compression gap
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == ':') {
            if (i + 1 < s.len and s[i + 1] == ':') {
                if (dc_at != null) return false; // at most one "::"
                dc_at = n;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        const start = i;
        while (i < s.len and s[i] != ':') i += 1;
        const val = std.fmt.parseInt(u16, s[start..i], 16) catch return false;
        if (n >= 8) return false;
        groups[n] = val;
        n += 1;
    }
    if (dc_at) |at| {
        const right_count = n - at;
        if (right_count > 0)
            std.mem.copyBackwards(u16, groups[8 - right_count ..], groups[at..n]);
        @memset(groups[at .. 8 - right_count], 0);
    } else if (n != 8) {
        return false; // no compression and not a full address
    }
    for (groups, 0..) |g, idx| {
        out[idx * 2] = @truncate(g >> 8);
        out[idx * 2 + 1] = @truncate(g & 0xFF);
    }
    return true;
}

fn monotonicNs() u64 {
    return @import("util").time.monotonicNanos();
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

// -- Packet builders (mirror the reference's test helpers) -----------------

const Pkt = struct {
    buf: [128]u8 = undefined,
    len: usize = 0,

    fn v6(proto: u8, src: [16]u8, dst: [16]u8, payload: []const u8) Pkt {
        var p = Pkt{};
        p.len = 40 + payload.len;
        p.buf[0] = 0x60;
        std.mem.writeInt(u16, p.buf[4..6], @intCast(payload.len), .big);
        p.buf[6] = proto;
        p.buf[7] = 64;
        @memcpy(p.buf[8..24], &src);
        @memcpy(p.buf[24..40], &dst);
        @memcpy(p.buf[40..][0..payload.len], payload);
        return p;
    }

    fn slice(p: *const Pkt) []const u8 {
        return p.buf[0..p.len];
    }
};

fn tcpPkt(sport: u16, dport: u16, flags: u8) [20]u8 {
    var t = [_]u8{0} ** 20;
    std.mem.writeInt(u16, t[0..2], sport, .big);
    std.mem.writeInt(u16, t[2..4], dport, .big);
    t[12] = 5 << 4; // data offset = 5 (20 bytes)
    t[13] = flags;
    return t;
}

fn udpPkt(sport: u16, dport: u16) [8]u8 {
    var u = [_]u8{0} ** 8;
    std.mem.writeInt(u16, u[0..2], sport, .big);
    std.mem.writeInt(u16, u[2..4], dport, .big);
    return u;
}

fn icmpEchoPkt(typ: u8, id: u16) [8]u8 {
    var i = [_]u8{0} ** 8;
    i[0] = typ;
    std.mem.writeInt(u16, i[4..6], id, .big);
    return i;
}

fn localIp() [16]u8 {
    var a = [_]u8{0} ** 16;
    a[0] = 0x02;
    a[15] = 0x01;
    return a;
}

fn peerIp() [16]u8 {
    var a = [_]u8{0} ** 16;
    a[0] = 0x02;
    a[15] = 0x02;
    return a;
}

test "tcp outbound then inbound passes" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const out = Pkt.v6(PROTO_TCP, localIp(), peerIp(), &tcpPkt(40000, 80, TCP_FLAG_SYN));
    fw.observeOutbound(out.slice());

    const reply = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(80, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK));
    try testing.expect(fw.checkInbound(reply.slice()));
}

test "tcp unsolicited inbound dropped" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const pkt = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(40000, 22, TCP_FLAG_SYN));
    try testing.expect(!fw.checkInbound(pkt.slice()));
}

test "open tcp allows syn and subsequent packets" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &[_]u16{22}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const syn = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(40000, 22, TCP_FLAG_SYN));
    try testing.expect(fw.checkInbound(syn.slice()));

    const ack = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(40000, 22, TCP_FLAG_ACK));
    try testing.expect(fw.checkInbound(ack.slice()));

    const other = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(40001, 23, TCP_FLAG_SYN));
    try testing.expect(!fw.checkInbound(other.slice()));
}

test "tcp inbound ack without flow dropped" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &[_]u16{22}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const ack = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(40000, 22, TCP_FLAG_ACK));
    try testing.expect(!fw.checkInbound(ack.slice()));
}

test "open all for bypass" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &[_][]const u8{"200::/8"}, .allow_icmp_echo = true });
    defer fw.deinit();

    const pkt = Pkt.v6(PROTO_TCP, peerIp(), localIp(), &tcpPkt(40000, 9999, TCP_FLAG_SYN));
    try testing.expect(fw.checkInbound(pkt.slice()));
}

test "udp round trip" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const out = Pkt.v6(PROTO_UDP, localIp(), peerIp(), &udpPkt(40000, 53));
    fw.observeOutbound(out.slice());

    const reply = Pkt.v6(PROTO_UDP, peerIp(), localIp(), &udpPkt(53, 40000));
    try testing.expect(fw.checkInbound(reply.slice()));
}

test "open udp allows inbound" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &[_]u16{5353}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const pkt = Pkt.v6(PROTO_UDP, peerIp(), localIp(), &udpPkt(40000, 5353));
    try testing.expect(fw.checkInbound(pkt.slice()));

    const other = Pkt.v6(PROTO_UDP, peerIp(), localIp(), &udpPkt(40000, 5354));
    try testing.expect(!fw.checkInbound(other.slice()));
}

test "icmp echo disabled" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = false });
    defer fw.deinit();

    const req = Pkt.v6(PROTO_ICMPV6, peerIp(), localIp(), &icmpEchoPkt(ICMP_ECHO_REQUEST, 7));
    try testing.expect(!fw.checkInbound(req.slice()));
}

test "icmp echo reply matches outbound request" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = false });
    defer fw.deinit();

    const req_out = Pkt.v6(PROTO_ICMPV6, localIp(), peerIp(), &icmpEchoPkt(ICMP_ECHO_REQUEST, 42));
    fw.observeOutbound(req_out.slice());

    const reply_in = Pkt.v6(PROTO_ICMPV6, peerIp(), localIp(), &icmpEchoPkt(ICMP_ECHO_REPLY, 42));
    try testing.expect(fw.checkInbound(reply_in.slice()));

    const stray = Pkt.v6(PROTO_ICMPV6, peerIp(), localIp(), &icmpEchoPkt(ICMP_ECHO_REPLY, 99));
    try testing.expect(!fw.checkInbound(stray.slice()));
}

test "icmp error always allowed" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = false });
    defer fw.deinit();

    var payload = [_]u8{0} ** 8;
    payload[0] = 1; // Destination Unreachable
    const pkt = Pkt.v6(PROTO_ICMPV6, peerIp(), localIp(), &payload);
    try testing.expect(fw.checkInbound(pkt.slice()));
}

test "non first fragment dropped on inbound" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    var payload = [_]u8{0} ** 8;
    payload[0] = PROTO_TCP; // next header
    // frag_offset != 0 (high 13 bits of bytes 2-3).
    payload[2] = 0;
    payload[3] = 0b00001000;
    const pkt = Pkt.v6(FRAGMENT, peerIp(), localIp(), &payload);
    try testing.expect(!fw.checkInbound(pkt.slice()));
}

test "malformed packet dropped" {
    const gpa = testing.allocator;
    var fw = try Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &.{}, .allow_icmp_echo = true });
    defer fw.deinit();

    const short = [_]u8{0x60} ** 10;
    try testing.expect(!fw.checkInbound(&short));

    var bad = [_]u8{0} ** 60;
    bad[0] = 0x40; // wrong version
    try testing.expect(!fw.checkInbound(&bad));
}

test "invalid open all for rejected" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidFirewallCidr, Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &[_][]const u8{"not a cidr"}, .allow_icmp_echo = true }));
}

test "ipv4 open all for rejected" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidFirewallCidr, Firewall.init(gpa, .{ .enable = true, .open_tcp = &.{}, .open_udp = &.{}, .open_all_for = &[_][]const u8{"10.0.0.0/8"}, .allow_icmp_echo = true }));
}

test "parseIPv6 compression" {
    var out: [16]u8 = undefined;
    try testing.expect(parseIPv6("2001:db8::1", &out));
    try testing.expect(out[0] == 0x20 and out[1] == 0x01);
    try testing.expect(out[2] == 0x0d and out[3] == 0xb8);
    try testing.expect(out[14] == 0x00 and out[15] == 0x01);

    var out2: [16]u8 = undefined;
    try testing.expect(parseIPv6("::1", &out2));
    try testing.expect(out2[15] == 0x01);
    try testing.expect(out2[0] == 0x00);

    var out3: [16]u8 = undefined;
    try testing.expect(parseIPv6("200::", &out3));
    try testing.expect(out3[0] == 0x02 and out3[1] == 0x00);
    try testing.expect(out3[15] == 0x00);

    try testing.expect(!parseIPv6("1:2:3:4:5:6:7", &out)); // too few, no "::"
    try testing.expect(!parseIPv6("1:2:3::4::5", &out)); // two "::"
}
