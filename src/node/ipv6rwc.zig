//! IPv6 ReadWriteCloser — bridges TUN <-> ironwood core.
//!
//! Accepts raw IPv6 packets read from the TUN device, resolves the
//! destination address/subnet to a mesh public key (buffering the packet and
//! triggering a path lookup if the key isn't known yet), and hands it to
//! `Core.writeTo` for session-encrypted, tree-routed delivery. In the other
//! direction, decrypted application payloads arriving from `Core` are
//! unwrapped (session-type byte stripped) and written back out to the TUN
//! device as IPv6 packets.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const Core = node.core.Core;
const PublicKey = ironwood.PublicKey;
const Address = node.Address;
const Subnet = node.Subnet;

/// How long key mappings live before refresh (120 s).
pub const KEY_STORE_TIMEOUT_NS: u64 = 120 * std.time.ns_per_s;

const IPV6_HEADER_LEN: usize = 40;

// ---------------------------------------------------------------------------
// KeyInfo — cached address/subnet for a known key
// ---------------------------------------------------------------------------

const KeyInfo = struct {
    address: Address,
    subnet: Subnet,
    last_seen_ns: u64,
};

// ---------------------------------------------------------------------------
// BufferedPacket — packet waiting for lookup
// ---------------------------------------------------------------------------

const BufferedPacket = struct {
    data: []u8,
    time_ns: u64,
};

// ---------------------------------------------------------------------------
// ReadWriteCloser
// ---------------------------------------------------------------------------

pub const ReadWriteCloser = struct {
    core: *Core,
    address: Address,
    subnet: Subnet,
    /// key -> KeyInfo
    key_to_info: std.AutoHashMapUnmanaged(PublicKey, KeyInfo),
    /// address bytes -> key
    addr_to_info: std.AutoHashMapUnmanaged([16]u8, PublicKey),
    /// subnet bytes -> key
    subnet_to_info: std.AutoHashMapUnmanaged([8]u8, PublicKey),
    /// Buffered packets by destination address.
    addr_buffer: std.AutoHashMapUnmanaged([16]u8, BufferedPacket),
    /// Buffered packets by destination subnet prefix.
    subnet_buffer: std.AutoHashMapUnmanaged([8]u8, BufferedPacket),
    mtu: u64,
    firewall: ?*Firewall,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, core: *Core, mtu: u64) !ReadWriteCloser {
        return .{
            .core = core,
            .address = core.address,
            .subnet = core.subnet,
            .key_to_info = .{},
            .addr_to_info = .{},
            .subnet_to_info = .{},
            .addr_buffer = .{},
            .subnet_buffer = .{},
            .mtu = mtu,
            .firewall = null,
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *ReadWriteCloser) void {
        self.key_to_info.deinit(self.gpa);
        self.addr_to_info.deinit(self.gpa);
        self.subnet_to_info.deinit(self.gpa);

        var ait = self.addr_buffer.iterator();
        while (ait.next()) |entry| self.gpa.free(entry.value_ptr.data);
        self.addr_buffer.deinit(self.gpa);

        var sit = self.subnet_buffer.iterator();
        while (sit.next()) |entry| self.gpa.free(entry.value_ptr.data);
        self.subnet_buffer.deinit(self.gpa);
    }

    /// Set an optional firewall.
    pub fn setFirewall(self: *ReadWriteCloser, fw: *Firewall) void {
        self.firewall = fw;
    }

    // -------------------------------------------------------------------
    // Outbound: TUN packet -> mesh
    // -------------------------------------------------------------------

    /// Accepts a raw IPv6 packet read from TUN. Parses the destination
    /// address, resolves it to a key (buffering + triggering lookup if
    /// unknown), and returns `OutgoingFrame`s to be flushed by the caller
    /// (e.g. via `NetworkManager.flushFrames`). Caller owns and must free
    /// the returned slice with `node.core.freeFrames`.
    pub fn handleOutbound(self: *ReadWriteCloser, packet: []const u8) ![]node.core.OutgoingFrame {
        if (packet.len < IPV6_HEADER_LEN) return &[_]node.core.OutgoingFrame{};
        if (packet[0] & 0xf0 != 0x60) return &[_]node.core.OutgoingFrame{}; // not IPv6

        const dst_bytes: [16]u8 = packet[24..40].*;
        var dst_addr = Address{ .bytes = dst_bytes };
        var dst_subnet = Subnet{ .bytes = dst_bytes[0..8].* };

        if (dst_addr.isValid()) {
            return self.sendToAddress(dst_addr, packet);
        } else if (dst_subnet.isValid()) {
            return self.sendToSubnet(dst_subnet, packet);
        }
        _ = &dst_addr;
        _ = &dst_subnet;
        return &[_]node.core.OutgoingFrame{};
    }

    fn sendToAddress(self: *ReadWriteCloser, addr: Address, bs: []const u8) ![]node.core.OutgoingFrame {
        if (self.addr_to_info.get(addr.bytes)) |key| {
            self.touchKey(key);
            return self.core.writeTo(&key, bs, node.core.TYPE_SESSION_TRAFFIC);
        }
        try self.bufferForAddr(addr, bs);
        return self.core.sendLookup(addr.getKey());
    }

    fn sendToSubnet(self: *ReadWriteCloser, subnet: Subnet, bs: []const u8) ![]node.core.OutgoingFrame {
        if (self.subnet_to_info.get(subnet.bytes)) |key| {
            self.touchKey(key);
            return self.core.writeTo(&key, bs, node.core.TYPE_SESSION_TRAFFIC);
        }
        try self.bufferForSubnet(subnet, bs);
        return self.core.sendLookup(subnet.getKey());
    }

    fn bufferForAddr(self: *ReadWriteCloser, addr: Address, bs: []const u8) !void {
        const dup = try self.gpa.dupe(u8, bs);
        errdefer self.gpa.free(dup);
        if (self.addr_buffer.fetchRemove(addr.bytes)) |kv| self.gpa.free(kv.value.data);
        try self.addr_buffer.put(self.gpa, addr.bytes, .{ .data = dup, .time_ns = monotonicNs() });
    }

    fn bufferForSubnet(self: *ReadWriteCloser, subnet: Subnet, bs: []const u8) !void {
        const dup = try self.gpa.dupe(u8, bs);
        errdefer self.gpa.free(dup);
        if (self.subnet_buffer.fetchRemove(subnet.bytes)) |kv| self.gpa.free(kv.value.data);
        try self.subnet_buffer.put(self.gpa, subnet.bytes, .{ .data = dup, .time_ns = monotonicNs() });
    }

    fn touchKey(self: *ReadWriteCloser, key: PublicKey) void {
        if (self.key_to_info.getPtr(key)) |info| info.last_seen_ns = monotonicNs();
    }

    // -------------------------------------------------------------------
    // Key discovery
    // -------------------------------------------------------------------

    /// Result of learning/refreshing a key mapping: any buffered packets
    /// that are now flushable as OutgoingFrames (caller must free with
    /// `node.core.freeFrames`).
    pub const UpdateResult = struct {
        frames: []node.core.OutgoingFrame,
    };

    /// Called when we learn a key mapping (from path notify callback or
    /// inbound traffic). Flushes any packets buffered while resolving.
    pub fn updateKey(self: *ReadWriteCloser, key: PublicKey) !UpdateResult {
        if (self.key_to_info.getPtr(key)) |info| {
            if (monotonicNs() - info.last_seen_ns < KEY_STORE_TIMEOUT_NS / 2) {
                return .{ .frames = &[_]node.core.OutgoingFrame{} };
            }
        }

        const address = node.addrForKey(&key);
        const subnet = node.subnetForKey(&key);
        const now = monotonicNs();

        try self.key_to_info.put(self.gpa, key, .{ .address = address, .subnet = subnet, .last_seen_ns = now });
        try self.addr_to_info.put(self.gpa, address.bytes, key);
        try self.subnet_to_info.put(self.gpa, subnet.bytes, key);

        var all_frames = std.ArrayListUnmanaged(node.core.OutgoingFrame).empty;
        errdefer {
            for (all_frames.items) |f| self.gpa.free(f.data);
            all_frames.deinit(self.gpa);
        }

        if (self.addr_buffer.fetchRemove(address.bytes)) |kv| {
            defer self.gpa.free(kv.value.data);
            if (now - kv.value.time_ns < KEY_STORE_TIMEOUT_NS) {
                const frames = try self.core.writeTo(&key, kv.value.data, node.core.TYPE_SESSION_TRAFFIC);
                try all_frames.appendSlice(self.gpa, frames);
                self.gpa.free(frames);
            }
        }
        if (self.subnet_buffer.fetchRemove(subnet.bytes)) |kv| {
            defer self.gpa.free(kv.value.data);
            if (now - kv.value.time_ns < KEY_STORE_TIMEOUT_NS) {
                const frames = try self.core.writeTo(&key, kv.value.data, node.core.TYPE_SESSION_TRAFFIC);
                try all_frames.appendSlice(self.gpa, frames);
                self.gpa.free(frames);
            }
        }
        return .{ .frames = try all_frames.toOwnedSlice(self.gpa) };
    }

    // -------------------------------------------------------------------
    // Inbound: mesh -> TUN
    // -------------------------------------------------------------------

    /// Given a decrypted application payload from `Core` (session-type byte
    /// still attached), validate it's TUN traffic and IPv6-shaped with a
    /// source address matching the sender's key. Returns the packet bytes
    /// (a view into `payload`, sans the type byte) to write to TUN, or null
    /// to drop.
    pub fn handleInbound(self: *ReadWriteCloser, source: *const PublicKey, payload: []const u8) ?[]const u8 {
        _ = self;
        _ = self;
        if (payload.len < 1) return null;
        if (payload[0] != node.core.TYPE_SESSION_TRAFFIC) return null;
        const pkt = payload[1..];
        if (pkt.len < IPV6_HEADER_LEN) return null;
        if (pkt[0] & 0xf0 != 0x60) return null; // not IPv6

        // Validate source address matches the sender's mesh key (anti-spoof).
        const expected_addr = node.addrForKey(source);
        const expected_subnet = node.subnetForKey(source);
        const src_bytes: [16]u8 = pkt[8..24].*;
        if (!std.mem.eql(u8, &src_bytes, &expected_addr.bytes) and
            !std.mem.eql(u8, src_bytes[0..8], &expected_subnet.bytes))
        {
            return null;
        }
        return pkt;
    }

    /// Build an ICMPv6 Packet Too Big message.
    pub fn buildPTB(pkt: []const u8, mtu: u32) ?[]u8 {
        if (pkt.len < IPV6_HEADER_LEN) return null;
        // Simplified: create minimal ICMPv6 PTB
        _ = mtu;
        return null; // Full implementation deferred
    }
};

const Firewall = @import("firewall.zig").Firewall;

fn monotonicNs() u64 {
    return @import("util").time.monotonicNanos();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "rwc init" {
    const gpa = testing.allocator;
    const id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();

    var rwc = try ReadWriteCloser.init(gpa, &core, 65535);
    defer rwc.deinit();
    try testing.expect(rwc.address.isValid());
}

test "update key caches and flushes buffered packet" {
    const gpa = testing.allocator;
    const id = ironwood.Crypto.generate();
    const peer_id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();
    var rwc = try ReadWriteCloser.init(gpa, &core, 65535);
    defer rwc.deinit();

    const peer_key = peer_id.public_key;
    const peer_addr = node.addrForKey(&peer_key);

    // Build a minimal fake IPv6 packet addressed to peer_addr.
    var pkt = [_]u8{0} ** 60;
    pkt[0] = 0x60; // version 6
    @memcpy(pkt[8..24], &node.addrForKey(&id.public_key).bytes); // src = us
    @memcpy(pkt[24..40], &peer_addr.bytes); // dst = peer

    const frames1 = try rwc.handleOutbound(&pkt);
    defer node.core.freeFrames(gpa, frames1);
    // No known key yet -> buffered + a lookup frame may or may not be
    // produced depending on router state, but no crash and no direct send.
    try testing.expect(rwc.addr_buffer.contains(peer_addr.bytes));

    const result = try rwc.updateKey(peer_key);
    defer node.core.freeFrames(gpa, result.frames);
    try testing.expect(rwc.key_to_info.contains(peer_key));
    try testing.expect(!rwc.addr_buffer.contains(peer_addr.bytes));
}

test "handleInbound validates source address" {
    const gpa = testing.allocator;
    const id = ironwood.Crypto.generate();
    const sender_id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();
    var rwc = try ReadWriteCloser.init(gpa, &core, 65535);
    defer rwc.deinit();

    const sender_addr = node.addrForKey(&sender_id.public_key);
    var payload = [_]u8{0} ** 61;
    payload[0] = node.core.TYPE_SESSION_TRAFFIC;
    payload[1] = 0x60;
    @memcpy(payload[9..25], &sender_addr.bytes); // src (offset by type byte)
    @memcpy(payload[25..41], &node.addrForKey(&id.public_key).bytes); // dst = us

    const result = rwc.handleInbound(&sender_id.public_key, &payload);
    try testing.expect(result != null);

    // Wrong source key should be rejected.
    const other = ironwood.Crypto.generate();
    const bad_result = rwc.handleInbound(&other.public_key, &payload);
    try testing.expect(bad_result == null);
}
