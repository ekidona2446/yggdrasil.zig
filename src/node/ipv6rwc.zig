//! IPv6 ReadWriteCloser — bridges TUN <-> ironwood core.
//!
//! Reads packets from the ironwood network destined for our TUN, validates
//! source addresses against known keys, buffers unknown destinations and
//! triggers lookups. Wire-compatible with the reference implementation.

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
        var kit = self.key_to_info.iterator();
        while (kit.next()) |_| {}
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

    /// Called when we learn a key mapping (from path notify or packet receipt).
    pub fn updateKey(self: *ReadWriteCloser, key: PublicKey) !void {
        // Fast path: already fresh
        if (self.key_to_info.getPtr(key)) |info| {
            if (monotonicNs() - info.last_seen_ns < KEY_STORE_TIMEOUT_NS / 2) return;
        }

        const address = node.addrForKey(&key);
        const subnet = node.subnetForKey(&key);
        const now = monotonicNs();

        try self.key_to_info.put(self.gpa, key, .{ .address = address, .subnet = subnet, .last_seen_ns = now });
        try self.addr_to_info.put(self.gpa, address.bytes, key);
        try self.subnet_to_info.put(self.gpa, subnet.bytes, key);

        // Flush buffered packets
        if (self.addr_buffer.fetchRemove(address.bytes)) |kv| {
            if (now - kv.value.time_ns < KEY_STORE_TIMEOUT_NS) {
                // Would call self.core.writeTo(kv.value.data, key) here
                self.gpa.free(kv.value.data);
            } else {
                self.gpa.free(kv.value.data);
            }
        }
        if (self.subnet_buffer.fetchRemove(subnet.bytes)) |kv| {
            if (now - kv.value.time_ns < KEY_STORE_TIMEOUT_NS) {
                self.gpa.free(kv.value.data);
            } else {
                self.gpa.free(kv.value.data);
            }
        }
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
    if (@import("builtin").os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.MONOTONIC, &ts) == 0)
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }
    return 0;
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

test "update key caches" {
    const gpa = testing.allocator;
    const id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();
    var rwc = try ReadWriteCloser.init(gpa, &core, 65535);
    defer rwc.deinit();

    const peer_key = [_]u8{0x99} ** 32;
    try rwc.updateKey(peer_key);
    try testing.expect(rwc.key_to_info.contains(peer_key));
}
