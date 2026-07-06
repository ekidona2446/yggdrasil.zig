//! Peer connection management.
//!
//! Manages peer connections: allocation, port assignment, and handle lookup.
//! Wire-compatible with Go Ironwood.

const std = @import("std");
const Allocator = std.mem.Allocator;

const wire_mod = @import("wire.zig");
const router_mod = @import("router.zig");
const crypto_mod = @import("crypto.zig");

pub const PeerPort = wire_mod.PeerPort;

// ---------------------------------------------------------------------------
// PeerHandle
// ---------------------------------------------------------------------------

/// Handle to a peer connection.
pub const PeerHandle = struct {
    id: router_mod.PeerId,
    key: crypto_mod.PublicKey,
    port: PeerPort,
    prio: u8,
    order: u64,

    pub fn toEntry(self: *const PeerHandle) router_mod.PeerEntry {
        return .{
            .id = self.id,
            .key = self.key,
            .port = self.port,
            .prio = self.prio,
            .order = self.order,
        };
    }
};

// ---------------------------------------------------------------------------
// Peers manager
// ---------------------------------------------------------------------------

pub const Peers = struct {
    next_id: router_mod.PeerId,
    used_ports: std.AutoHashMapUnmanaged(PeerPort, crypto_mod.PublicKey),
    handles: std.AutoHashMapUnmanaged(crypto_mod.PublicKey, std.AutoHashMapUnmanaged(router_mod.PeerId, PeerHandle)),
    order: u64,
    gpa: Allocator,

    pub fn init(gpa: Allocator) Peers {
        return .{
            .next_id = 1,
            .used_ports = .{},
            .handles = .{},
            .order = 0,
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *Peers) void {
        var hit = self.handles.iterator();
        while (hit.next()) |entry| {
            entry.value_ptr.deinit(self.gpa);
        }
        self.handles.deinit(self.gpa);
        self.used_ports.deinit(self.gpa);
    }

    /// Allocate a new peer handle. Caller owns the returned handle.
    pub fn allocatePeer(self: *Peers, key: crypto_mod.PublicKey, prio: u8) !PeerHandle {
        const id = self.next_id;
        self.next_id += 1;

        const port = if (self.handles.getPtr(key)) |existing|
            if (existing.count() > 0)
                blk: {
                    var iter = existing.iterator();
                    break :blk iter.next().?.value_ptr.port;
                }
            else
                try self.allocPort()
        else
            try self.allocPort();

        if (!self.handles.contains(key)) {
            try self.used_ports.put(self.gpa, port, key);
        }

        const order = self.order;
        self.order += 1;

        const handle = PeerHandle{
            .id = id,
            .key = key,
            .port = port,
            .prio = prio,
            .order = order,
        };

        const gop = try self.handles.getOrPut(self.gpa, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.put(self.gpa, id, handle);

        return handle;
    }

    fn allocPort(self: *Peers) !PeerPort {
        var p: PeerPort = 1;
        while (self.used_ports.contains(p)) {
            p += 1;
            if (p == 0) return error.PortExhausted;
        }
        return p;
    }

    /// Remove a peer by ID. Returns the freed port if this was the last peer for its key.
    pub fn removePeer(self: *Peers, id: router_mod.PeerId, key: *const crypto_mod.PublicKey) ?PeerPort {
        if (self.handles.getPtr(key.*)) |peers| {
            const port = if (peers.get(id)) |h| h.port else null;
            _ = peers.remove(id);
            if (peers.count() == 0) {
                if (self.handles.fetchRemove(key.*)) |kv| {
                    var sub = kv.value;
                    sub.deinit(self.gpa);
                }
                if (port) |p| _ = self.used_ports.remove(p);
            }
            return port;
        }
        return null;
    }

    /// Get a peer handle by ID.
    pub fn getHandle(self: *const Peers, peer_id: router_mod.PeerId) ?*const PeerHandle {
        var hit = self.handles.iterator();
        while (hit.next()) |entry| {
            if (entry.value_ptr.getPtr(peer_id)) |h| return h;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "allocate and remove peer" {
    const gpa = testing.allocator;
    var peers = Peers.init(gpa);
    defer peers.deinit();

    const key = [_]u8{0x42} ** 32;
    const handle = try peers.allocatePeer(key, 0);
    try testing.expectEqual(@as(router_mod.PeerId, 1), handle.id);
    try testing.expectEqual(@as(PeerPort, 1), handle.port);
    try testing.expect(peers.getHandle(1) != null);

    const port = peers.removePeer(1, &key);
    try testing.expectEqual(@as(PeerPort, 1), port.?);
    try testing.expect(peers.getHandle(1) == null);
}

test "port reuse for same key" {
    const gpa = testing.allocator;
    var peers = Peers.init(gpa);
    defer peers.deinit();

    const key = [_]u8{0xAA} ** 32;
    const h1 = try peers.allocatePeer(key, 0);
    const h2 = try peers.allocatePeer(key, 1);
    try testing.expectEqual(h1.port, h2.port);
    try testing.expect(h1.id != h2.id);
}

test "port scanning skips used" {
    const gpa = testing.allocator;
    var peers = Peers.init(gpa);
    defer peers.deinit();

    const k1 = [_]u8{1} ** 32;
    const k2 = [_]u8{2} ** 32;
    const h1 = try peers.allocatePeer(k1, 0);
    const h2 = try peers.allocatePeer(k2, 0);
    try testing.expectEqual(@as(PeerPort, 1), h1.port);
    try testing.expectEqual(@as(PeerPort, 2), h2.port);
}
