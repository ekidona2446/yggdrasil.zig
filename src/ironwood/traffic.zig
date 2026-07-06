//! Traffic packet and Deficit Round Robin (DRR) packet queue.
//!
//! The packet queue groups packets into flows keyed by (source, dest) and
//! schedules them with deficit round robin, giving long-term byte fairness
//! across flows (so many small packets can't starve fewer large ones). The
//! queue is hard-bounded in memory: a global byte cap and a per-flow byte cap,
//! enforced inside `push` by evicting the oldest packet from the largest flow.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cryptomod = @import("crypto.zig");
const PublicKey = cryptomod.PublicKey;
const PUBLIC_KEY_SIZE = cryptomod.PUBLIC_KEY_SIZE;
const wire = @import("wire.zig");
const PeerPort = wire.PeerPort;
const timemod = @import("util").time;
const Instant = timemod.Instant;

// ---------------------------------------------------------------------------
// TrafficPacket
// ---------------------------------------------------------------------------

/// A user traffic packet routed through the network. Owns its `path`, `from`,
/// and `payload` slices; call `deinit` to free them.
pub const TrafficPacket = struct {
    path: []PeerPort,
    from: []PeerPort,
    source: PublicKey,
    dest: PublicKey,
    watermark: u64,
    payload: []u8,

    /// Create a packet with empty path/from and a maximal watermark, taking
    /// ownership of `payload` (must be allocator-owned).
    pub fn init(source: PublicKey, dest: PublicKey, payload: []u8) TrafficPacket {
        return .{
            .path = &.{},
            .from = &.{},
            .source = source,
            .dest = dest,
            .watermark = std.math.maxInt(u64),
            .payload = payload,
        };
    }

    pub fn deinit(self: *TrafficPacket, gpa: Allocator) void {
        if (self.path.len != 0) gpa.free(self.path);
        if (self.from.len != 0) gpa.free(self.from);
        if (self.payload.len != 0) gpa.free(self.payload);
        self.path = &.{};
        self.from = &.{};
        self.payload = &.{};
    }

    /// Deep copy; caller owns the result and must `deinit` it.
    pub fn clone(self: *const TrafficPacket, gpa: Allocator) Allocator.Error!TrafficPacket {
        const path = try gpa.dupe(PeerPort, self.path);
        errdefer gpa.free(path);
        const from = try gpa.dupe(PeerPort, self.from);
        errdefer gpa.free(from);
        const payload = try gpa.dupe(u8, self.payload);
        return .{
            .path = path,
            .from = from,
            .source = self.source,
            .dest = self.dest,
            .watermark = self.watermark,
            .payload = payload,
        };
    }

    /// Replace the owned `path` with a copy of `new_path`.
    pub fn setPath(self: *TrafficPacket, gpa: Allocator, new_path: []const PeerPort) Allocator.Error!void {
        const dup = try gpa.dupe(PeerPort, new_path);
        if (self.path.len != 0) gpa.free(self.path);
        self.path = dup;
    }

    /// Replace the owned `from` with a copy of `new_from`.
    pub fn setFrom(self: *TrafficPacket, gpa: Allocator, new_from: []const PeerPort) Allocator.Error!void {
        const dup = try gpa.dupe(PeerPort, new_from);
        if (self.from.len != 0) gpa.free(self.from);
        self.from = dup;
    }

    /// Estimated wire size of the packet (used for queue size accounting).
    pub fn wireSize(self: *const TrafficPacket) u64 {
        return @intCast(wire.pathSize(self.path) + wire.pathSize(self.from) +
            PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE +
            wire.uvarintSize(self.watermark) + self.payload.len);
    }
};

// ---------------------------------------------------------------------------
// FlowDeque: FIFO of queued packets for a single flow
// ---------------------------------------------------------------------------

const PqPacketInfo = struct {
    packet: TrafficPacket,
    size: u64,
    time: Instant,
};

/// A FIFO deque backed by a growable buffer with a moving head index.
/// Compacts when the dead prefix grows large to bound memory.
const Deque = struct {
    items: std.ArrayListUnmanaged(PqPacketInfo) = .empty,
    head: usize = 0,

    fn deinit(self: *Deque, gpa: Allocator) void {
        // Free any packets still queued (from head onward).
        var i = self.head;
        while (i < self.items.items.len) : (i += 1) {
            self.items.items[i].packet.deinit(gpa);
        }
        self.items.deinit(gpa);
    }

    fn len(self: *const Deque) usize {
        return self.items.items.len - self.head;
    }

    fn isEmpty(self: *const Deque) bool {
        return self.len() == 0;
    }

    fn pushBack(self: *Deque, gpa: Allocator, info: PqPacketInfo) Allocator.Error!void {
        try self.items.append(gpa, info);
    }

    fn front(self: *const Deque) ?*const PqPacketInfo {
        if (self.isEmpty()) return null;
        return &self.items.items[self.head];
    }

    fn popFront(self: *Deque) ?PqPacketInfo {
        if (self.isEmpty()) return null;
        const info = self.items.items[self.head];
        self.head += 1;
        // Compact when the dead prefix dominates, to release memory.
        if (self.head > 32 and self.head * 2 >= self.items.items.len) {
            const live = self.items.items.len - self.head;
            std.mem.copyForwards(PqPacketInfo, self.items.items[0..live], self.items.items[self.head..]);
            self.items.shrinkRetainingCapacity(live);
            self.head = 0;
        }
        return info;
    }
};

// ---------------------------------------------------------------------------
// PacketQueue: deficit round robin (DRR) scheduling, byte-bounded
// ---------------------------------------------------------------------------

const DEFAULT_PACKET_QUEUE_MAX_BYTES_MULTIPLIER: u64 = 16;
const DEFAULT_PACKET_QUEUE_PER_FLOW_MULTIPLIER: u64 = 4;
const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

/// Stable identity of a queued flow: the original sender and intended receiver.
const FlowKey = struct {
    source: PublicKey,
    dest: PublicKey,
};

/// A single flow's backlog plus its DRR scheduling state.
const Flow = struct {
    infos: Deque = .{},
    size: u64 = 0,
    deficit: u64 = 0,
    /// Position in `PacketQueue.active`, or null when inactive.
    index: ?usize = null,
};

pub const PacketQueue = struct {
    flows: std.AutoHashMapUnmanaged(FlowKey, Flow) = .{},
    active: std.ArrayListUnmanaged(FlowKey) = .empty,
    next: ?usize = null,
    size: u64 = 0,
    max_bytes_total: u64,
    max_bytes_per_flow: u64,
    quantum: u64,
    gpa: Allocator,

    pub fn init(gpa: Allocator, quantum_in: u64) PacketQueue {
        const quantum = if (quantum_in == 0) DEFAULT_MAX_MESSAGE_SIZE else quantum_in;
        return .{
            .max_bytes_total = quantum * DEFAULT_PACKET_QUEUE_MAX_BYTES_MULTIPLIER,
            .max_bytes_per_flow = quantum * DEFAULT_PACKET_QUEUE_PER_FLOW_MULTIPLIER,
            .quantum = quantum,
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        var it = self.flows.valueIterator();
        while (it.next()) |flow| flow.infos.deinit(self.gpa);
        self.flows.deinit(self.gpa);
        self.active.deinit(self.gpa);
    }

    pub fn isEmpty(self: *const PacketQueue) bool {
        return self.size == 0;
    }

    pub fn sizeBytes(self: *const PacketQueue) u64 {
        return self.size;
    }

    fn activate(self: *PacketQueue, key: FlowKey) Allocator.Error!void {
        const idx = self.active.items.len;
        try self.active.append(self.gpa, key);
        if (self.flows.getPtr(key)) |flow| flow.index = idx;
    }

    fn deactivate(self: *PacketQueue, key: FlowKey) void {
        const idx = blk: {
            const f = self.flows.getPtr(key) orelse return;
            break :blk f.index orelse return;
        };
        const last = self.active.items.len - 1;
        if (idx > last) return;
        if (idx != last) {
            const moved = self.active.items[last];
            self.active.items[idx] = moved;
            if (self.flows.getPtr(moved)) |mf| mf.index = idx;
        }
        _ = self.active.pop();
        if (self.flows.getPtr(key)) |flow| flow.index = null;
        if (self.active.items.len == 0) {
            self.next = null;
            return;
        }
        if (self.next != null and self.next.? == last) self.next = idx;
        if (self.next) |n| {
            if (n >= self.active.items.len) self.next = 0;
        }
    }

    fn flowFor(self: *PacketQueue, key: FlowKey) Allocator.Error!*Flow {
        const gop = try self.flows.getOrPut(self.gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = Flow{};
        return gop.value_ptr;
    }

    fn removeFlowIfEmpty(self: *PacketQueue, key: FlowKey) void {
        const f = self.flows.getPtr(key) orelse return;
        if (!f.infos.isEmpty()) return;
        const active = f.index != null;
        if (active) self.deactivate(key);
        if (self.flows.fetchRemove(key)) |kv| {
            var flow = kv.value;
            flow.infos.deinit(self.gpa);
        }
    }

    /// Remove and return the head packet of a specific flow.
    fn dropFrom(self: *PacketQueue, key: FlowKey) ?PqPacketInfo {
        const deficit_cap = self.quantum * 4;
        const info = blk: {
            const flow = self.flows.getPtr(key) orelse return null;
            const info = flow.infos.popFront() orelse return null;
            flow.size -= info.size;
            if (flow.deficit > deficit_cap) flow.deficit = deficit_cap;
            break :blk info;
        };
        self.size -= info.size;
        self.removeFlowIfEmpty(key);
        return info;
    }

    /// Find the active flow with the most queued bytes (oldest head breaks ties).
    fn largestFlow(self: *const PacketQueue) ?FlowKey {
        var best: ?FlowKey = null;
        var best_size: u64 = 0;
        var best_time: Instant = .{ .nanos = 0 };
        for (self.active.items) |k| {
            const f = self.flows.getPtr(k) orelse continue;
            const head = f.infos.front() orelse continue;
            const replace = if (best == null)
                true
            else if (f.size != best_size)
                f.size > best_size
            else
                // tie on size: prefer the older head (smaller time).
                head.time.order(best_time) == .lt;
            if (replace) {
                best = k;
                best_size = f.size;
                best_time = head.time;
            }
        }
        return best;
    }

    /// Drop the oldest packet from the largest flow. Returns true if dropped.
    pub fn dropLargest(self: *PacketQueue) bool {
        if (self.largestFlow()) |key| {
            if (self.dropFrom(key)) |info| {
                var i = info;
                i.packet.deinit(self.gpa);
                return true;
            }
        }
        return false;
    }

    /// Add a packet to the queue, hard-bounded globally and per flow.
    /// Takes ownership of `packet` (frees it if rejected/evicted).
    pub fn push(self: *PacketQueue, packet: TrafficPacket) Allocator.Error!void {
        var pkt = packet;
        const pkt_size = pkt.wireSize();
        if (pkt_size > self.max_bytes_total or pkt_size > self.max_bytes_per_flow) {
            pkt.deinit(self.gpa);
            return;
        }
        const key = FlowKey{ .source = pkt.source, .dest = pkt.dest };
        const info = PqPacketInfo{ .packet = pkt, .size = pkt_size, .time = Instant.now() };

        _ = try self.flowFor(key);

        // Per-flow cap: evict this flow's oldest packets until the new one fits.
        while (true) {
            const fs: struct { size: u64, count: usize } = if (self.flows.getPtr(key)) |f|
                .{ .size = f.size, .count = f.infos.len() }
            else
                .{ .size = 0, .count = 0 };
            if (fs.size + pkt_size <= self.max_bytes_per_flow or fs.count == 0) break;
            if (self.dropFrom(key)) |dropped| {
                var d = dropped;
                d.packet.deinit(self.gpa);
            } else {
                var i = info;
                i.packet.deinit(self.gpa);
                return;
            }
        }

        // Global cap: evict from the largest flow until the new packet fits.
        while (self.size + pkt_size > self.max_bytes_total and self.size > 0) {
            if (!self.dropLargest()) {
                var i = info;
                i.packet.deinit(self.gpa);
                return;
            }
        }

        // The flow may have been deleted while making room; re-acquire it.
        const flow = try self.flowFor(key);
        try flow.infos.pushBack(self.gpa, info);
        flow.size += pkt_size;
        const needs_activate = flow.index == null;
        self.size += pkt_size;
        if (needs_activate) try self.activate(key);
    }

    /// Remove and return the next packet using deficit round robin.
    fn popInfo(self: *PacketQueue) ?PqPacketInfo {
        if (self.isEmpty() or self.active.items.len == 0) {
            self.next = null;
            return null;
        }

        var need_credit = false;
        if (self.next == null) {
            self.next = 0;
            need_credit = true;
        } else if (self.next.? >= self.active.items.len) {
            self.next = 0;
        }

        const quantum = self.quantum;
        var idx = self.next.?;
        var key = self.active.items[idx];

        if (need_credit) {
            if (self.flows.getPtr(key)) |flow| flow.deficit += quantum;
        }

        while (true) {
            const serveable = blk: {
                const f = self.flows.getPtr(key) orelse break :blk false;
                const head = f.infos.front() orelse break :blk false;
                break :blk head.size <= f.deficit;
            };
            if (serveable) {
                if (self.dropFrom(key)) |info| {
                    if (self.flows.getPtr(key)) |flow| flow.deficit -= info.size;
                    return info;
                }
            }
            idx += 1;
            if (idx >= self.active.items.len) idx = 0;
            self.next = idx;
            key = self.active.items[idx];
            if (self.flows.getPtr(key)) |flow| flow.deficit += quantum;
        }
    }

    /// Remove and return the next packet (DRR order). Caller owns the packet.
    pub fn pop(self: *PacketQueue) ?TrafficPacket {
        if (self.popInfo()) |info| return info.packet;
        return null;
    }

    /// Age in nanoseconds of the oldest packet across flows, or null if empty.
    pub fn oldestAgeNanos(self: *const PacketQueue) ?u64 {
        var oldest: ?Instant = null;
        for (self.active.items) |k| {
            const f = self.flows.getPtr(k) orelse continue;
            const head = f.infos.front() orelse continue;
            if (oldest == null or head.time.order(oldest.?) == .lt) oldest = head.time;
        }
        if (oldest) |o| return o.elapsedNanos();
        return null;
    }
};

// ---------------------------------------------------------------------------
// DeliveryQueue: queue + recv-ready counting
// ---------------------------------------------------------------------------

/// Maximum age for queued packets before they are dropped (25 ms).
pub const MAX_PACKET_AGE_NS: u64 = 25 * std.time.ns_per_ms;

/// Lightweight CAS spinlock (Zig 0.16 removed `std.Thread.Mutex`); the queue's
/// critical sections are short and contain no async suspension points.
const SpinLock = struct {
    state: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fn lock(self: *SpinLock) void {
        while (self.state.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    fn unlock(self: *SpinLock) void {
        self.state.store(false, .release);
    }
};

/// Manages the packet queue with receive-ready counting. Packets are queued
/// when no reader is waiting and handed back for immediate send when one is.
pub const DeliveryQueue = struct {
    lock: SpinLock = .{},
    queue: PacketQueue,
    recv_ready: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(gpa: Allocator, quantum: u64) DeliveryQueue {
        return .{ .queue = PacketQueue.init(gpa, quantum) };
    }

    pub fn deinit(self: *DeliveryQueue) void {
        self.queue.deinit();
    }

    /// Attempt to deliver a packet. Returns the packet (ownership) if a reader
    /// is waiting (caller should send it immediately), or null if it was queued
    /// (or dropped). Takes ownership of `packet`.
    pub fn deliver(self: *DeliveryQueue, packet: TrafficPacket) Allocator.Error!?TrafficPacket {
        // Fast path: a reader is waiting.
        if (self.recv_ready.load(.acquire) > 0) {
            _ = self.recv_ready.fetchSub(1, .acq_rel);
            return packet;
        }
        // Slow path: queue it.
        self.lock.lock();
        defer self.lock.unlock();
        if (self.queue.oldestAgeNanos()) |age| {
            if (age > MAX_PACKET_AGE_NS) _ = self.queue.dropLargest();
        }
        try self.queue.push(packet);
        return null;
    }

    pub fn queueSize(self: *DeliveryQueue) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.queue.sizeBytes();
    }

    /// Called by a reader before parking. Returns a queued packet if available
    /// (ownership), or null if the reader should wait (recv_ready incremented).
    pub fn tryPopOrWait(self: *DeliveryQueue) ?TrafficPacket {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.queue.pop()) |packet| return packet;
        _ = self.recv_ready.fetchAdd(1, .acq_rel);
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makePacket(gpa: Allocator, src: u8, dst: u8, payload: []const u8) !TrafficPacket {
    return TrafficPacket.init([_]u8{src} ** 32, [_]u8{dst} ** 32, try gpa.dupe(u8, payload));
}

fn bigQueue(gpa: Allocator) PacketQueue {
    return PacketQueue.init(gpa, 1024 * 1024);
}

test "push and pop FIFO across two flows" {
    const gpa = testing.allocator;
    var q = bigQueue(gpa);
    defer q.deinit();

    try q.push(try makePacket(gpa, 1, 2, "hello"));
    try q.push(try makePacket(gpa, 3, 4, "world"));
    try testing.expect(!q.isEmpty());

    var p1 = q.pop().?;
    defer p1.deinit(gpa);
    try testing.expectEqualSlices(u8, "hello", p1.payload);
    var p2 = q.pop().?;
    defer p2.deinit(gpa);
    try testing.expectEqualSlices(u8, "world", p2.payload);
    try testing.expect(q.isEmpty());
    try testing.expect(q.pop() == null);
}

test "drop_largest removes from biggest flow" {
    const gpa = testing.allocator;
    var q = bigQueue(gpa);
    defer q.deinit();

    try q.push(try makePacket(gpa, 1, 2, &[_]u8{0} ** 100));
    try q.push(try makePacket(gpa, 1, 2, &[_]u8{0} ** 100));
    try q.push(try makePacket(gpa, 1, 2, &[_]u8{0} ** 100));
    try q.push(try makePacket(gpa, 3, 4, &[_]u8{0} ** 100));

    try testing.expect(q.dropLargest());

    var count: usize = 0;
    while (q.pop()) |p| {
        var pp = p;
        pp.deinit(gpa);
        count += 1;
    }
    try testing.expectEqual(@as(usize, 3), count);
}

test "same dest different sources" {
    const gpa = testing.allocator;
    var q = bigQueue(gpa);
    defer q.deinit();

    try q.push(try makePacket(gpa, 1, 10, "a"));
    try q.push(try makePacket(gpa, 2, 10, "b"));
    try q.push(try makePacket(gpa, 3, 10, "c"));

    inline for (.{ "a", "b", "c" }) |expected| {
        var p = q.pop().?;
        defer p.deinit(gpa);
        try testing.expectEqualSlices(u8, expected, p.payload);
    }
}

test "DRR round-robin fairness alternates flows" {
    const gpa = testing.allocator;
    // Quantum just above one packet => one credit round serves one packet.
    var probe = try makePacket(gpa, 1, 2, &[_]u8{0} ** 1000);
    const w = probe.wireSize();
    probe.deinit(gpa);

    var q = PacketQueue.init(gpa, w + 1);
    defer q.deinit();

    var i: usize = 0;
    while (i < 4) : (i += 1) try q.push(try makePacket(gpa, 1, 2, &[_]u8{0} ** 1000));
    i = 0;
    while (i < 4) : (i += 1) try q.push(try makePacket(gpa, 3, 2, &[_]u8{0} ** 1000));

    var sources = std.ArrayListUnmanaged(u8).empty;
    defer sources.deinit(gpa);
    while (q.pop()) |p| {
        var pp = p;
        try sources.append(gpa, pp.source[0]);
        pp.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 8), sources.items.len);
    for (sources.items, 0..) |s, idx| {
        const expected: u8 = if (idx % 2 == 0) 1 else 3;
        try testing.expectEqual(expected, s);
    }
}

test "per-flow byte cap eviction keeps newest FIFO survivors" {
    const gpa = testing.allocator;
    var q = PacketQueue.init(gpa, 1024);
    defer q.deinit();
    const cap = q.max_bytes_per_flow;

    const N: u8 = 40;
    var i: u8 = 0;
    while (i < N) : (i += 1) {
        var payload = [_]u8{0} ** 200;
        payload[0] = i;
        try q.push(try makePacket(gpa, 1, 2, &payload));
        try testing.expect(q.sizeBytes() <= cap);
    }

    var tags = std.ArrayListUnmanaged(u8).empty;
    defer tags.deinit(gpa);
    while (q.pop()) |p| {
        var pp = p;
        try tags.append(gpa, pp.payload[0]);
        pp.deinit(gpa);
    }
    try testing.expect(tags.items.len > 0);
    try testing.expectEqual(N - 1, tags.items[tags.items.len - 1]);
    try testing.expect(tags.items[0] > 0);
    var j: usize = 1;
    while (j < tags.items.len) : (j += 1) {
        try testing.expectEqual(tags.items[j - 1] + 1, tags.items[j]);
    }
}

test "total byte cap eviction drops largest flows, spares tiny flow" {
    const gpa = testing.allocator;
    var q = PacketQueue.init(gpa, 1024);
    defer q.deinit();
    const total_cap = q.max_bytes_total;

    try q.push(try makePacket(gpa, 100, 200, &[_]u8{7} ** 10));

    var src: u8 = 1;
    while (src <= 5) : (src += 1) {
        var n: usize = 0;
        while (n < 8) : (n += 1) {
            try q.push(try makePacket(gpa, src, 2, &[_]u8{0} ** 500));
            try testing.expect(q.sizeBytes() <= total_cap);
        }
    }

    var saw_small = false;
    while (q.pop()) |p| {
        var pp = p;
        if (pp.source[0] == 100) saw_small = true;
        pp.deinit(gpa);
    }
    try testing.expect(saw_small);
}

test "oversized packet rejected" {
    const gpa = testing.allocator;
    var q = PacketQueue.init(gpa, 1024); // per-flow cap = 4096
    defer q.deinit();
    try q.push(try makePacket(gpa, 1, 2, &[_]u8{0} ** 5000));
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(u64, 0), q.sizeBytes());
    try testing.expect(q.pop() == null);
}

test "delivery queue: deliver returns packet when reader waiting, else queues" {
    const gpa = testing.allocator;
    var dq = DeliveryQueue.init(gpa, 1024 * 1024);
    defer dq.deinit();

    // No reader waiting: packet is queued, deliver returns null.
    const r1 = try dq.deliver(try makePacket(gpa, 1, 2, "queued"));
    try testing.expect(r1 == null);
    try testing.expect(dq.queueSize() > 0);

    // Reader parks; there's already a queued packet so it pops immediately.
    var popped = dq.tryPopOrWait().?;
    defer popped.deinit(gpa);
    try testing.expectEqualSlices(u8, "queued", popped.payload);

    // Now no packet queued: reader registers as waiting.
    try testing.expect(dq.tryPopOrWait() == null);

    // With a reader waiting, deliver hands the packet straight back.
    var direct = (try dq.deliver(try makePacket(gpa, 3, 4, "direct"))).?;
    defer direct.deinit(gpa);
    try testing.expectEqualSlices(u8, "direct", direct.payload);
}
