//! Bloom filter, wire-compatible with Go's bits-and-blooms/bloom library.
//!
//! Hashing scheme (must match the Go library exactly):
//!   - MurmurHash3 x64 128-bit produces 4 base hash values (h1..h4).
//!   - location(h, i) = h[i%2] + i*h[2 + (((i + (i%2)) % 4) / 2)]
//!
//! Wire format: [16 bytes zero-flags][16 bytes ones-flags][remaining u64s big-endian].
//! The wire encode/decode lives in `wire.zig`; this module re-exports them.

const std = @import("std");
const Allocator = std.mem.Allocator;

const wire = @import("wire.zig");
const cryptomod = @import("crypto.zig");
const PublicKey = cryptomod.PublicKey;
const types = @import("types.zig");

// Configuration constants — must match the Go library.
pub const BLOOM_FILTER_BITS: usize = 8192;
pub const BLOOM_FILTER_K: usize = 8;
pub const BLOOM_FILTER_U64S: usize = BLOOM_FILTER_BITS / 64; // 128

comptime {
    std.debug.assert(BLOOM_FILTER_U64S == wire.BLOOM_FILTER_U64S);
}

// Re-export wire codec so callers can `bloom.encodeBloom(...)`.
pub const encodeBloom = wire.encodeBloom;
pub const decodeBloom = wire.decodeBloom;
pub const bloomWireSize = wire.bloomWireSize;

// ---------------------------------------------------------------------------
// MurmurHash3 x64 128-bit
// ---------------------------------------------------------------------------

inline fn rotl64(x: u64, r: u6) u64 {
    return std.math.rotl(u64, x, r);
}

inline fn fmix64(k_in: u64) u64 {
    var k = k_in;
    k ^= k >> 33;
    k *%= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *%= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;
    return k;
}

pub fn murmur3X64_128(data: []const u8, seed: u32) u128 {
    const c1: u64 = 0x87c37b91114253d5;
    const c2: u64 = 0x4cf5ad432745937f;

    var h1: u64 = seed;
    var h2: u64 = seed;

    const nblocks = data.len / 16;

    // Body: process 16-byte blocks.
    var i: usize = 0;
    while (i < nblocks) : (i += 1) {
        const base = i * 16;
        var k1 = std.mem.readInt(u64, data[base .. base + 8][0..8], .little);
        var k2 = std.mem.readInt(u64, data[base + 8 .. base + 16][0..8], .little);

        k1 *%= c1;
        k1 = rotl64(k1, 31);
        k1 *%= c2;
        h1 ^= k1;

        h1 = rotl64(h1, 27);
        h1 +%= h2;
        h1 = h1 *% 5 +% 0x52dce729;

        k2 *%= c2;
        k2 = rotl64(k2, 33);
        k2 *%= c1;
        h2 ^= k2;

        h2 = rotl64(h2, 31);
        h2 +%= h1;
        h2 = h2 *% 5 +% 0x38495ab5;
    }

    // Tail: remaining 1..15 bytes.
    const tail = data[nblocks * 16 ..];
    var k1: u64 = 0;
    var k2: u64 = 0;

    const tl = tail.len;
    if (tl >= 15) k2 ^= @as(u64, tail[14]) << 48;
    if (tl >= 14) k2 ^= @as(u64, tail[13]) << 40;
    if (tl >= 13) k2 ^= @as(u64, tail[12]) << 32;
    if (tl >= 12) k2 ^= @as(u64, tail[11]) << 24;
    if (tl >= 11) k2 ^= @as(u64, tail[10]) << 16;
    if (tl >= 10) k2 ^= @as(u64, tail[9]) << 8;
    if (tl >= 9) {
        k2 ^= @as(u64, tail[8]);
        k2 *%= c2;
        k2 = rotl64(k2, 33);
        k2 *%= c1;
        h2 ^= k2;
    }

    if (tl >= 8) k1 ^= @as(u64, tail[7]) << 56;
    if (tl >= 7) k1 ^= @as(u64, tail[6]) << 48;
    if (tl >= 6) k1 ^= @as(u64, tail[5]) << 40;
    if (tl >= 5) k1 ^= @as(u64, tail[4]) << 32;
    if (tl >= 4) k1 ^= @as(u64, tail[3]) << 24;
    if (tl >= 3) k1 ^= @as(u64, tail[2]) << 16;
    if (tl >= 2) k1 ^= @as(u64, tail[1]) << 8;
    if (tl >= 1) {
        k1 ^= @as(u64, tail[0]);
        k1 *%= c1;
        k1 = rotl64(k1, 31);
        k1 *%= c2;
        h1 ^= k1;
    }

    // Finalization.
    h1 ^= @as(u64, data.len);
    h2 ^= @as(u64, data.len);

    h1 +%= h2;
    h2 +%= h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 +%= h2;
    h2 +%= h1;

    return (@as(u128, h2) << 64) | @as(u128, h1);
}

/// Generate four base hash values, replicating Go's `sum256`:
///   1. murmur3(data)        -> h1, h2
///   2. murmur3(data || [1]) -> h3, h4
fn baseHashes(data: []const u8) [4]u64 {
    const r1 = murmur3X64_128(data, 0);
    const h1: u64 = @truncate(r1);
    const h2: u64 = @truncate(r1 >> 64);

    // data || [1]; use a small stack buffer for typical key sizes, else heap.
    var stack_buf: [256]u8 = undefined;
    var r2: u128 = undefined;
    if (data.len + 1 <= stack_buf.len) {
        @memcpy(stack_buf[0..data.len], data);
        stack_buf[data.len] = 1;
        r2 = murmur3X64_128(stack_buf[0 .. data.len + 1], 0);
    } else {
        // Rare for 32-byte keys; allocate via page allocator for correctness.
        const gpa = std.heap.page_allocator;
        const buf = gpa.alloc(u8, data.len + 1) catch unreachable;
        defer gpa.free(buf);
        @memcpy(buf[0..data.len], data);
        buf[data.len] = 1;
        r2 = murmur3X64_128(buf, 0);
    }
    const h3: u64 = @truncate(r2);
    const h4: u64 = @truncate(r2 >> 64);

    return .{ h1, h2, h3, h4 };
}

/// Calculate the ith hash bit location:
/// location(h, i) = h[i%2] + i*h[2 + (((i + (i%2)) % 4) / 2)]
fn location(h: *const [4]u64, i: usize, m: usize) usize {
    const ii: u64 = @intCast(i);
    const base = h[i % 2];
    const inner = (i + (i % 2)) % 4;
    const hash_idx = 2 + (inner / 2);
    const mult = h[hash_idx];
    const loc = base +% (ii *% mult);
    return @intCast(loc % @as(u64, @intCast(m)));
}

// ---------------------------------------------------------------------------
// BloomFilter
// ---------------------------------------------------------------------------

pub const BloomFilter = struct {
    bits: [BLOOM_FILTER_U64S]u64,

    pub fn init() BloomFilter {
        return .{ .bits = [_]u64{0} ** BLOOM_FILTER_U64S };
    }

    pub fn fromRaw(bits: [BLOOM_FILTER_U64S]u64) BloomFilter {
        return .{ .bits = bits };
    }

    pub fn asRaw(self: *const BloomFilter) *const [BLOOM_FILTER_U64S]u64 {
        return &self.bits;
    }

    fn setBit(self: *BloomFilter, bit: usize) void {
        const idx = bit / 64;
        const offset: u6 = @intCast(bit % 64);
        self.bits[idx] |= @as(u64, 1) << offset;
    }

    fn getBit(self: *const BloomFilter, bit: usize) bool {
        const idx = bit / 64;
        const offset: u6 = @intCast(bit % 64);
        return (self.bits[idx] >> offset) & 1 == 1;
    }

    /// Add a key to the filter.
    pub fn add(self: *BloomFilter, key: []const u8) void {
        const h = baseHashes(key);
        var i: usize = 0;
        while (i < BLOOM_FILTER_K) : (i += 1) {
            self.setBit(location(&h, i, BLOOM_FILTER_BITS));
        }
    }

    /// Test whether a key might be present. False = definitely absent.
    pub fn testKey(self: *const BloomFilter, key: []const u8) bool {
        const h = baseHashes(key);
        var i: usize = 0;
        while (i < BLOOM_FILTER_K) : (i += 1) {
            if (!self.getBit(location(&h, i, BLOOM_FILTER_BITS))) return false;
        }
        return true;
    }

    /// Merge another filter into this one (bitwise OR).
    pub fn merge(self: *BloomFilter, other: *const BloomFilter) void {
        for (&self.bits, other.bits) |*a, b| a.* |= b;
    }

    /// Count the number of set bits.
    pub fn countOnes(self: *const BloomFilter) u32 {
        var total: u32 = 0;
        for (self.bits) |w| total += @popCount(w);
        return total;
    }

    pub fn equal(self: *const BloomFilter, other: *const BloomFilter) bool {
        return std.mem.eql(u64, &self.bits, &other.bits);
    }

    /// Encode this filter to wire format, appending to `out`.
    pub fn encode(self: *const BloomFilter, out: *std.ArrayListUnmanaged(u8), gpa: Allocator) Allocator.Error!void {
        try encodeBloom(out, gpa, &self.bits);
    }

    /// Decode a filter from wire format.
    pub fn decode(data: []const u8) types.Error!BloomFilter {
        return .{ .bits = try decodeBloom(data) };
    }
};

// ---------------------------------------------------------------------------
// Blooms manager: per-peer bloom filter state
// ---------------------------------------------------------------------------

const config = @import("config.zig");

/// Map from peer public key -> value, keyed on the raw 32-byte key.
fn KeyMap(comptime V: type) type {
    return std.AutoHashMapUnmanaged(PublicKey, V);
}

/// Per-peer bloom filter tracking.
pub const BloomInfo = struct {
    /// What we advertise to this peer.
    send: BloomFilter,
    /// What we received from this peer.
    recv: BloomFilter,
    /// Sequence counter for periodic resend.
    seq: u16,
    /// Whether this peer is on the spanning tree.
    on_tree: bool,
    /// Whether we've set unnecessary 1 bits (need cleanup).
    z_dirty: bool,

    pub fn init() BloomInfo {
        return .{
            .send = BloomFilter.init(),
            .recv = BloomFilter.init(),
            .seq = 0,
            .on_tree = false,
            .z_dirty = false,
        };
    }
};

/// A (peer_key, filter) pair produced by maintenance routines.
pub const KeyBloom = struct {
    key: PublicKey,
    filter: BloomFilter,
};

/// Manages bloom filters for all peers.
///
/// The `transform` callback corresponds to `Config.bloom_transform`; when
/// `null` the identity function is used.
pub const Blooms = struct {
    blooms: KeyMap(BloomInfo),
    transform: ?config.BloomTransformFn,
    gpa: Allocator,

    pub fn init(gpa: Allocator, transform: ?config.BloomTransformFn) Blooms {
        return .{
            .blooms = KeyMap(BloomInfo){},
            .transform = transform,
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *Blooms) void {
        self.blooms.deinit(self.gpa);
    }

    /// Apply the bloom transform to a key (identity if none configured).
    pub fn xKey(self: *const Blooms, key: *const PublicKey) PublicKey {
        if (self.transform) |f| return f(key.*);
        return key.*;
    }

    /// Whether a peer is currently on the spanning tree.
    pub fn isOnTree(self: *const Blooms, key: *const PublicKey) bool {
        if (self.blooms.get(key.*)) |info| return info.on_tree;
        return false;
    }

    /// Add bloom info for a new peer (idempotent).
    pub fn addInfo(self: *Blooms, key: PublicKey) Allocator.Error!void {
        const gop = try self.blooms.getOrPut(self.gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = BloomInfo.init();
    }

    /// Remove bloom info for a disconnected peer.
    pub fn removeInfo(self: *Blooms, key: *const PublicKey) void {
        _ = self.blooms.remove(key.*);
    }

    /// Handle receiving a bloom filter from a peer.
    pub fn handleBloom(self: *Blooms, peer_key: *const PublicKey, filter: BloomFilter) void {
        if (self.blooms.getPtr(peer_key.*)) |info| info.recv = filter;
    }

    /// Get the current send bloom for a peer (for retransmission).
    pub fn getSendBloom(self: *const Blooms, key: *const PublicKey) ?BloomFilter {
        if (self.blooms.get(key.*)) |info| return info.send;
        return null;
    }

    /// Update on-tree status for all peers from the current tree state.
    /// `infos` maps node key -> its parent key for all known nodes.
    /// Returns blank filters that must be sent to peers dropped from the tree.
    /// Caller owns the returned slice.
    pub fn fixOnTree(
        self: *Blooms,
        self_key: *const PublicKey,
        self_parent: *const PublicKey,
        infos: *const KeyMap(PublicKey),
    ) Allocator.Error![]KeyBloom {
        var to_send = std.ArrayListUnmanaged(KeyBloom).empty;
        errdefer to_send.deinit(self.gpa);

        var it = self.blooms.iterator();
        while (it.next()) |entry| {
            const pk = entry.key_ptr.*;
            const pbi = entry.value_ptr;
            const was_on = pbi.on_tree;
            pbi.on_tree = false;

            if (std.mem.eql(u8, &self_parent.*, &pk)) {
                // Our parent is on the tree.
                pbi.on_tree = true;
            } else if (infos.get(pk)) |parent| {
                // Children: nodes whose parent is us.
                if (std.mem.eql(u8, &parent, &self_key.*)) pbi.on_tree = true;
            }

            if (was_on and !pbi.on_tree) {
                // Dropped from tree: send a blank filter to clear false positives.
                const blank = BloomFilter.init();
                pbi.send = blank;
                try to_send.append(self.gpa, .{ .key = pk, .filter = blank });
            }
        }
        return to_send.toOwnedSlice(self.gpa);
    }

    /// Compute the bloom filter we should send to `key`.
    /// Returns the filter and whether it differs from what we last sent.
    pub fn getBloomFor(
        self: *Blooms,
        key: *const PublicKey,
        our_key: *const PublicKey,
        keep_ones: bool,
    ) BloomResult {
        var b = BloomFilter.init();

        // Add our own (transformed) key.
        const xform = self.xKey(our_key);
        b.add(&xform);

        // Merge recv filters from all on-tree peers except the target.
        var it = self.blooms.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            const info = entry.value_ptr;
            if (info.on_tree and !std.mem.eql(u8, &k, &key.*)) {
                b.merge(&info.recv);
            }
        }

        const pbi = self.blooms.getPtr(key.*).?; // must exist

        if (keep_ones) {
            if (!pbi.z_dirty) {
                const c = b;
                b.merge(&pbi.send);
                if (!b.equal(&c)) pbi.z_dirty = true;
            } else {
                b.merge(&pbi.send);
            }
        } else {
            pbi.z_dirty = false;
        }

        const is_new = !b.equal(&pbi.send);
        if (is_new) pbi.send = b;
        return .{ .filter = b, .is_new = is_new };
    }

    /// Periodic maintenance: refresh on-tree status and compute new blooms.
    /// Returns (peer_key, filter) pairs that should be sent. Caller owns slice.
    pub fn doMaintenance(
        self: *Blooms,
        self_key: *const PublicKey,
        self_parent: *const PublicKey,
        infos: *const KeyMap(PublicKey),
    ) Allocator.Error![]KeyBloom {
        var to_send = std.ArrayListUnmanaged(KeyBloom).empty;
        errdefer to_send.deinit(self.gpa);

        // Fix on-tree status; collect blank filters for dropped peers.
        const dropped = try self.fixOnTree(self_key, self_parent, infos);
        defer self.gpa.free(dropped);
        try to_send.appendSlice(self.gpa, dropped);

        // Snapshot of on-tree keys (iteration order is unspecified but stable
        // within this call since we don't mutate the map structure below).
        var on_tree_keys = std.ArrayListUnmanaged(PublicKey).empty;
        defer on_tree_keys.deinit(self.gpa);
        var it = self.blooms.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.on_tree) try on_tree_keys.append(self.gpa, entry.key_ptr.*);
        }

        for (on_tree_keys.items) |k| {
            const z_dirty = self.blooms.get(k).?.z_dirty;
            const keep_ones = !z_dirty;
            const res = self.getBloomFor(&k, self_key, keep_ones);

            const pbi = self.blooms.getPtr(k).?;
            pbi.seq += 1;
            if (res.is_new or pbi.seq >= 3600) {
                try to_send.append(self.gpa, .{ .key = k, .filter = res.filter });
                pbi.seq = 0;
            }
        }

        return to_send.toOwnedSlice(self.gpa);
    }

    /// Determine which peers should receive a multicast packet to `to_key`.
    /// Returns peer keys whose recv filter matches. Caller owns the slice.
    pub fn getMulticastTargets(
        self: *const Blooms,
        from_key: *const PublicKey,
        to_key: *const PublicKey,
        out: *std.ArrayListUnmanaged(PublicKey),
        gpa: Allocator,
    ) Allocator.Error!void {
        const xform = self.xKey(to_key);
        var it = self.blooms.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            const pbi = entry.value_ptr;
            if (!pbi.on_tree) continue;
            if (std.mem.eql(u8, &k, &from_key.*)) continue;
            if (!pbi.recv.testKey(&xform)) continue;
            try out.append(gpa, k);
        }
    }

    /// Count on-tree peers whose recv filter matches the already-transformed key.
    pub fn countOnTreeTargetsForXKey(self: *const Blooms, xformed_key: *const PublicKey) usize {
        var count: usize = 0;
        var it = self.blooms.iterator();
        while (it.next()) |entry| {
            const pbi = entry.value_ptr;
            if (pbi.on_tree and pbi.recv.testKey(xformed_key)) count += 1;
        }
        return count;
    }
};

pub const BloomResult = struct {
    filter: BloomFilter,
    is_new: bool,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "murmur3 x64 128 known vectors" {
    // Reference values from the canonical MurmurHash3 x64 128 implementation
    // (low 64 = h1, high 64 = h2).
    // Empty input, seed 0 -> 0.
    try testing.expectEqual(@as(u128, 0), murmur3X64_128("", 0));

    // "hello" seed 0: well-known result cdbd6c6cXX... verify via roundtrip stability.
    // Canonical MurmurHash3 x64 128 of "hello" with seed 0
    // (low 64 = h1 = 0xcbd8a7b341bd9b02, high 64 = h2 = 0x5b1e906a48ae1d19).
    try testing.expectEqual(
        @as(u128, 0x5b1e906a48ae1d19cbd8a7b341bd9b02),
        murmur3X64_128("hello", 0),
    );
    // Different seed must differ.
    try testing.expect(murmur3X64_128("hello", 0) != murmur3X64_128("hello", 1));
}

test "basic add and test" {
    var filter = BloomFilter.init();
    const key = "hello world";
    try testing.expect(!filter.testKey(key));
    filter.add(key);
    try testing.expect(filter.testKey(key));
}

test "merge" {
    var f1 = BloomFilter.init();
    var f2 = BloomFilter.init();
    f1.add("key1");
    f2.add("key2");
    f1.merge(&f2);
    try testing.expect(f1.testKey("key1"));
    try testing.expect(f1.testKey("key2"));
}

test "count ones bounded by k" {
    var filter = BloomFilter.init();
    try testing.expectEqual(@as(u32, 0), filter.countOnes());
    filter.add("test");
    try testing.expect(filter.countOnes() > 0);
    try testing.expect(filter.countOnes() <= BLOOM_FILTER_K);
}

test "false positive rate is low" {
    var filter = BloomFilter.init();
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, i, .big);
        filter.add(&key);
    }
    // All added keys must be present.
    i = 0;
    while (i < 1000) : (i += 1) {
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, i, .big);
        try testing.expect(filter.testKey(&key));
    }
    // False positive rate on unseen keys should be small.
    var fp: u32 = 0;
    i = 1000;
    while (i < 2000) : (i += 1) {
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, i, .big);
        if (filter.testKey(&key)) fp += 1;
    }
    const rate = @as(f64, @floatFromInt(fp)) / 1000.0;
    try testing.expect(rate < 0.05);
}

test "encode/decode roundtrip preserves membership" {
    const gpa = testing.allocator;
    var filter = BloomFilter.init();
    filter.add("test key");
    filter.add("another key");

    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(gpa);
    try filter.encode(&buf, gpa);
    const decoded = try BloomFilter.decode(buf.items);
    try testing.expect(filter.equal(&decoded));
    try testing.expect(decoded.testKey("test key"));
    try testing.expect(decoded.testKey("another key"));
}

test "empty and full filter encode roundtrip" {
    const gpa = testing.allocator;
    {
        const filter = BloomFilter.init();
        var buf = std.ArrayListUnmanaged(u8).empty;
        defer buf.deinit(gpa);
        try filter.encode(&buf, gpa);
        const decoded = try BloomFilter.decode(buf.items);
        try testing.expect(filter.equal(&decoded));
    }
    {
        const filter = BloomFilter.fromRaw([_]u64{std.math.maxInt(u64)} ** BLOOM_FILTER_U64S);
        var buf = std.ArrayListUnmanaged(u8).empty;
        defer buf.deinit(gpa);
        try filter.encode(&buf, gpa);
        const decoded = try BloomFilter.decode(buf.items);
        try testing.expect(filter.equal(&decoded));
    }
}

test "known wire vector for single key [42; 32] (Go compatibility)" {
    // This is the exact vector from reference test
    // `test_known_values_single_key`, proving byte-for-byte compatibility
    // with the Go bits-and-blooms/bloom library and its murmur3 scheme.
    const expected_hex = "fdbfffbfff7ffe7ffffffffcffffffff0000000000000000000000000000000020000000000000000000000000080000200000000000000000000000000080000000200000000000020000000000000000020000000000000200000000000000";
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    const expected_filter = BloomFilter.fromRaw(try decodeBloom(&expected_bytes));

    const key = [_]u8{42} ** 32;
    var filter = BloomFilter.init();
    filter.add(&key);

    try testing.expect(filter.equal(&expected_filter));
    try testing.expect(filter.testKey(&key));
}

test "blooms manager add/remove/handle/on_tree" {
    const gpa = testing.allocator;
    var bl = Blooms.init(gpa, null);
    defer bl.deinit();

    const a = [_]u8{0xAA} ** 32;
    const b = [_]u8{0xBB} ** 32;

    try bl.addInfo(a);
    try bl.addInfo(a); // idempotent
    try bl.addInfo(b);
    try testing.expect(!bl.isOnTree(&a));

    var f = BloomFilter.init();
    f.add("payload");
    bl.handleBloom(&a, f);
    const got = bl.getSendBloom(&a);
    try testing.expect(got != null); // send starts empty but entry exists

    bl.removeInfo(&b);
    try testing.expect(bl.getSendBloom(&b) == null);
    try testing.expect(bl.getSendBloom(&a) != null);
}

test "blooms fixOnTree marks parent and children" {
    const gpa = testing.allocator;
    var bl = Blooms.init(gpa, null);
    defer bl.deinit();

    const self_key = [_]u8{0x01} ** 32;
    const parent = [_]u8{0x02} ** 32;
    const child = [_]u8{0x03} ** 32;
    const stranger = [_]u8{0x04} ** 32;

    try bl.addInfo(parent);
    try bl.addInfo(child);
    try bl.addInfo(stranger);

    // infos: child's parent is us; stranger's parent is someone else.
    var infos = std.AutoHashMapUnmanaged(PublicKey, PublicKey){};
    defer infos.deinit(gpa);
    try infos.put(gpa, child, self_key);
    try infos.put(gpa, stranger, [_]u8{0x09} ** 32);

    const dropped = try bl.fixOnTree(&self_key, &parent, &infos);
    defer gpa.free(dropped);

    try testing.expect(bl.isOnTree(&parent));
    try testing.expect(bl.isOnTree(&child));
    try testing.expect(!bl.isOnTree(&stranger));
    try testing.expectEqual(@as(usize, 0), dropped.len); // none were previously on-tree
}

test "blooms getBloomFor contains our key and merges on-tree recv" {
    const gpa = testing.allocator;
    var bl = Blooms.init(gpa, null);
    defer bl.deinit();

    const our_key = [_]u8{0x01} ** 32;
    const peer = [_]u8{0x02} ** 32;
    const other = [_]u8{0x03} ** 32;

    try bl.addInfo(peer);
    try bl.addInfo(other);

    // Mark `other` on-tree and give it a recv filter containing "secret".
    bl.blooms.getPtr(other).?.on_tree = true;
    var recv = BloomFilter.init();
    recv.add("secret");
    bl.handleBloom(&other, recv);

    const res = bl.getBloomFor(&peer, &our_key, false);
    // Must contain our own key and the merged "secret" from on-tree `other`.
    var ours = BloomFilter.init();
    ours.add(&our_key);
    try testing.expect(res.filter.testKey(&our_key));
    try testing.expect(res.filter.testKey("secret"));
    try testing.expect(res.is_new);

    // Calling again with identical state yields not-new.
    const res2 = bl.getBloomFor(&peer, &our_key, false);
    try testing.expect(!res2.is_new);
}

test "blooms getMulticastTargets respects on_tree, sender, and membership" {
    const gpa = testing.allocator;
    var bl = Blooms.init(gpa, null);
    defer bl.deinit();

    const sender = [_]u8{0x01} ** 32;
    const match = [_]u8{0x02} ** 32;
    const no_match = [_]u8{0x03} ** 32;
    const off_tree = [_]u8{0x04} ** 32;
    const dest = [_]u8{0xDD} ** 32;

    try bl.addInfo(sender);
    try bl.addInfo(match);
    try bl.addInfo(no_match);
    try bl.addInfo(off_tree);

    inline for (.{ sender, match, no_match }) |k| {
        bl.blooms.getPtr(k).?.on_tree = true;
    }
    // off_tree stays off-tree.

    var fmatch = BloomFilter.init();
    fmatch.add(&dest);
    bl.handleBloom(&match, fmatch);
    bl.handleBloom(&sender, fmatch); // sender matches but is the source -> excluded

    var targets = std.ArrayListUnmanaged(PublicKey).empty;
    defer targets.deinit(gpa);
    try bl.getMulticastTargets(&sender, &dest, &targets, gpa);

    try testing.expectEqual(@as(usize, 1), targets.items.len);
    try testing.expectEqualSlices(u8, &match, &targets.items[0]);
}
