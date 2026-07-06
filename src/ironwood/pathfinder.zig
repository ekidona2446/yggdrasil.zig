//! Path discovery state machine.
//!
//! Handles PathLookup / PathNotify / PathBroken. Maintains a cache of known
//! paths to destinations with timeouts and throttles lookups to avoid flooding.
//! Used from within the router — not independently thread-safe.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cryptomod = @import("crypto.zig");
const Crypto = cryptomod.Crypto;
const PublicKey = cryptomod.PublicKey;
const Sig = cryptomod.Sig;
const wire = @import("wire.zig");
const PeerPort = wire.PeerPort;
const traffic = @import("traffic.zig");
const TrafficPacket = traffic.TrafficPacket;
const timemod = @import("util").time;
const Instant = timemod.Instant;

const KeyMap = std.AutoHashMapUnmanaged;

// ---------------------------------------------------------------------------
// PathInfo: cached path to a destination
// ---------------------------------------------------------------------------

pub const PathInfo = struct {
    /// Tree coordinates to destination (not zero-terminated). Owned.
    path: []PeerPort,
    seq: u64,
    /// When we last sent a lookup request.
    req_time: Instant,
    /// When this entry was last refreshed.
    last_refresh: Instant,
    /// Cached traffic packet waiting for a path. Owned when present.
    cached_traffic: ?TrafficPacket,
    /// Path broken flag (must get a new notify to clear).
    broken: bool,

    fn deinit(self: *PathInfo, gpa: Allocator) void {
        if (self.path.len != 0) gpa.free(self.path);
        self.path = &.{};
        if (self.cached_traffic) |*t| t.deinit(gpa);
        self.cached_traffic = null;
    }
};

// ---------------------------------------------------------------------------
// PathRumor: pending lookup for an unknown destination
// ---------------------------------------------------------------------------

pub const PathRumor = struct {
    /// Cached traffic packet. Owned when present.
    traffic: ?TrafficPacket,
    /// When we last sent a lookup (null = never sent).
    send_time: ?Instant,
    /// When this rumor was created (expiry fallback if never sent).
    created: Instant,

    fn deinit(self: *PathRumor, gpa: Allocator) void {
        if (self.traffic) |*t| t.deinit(gpa);
        self.traffic = null;
    }
};

// ---------------------------------------------------------------------------
// OwnPathInfo: our own signed path info advertised to lookup requesters
// ---------------------------------------------------------------------------

pub const OwnPathInfo = struct {
    seq: u64 = 0,
    path: []PeerPort = &.{},
    sig: Sig = [_]u8{0} ** 64,

    pub fn deinit(self: *OwnPathInfo, gpa: Allocator) void {
        if (self.path.len != 0) gpa.free(self.path);
        self.path = &.{};
    }

    /// Compute the bytes that are signed: uvarint(seq) || encode_path(path).
    /// Caller owns the returned buffer.
    pub fn bytesForSig(self: *const OwnPathInfo, gpa: Allocator) Allocator.Error![]u8 {
        var out = std.ArrayListUnmanaged(u8).empty;
        errdefer out.deinit(gpa);
        try wire.encodeUvarint(&out, gpa, self.seq);
        try wire.encodePath(&out, gpa, self.path);
        return out.toOwnedSlice(gpa);
    }

    /// Sign the current contents with our private key.
    pub fn sign(self: *OwnPathInfo, gpa: Allocator, crypto: *const Crypto) Allocator.Error!void {
        const bytes = try self.bytesForSig(gpa);
        defer gpa.free(bytes);
        self.sig = crypto.sign(bytes);
    }

    /// Equality ignoring the signature.
    pub fn contentEqual(self: *const OwnPathInfo, other: *const OwnPathInfo) bool {
        return self.seq == other.seq and std.mem.eql(PeerPort, self.path, other.path);
    }
};

// ---------------------------------------------------------------------------
// Pathfinder
// ---------------------------------------------------------------------------

pub const AcceptResult = struct {
    accepted: bool,
    /// Cached traffic to re-send (ownership transferred to caller), if any.
    traffic: ?TrafficPacket,
};

pub const Pathfinder = struct {
    info: OwnPathInfo,
    paths: KeyMap(PublicKey, PathInfo) = .{},
    rumors: KeyMap(PublicKey, PathRumor) = .{},
    gpa: Allocator,

    pub fn init(gpa: Allocator, crypto: *const Crypto) Allocator.Error!Pathfinder {
        var info = OwnPathInfo{};
        try info.sign(gpa, crypto);
        return .{ .info = info, .gpa = gpa };
    }

    pub fn deinit(self: *Pathfinder) void {
        self.info.deinit(self.gpa);
        var pit = self.paths.valueIterator();
        while (pit.next()) |p| p.deinit(self.gpa);
        self.paths.deinit(self.gpa);
        var rit = self.rumors.valueIterator();
        while (rit.next()) |r| r.deinit(self.gpa);
        self.rumors.deinit(self.gpa);
    }

    /// Should we throttle a lookup to this destination?
    pub fn shouldThrottleLookup(self: *const Pathfinder, dest: *const PublicKey, throttle_ns: u64) bool {
        if (self.paths.getPtr(dest.*)) |info| return info.req_time.elapsedNanos() < throttle_ns;
        return false;
    }

    pub fn markLookupSent(self: *Pathfinder, dest: *const PublicKey) void {
        if (self.paths.getPtr(dest.*)) |info| info.req_time = Instant.now();
    }

    /// Should a rumor lookup be throttled? False if never sent.
    pub fn shouldThrottleRumor(self: *const Pathfinder, xformed_dest: *const PublicKey, throttle_ns: u64) bool {
        if (self.rumors.getPtr(xformed_dest.*)) |rumor| {
            if (rumor.send_time) |t| return t.elapsedNanos() < throttle_ns;
            return false;
        }
        return false;
    }

    /// Get or create a rumor. Returns true if it was just created.
    pub fn ensureRumor(self: *Pathfinder, xformed_dest: PublicKey) Allocator.Error!bool {
        if (self.rumors.contains(xformed_dest)) return false;
        try self.rumors.put(self.gpa, xformed_dest, .{
            .traffic = null,
            .send_time = null,
            .created = Instant.now(),
        });
        return true;
    }

    pub fn markRumorSent(self: *Pathfinder, xformed_dest: *const PublicKey) void {
        if (self.rumors.getPtr(xformed_dest.*)) |rumor| rumor.send_time = Instant.now();
    }

    /// Cache a traffic packet in a rumor. Takes ownership; frees any previous.
    pub fn cacheRumorTraffic(self: *Pathfinder, xformed_dest: *const PublicKey, tr: TrafficPacket) void {
        if (self.rumors.getPtr(xformed_dest.*)) |rumor| {
            if (rumor.traffic) |*old| old.deinit(self.gpa);
            rumor.traffic = tr;
        } else {
            // No rumor to hold it: drop the packet to avoid a leak.
            var t = tr;
            t.deinit(self.gpa);
        }
    }

    /// Process a path notification response.
    ///
    /// Takes ownership of `notify_path` (stored or freed). On accept, may return
    /// a cached traffic packet (ownership transferred to caller).
    pub fn acceptNotify(
        self: *Pathfinder,
        source: PublicKey,
        xformed_source: PublicKey,
        notify_seq: u64,
        notify_path: []PeerPort,
    ) Allocator.Error!AcceptResult {
        if (self.paths.getPtr(source)) |info| {
            if (notify_seq <= info.seq) {
                self.gpa.free(notify_path);
                return .{ .accepted = false, .traffic = null };
            }
            // Storm prevention: working path with unchanged coords -> ignore.
            if (!info.broken and std.mem.eql(PeerPort, info.path, notify_path)) {
                self.gpa.free(notify_path);
                return .{ .accepted = false, .traffic = null };
            }
            if (info.path.len != 0) self.gpa.free(info.path);
            info.path = notify_path;
            info.seq = notify_seq;
            info.broken = false;
            info.last_refresh = Instant.now();
            const cached = info.cached_traffic;
            info.cached_traffic = null;
            return .{ .accepted = true, .traffic = cached };
        }

        // New path — requires an existing rumor for the transformed key.
        if (!self.rumors.contains(xformed_source)) {
            self.gpa.free(notify_path);
            return .{ .accepted = false, .traffic = null };
        }

        // Take a cached rumor packet only if it's destined for `source`.
        var out_traffic: ?TrafficPacket = null;
        if (self.rumors.getPtr(xformed_source)) |rumor| {
            if (rumor.traffic) |t| {
                if (std.mem.eql(u8, &t.dest, &source)) {
                    out_traffic = rumor.traffic;
                    rumor.traffic = null;
                }
            }
        }

        try self.paths.put(self.gpa, source, .{
            .path = notify_path,
            .seq = notify_seq,
            .req_time = Instant.now(),
            .last_refresh = Instant.now(),
            .cached_traffic = null,
            .broken = false,
        });

        return .{ .accepted = true, .traffic = out_traffic };
    }

    pub fn handleBroken(self: *Pathfinder, dest: *const PublicKey) void {
        if (self.paths.getPtr(dest.*)) |info| info.broken = true;
    }

    /// Reset timeout for a destination (on receiving traffic from them).
    pub fn resetTimeout(self: *Pathfinder, key: *const PublicKey) void {
        if (self.paths.getPtr(key.*)) |info| {
            if (!info.broken) info.last_refresh = Instant.now();
        }
    }

    /// Cached path for a destination (null if unknown or broken).
    pub fn getPath(self: *const Pathfinder, dest: *const PublicKey) ?[]const PeerPort {
        if (self.paths.getPtr(dest.*)) |info| {
            if (!info.broken) return info.path;
        }
        return null;
    }

    /// True if the path-notify cache slot for `dest` is empty.
    pub fn needsTrafficCache(self: *const Pathfinder, dest: *const PublicKey) bool {
        if (self.paths.getPtr(dest.*)) |info| return info.cached_traffic == null;
        return false;
    }

    /// Cache a traffic packet for a destination. Takes ownership.
    pub fn cacheTraffic(self: *Pathfinder, dest: *const PublicKey, tr: TrafficPacket) void {
        if (self.paths.getPtr(dest.*)) |info| {
            if (info.cached_traffic) |*old| old.deinit(self.gpa);
            info.cached_traffic = tr;
        } else {
            var t = tr;
            t.deinit(self.gpa);
        }
    }

    /// Clean up expired paths and rumors.
    pub fn cleanupExpired(self: *Pathfinder, path_timeout_ns: u64) void {
        // Paths: drop those not refreshed within the timeout.
        {
            var to_remove = std.ArrayListUnmanaged(PublicKey).empty;
            defer to_remove.deinit(self.gpa);
            var it = self.paths.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.last_refresh.elapsedNanos() >= path_timeout_ns) {
                    to_remove.append(self.gpa, entry.key_ptr.*) catch {};
                }
            }
            for (to_remove.items) |k| {
                if (self.paths.fetchRemove(k)) |kv| {
                    var v = kv.value;
                    v.deinit(self.gpa);
                }
            }
        }
        // Rumors: expiry from send_time if set, else created.
        {
            var to_remove = std.ArrayListUnmanaged(PublicKey).empty;
            defer to_remove.deinit(self.gpa);
            var it = self.rumors.iterator();
            while (it.next()) |entry| {
                const base = entry.value_ptr.send_time orelse entry.value_ptr.created;
                if (base.elapsedNanos() >= path_timeout_ns) {
                    to_remove.append(self.gpa, entry.key_ptr.*) catch {};
                }
            }
            for (to_remove.items) |k| {
                if (self.rumors.fetchRemove(k)) |kv| {
                    var v = kv.value;
                    v.deinit(self.gpa);
                }
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeCrypto() Crypto {
    return Crypto.generate();
}

test "pathfinder new signs own info" {
    const gpa = testing.allocator;
    const crypto = makeCrypto();
    var pf = try Pathfinder.init(gpa, &crypto);
    defer pf.deinit();
    try testing.expectEqual(@as(u64, 0), pf.info.seq);
    try testing.expectEqual(@as(usize, 0), pf.info.path.len);
}

test "own path info sign and verify" {
    const gpa = testing.allocator;
    const crypto = makeCrypto();
    var info = OwnPathInfo{ .seq = 7, .path = try gpa.dupe(PeerPort, &[_]PeerPort{ 1, 2, 3 }) };
    defer info.deinit(gpa);
    try info.sign(gpa, &crypto);

    const bytes = try info.bytesForSig(gpa);
    defer gpa.free(bytes);
    try testing.expect(Crypto.verify(&crypto.public_key, bytes, &info.sig));
}

test "throttle lookup based on req_time" {
    const gpa = testing.allocator;
    const crypto = makeCrypto();
    var pf = try Pathfinder.init(gpa, &crypto);
    defer pf.deinit();

    const dest = [_]u8{0xAB} ** 32;
    // No path yet -> not throttled.
    try testing.expect(!pf.shouldThrottleLookup(&dest, std.time.ns_per_s));

    // Insert a path; req_time just set -> throttled within a 1s window.
    try pf.paths.put(gpa, dest, .{
        .path = try gpa.dupe(PeerPort, &[_]PeerPort{1}),
        .seq = 1,
        .req_time = Instant.now(),
        .last_refresh = Instant.now(),
        .cached_traffic = null,
        .broken = false,
    });
    try testing.expect(pf.shouldThrottleLookup(&dest, std.time.ns_per_s));
}

test "accept_notify creates new path when rumor exists" {
    const gpa = testing.allocator;
    const crypto = makeCrypto();
    var pf = try Pathfinder.init(gpa, &crypto);
    defer pf.deinit();

    const source = [_]u8{0x11} ** 32;
    const xformed = source; // identity transform in this test

    // Without a rumor, a new path is rejected (path freed internally).
    const r0 = try pf.acceptNotify(source, xformed, 1, try gpa.dupe(PeerPort, &[_]PeerPort{ 1, 2 }));
    try testing.expect(!r0.accepted);
    try testing.expect(r0.traffic == null);

    // Create a rumor, then accept.
    _ = try pf.ensureRumor(xformed);
    const r1 = try pf.acceptNotify(source, xformed, 1, try gpa.dupe(PeerPort, &[_]PeerPort{ 1, 2 }));
    try testing.expect(r1.accepted);
    try testing.expect(r1.traffic == null);

    // Path now retrievable.
    const path = pf.getPath(&source).?;
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 1, 2 }, path);

    // Lower/equal seq is rejected.
    const r2 = try pf.acceptNotify(source, xformed, 1, try gpa.dupe(PeerPort, &[_]PeerPort{3}));
    try testing.expect(!r2.accepted);

    // Higher seq with different coords accepted.
    const r3 = try pf.acceptNotify(source, xformed, 2, try gpa.dupe(PeerPort, &[_]PeerPort{ 9, 9 }));
    try testing.expect(r3.accepted);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 9, 9 }, pf.getPath(&source).?);
}

test "handle_broken marks path and hides it" {
    const gpa = testing.allocator;
    const crypto = makeCrypto();
    var pf = try Pathfinder.init(gpa, &crypto);
    defer pf.deinit();

    const source = [_]u8{0x22} ** 32;
    _ = try pf.ensureRumor(source);
    _ = try pf.acceptNotify(source, source, 1, try gpa.dupe(PeerPort, &[_]PeerPort{5}));
    try testing.expect(pf.getPath(&source) != null);

    pf.handleBroken(&source);
    try testing.expect(pf.getPath(&source) == null); // broken hidden

    // A broken path accepts same coords with higher seq (un-breaks).
    const r = try pf.acceptNotify(source, source, 2, try gpa.dupe(PeerPort, &[_]PeerPort{5}));
    try testing.expect(r.accepted);
    try testing.expect(pf.getPath(&source) != null);
}

test "cache and take rumor traffic on accept" {
    const gpa = testing.allocator;
    const crypto = makeCrypto();
    var pf = try Pathfinder.init(gpa, &crypto);
    defer pf.deinit();

    const source = [_]u8{0x33} ** 32;
    _ = try pf.ensureRumor(source);

    // Cache a packet destined for source in the rumor.
    const pkt = TrafficPacket.init([_]u8{0xAA} ** 32, source, try gpa.dupe(u8, "payload"));
    pf.cacheRumorTraffic(&source, pkt);

    // Accepting the notify should hand the cached packet back.
    const r = try pf.acceptNotify(source, source, 1, try gpa.dupe(PeerPort, &[_]PeerPort{1}));
    try testing.expect(r.accepted);
    try testing.expect(r.traffic != null);
    var t = r.traffic.?;
    defer t.deinit(gpa);
    try testing.expectEqualSlices(u8, "payload", t.payload);
}
