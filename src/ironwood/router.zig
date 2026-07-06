//! The spanning tree CRDT router.
//!
//! Maintains tree state, handles announcements, performs greedy routing, and
//! coordinates bloom filters and path discovery. The router is a pure state
//! machine: methods take inputs and return a list of `RouterAction`s for the
//! networking layer to execute. It performs no I/O itself.
//!
//! Ownership: methods that return `[]RouterAction` transfer ownership of the
//! slice (and any owned payloads inside actions) to the caller, who must call
//! `deinitActions`. Inputs that own heap memory (e.g. `TrafficPacket`) are
//! consumed unless documented otherwise.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cryptomod = @import("crypto.zig");
const Crypto = cryptomod.Crypto;
const PublicKey = cryptomod.PublicKey;
const Sig = cryptomod.Sig;
const wire = @import("wire.zig");
const PeerPort = wire.PeerPort;
const bloommod = @import("bloom.zig");
const Blooms = bloommod.Blooms;
const BloomFilter = bloommod.BloomFilter;
const config = @import("config.zig");
const traffic = @import("traffic.zig");
const TrafficPacket = traffic.TrafficPacket;
const pathfinder = @import("pathfinder.zig");
const Pathfinder = pathfinder.Pathfinder;
const OwnPathInfo = pathfinder.OwnPathInfo;
const timemod = @import("util").time;
const Instant = timemod.Instant;

const KeyMap = std.AutoHashMapUnmanaged;

/// Latency assumed for a peer whose RTT we haven't measured yet (5 s in ns).
const UNKNOWN_LATENCY_NS: u64 = 5 * std.time.ns_per_s;

/// Unique identifier for a peer connection.
pub const PeerId = u64;

// ---------------------------------------------------------------------------
// Router-level types
// ---------------------------------------------------------------------------

/// Stored tree state for a known node.
pub const RouterInfo = struct {
    parent: PublicKey,
    seq: u64,
    nonce: u64,
    port: PeerPort,
    psig: Sig,
    sig: Sig,

    pub fn eql(a: *const RouterInfo, b: *const RouterInfo) bool {
        return std.mem.eql(u8, &a.parent, &b.parent) and a.seq == b.seq and
            a.nonce == b.nonce and a.port == b.port and
            std.mem.eql(u8, &a.psig, &b.psig) and std.mem.eql(u8, &a.sig, &b.sig);
    }

    /// Reconstruct an announcement from stored info.
    pub fn getAnnounce(self: *const RouterInfo, key: PublicKey) RouterAnnounce {
        return .{
            .key = key,
            .parent = self.parent,
            .seq = self.seq,
            .nonce = self.nonce,
            .port = self.port,
            .psig = self.psig,
            .sig = self.sig,
        };
    }
};

/// A tree announcement message (internal representation).
pub const RouterAnnounce = struct {
    key: PublicKey,
    parent: PublicKey,
    seq: u64,
    nonce: u64,
    port: PeerPort,
    psig: Sig,
    sig: Sig,

    /// Bytes for the signature: key || parent || uvarint(seq,nonce,port).
    /// Caller owns the returned buffer.
    pub fn bytesForSig(self: *const RouterAnnounce, gpa: Allocator) Allocator.Error![]u8 {
        var out = std.ArrayListUnmanaged(u8).empty;
        errdefer out.deinit(gpa);
        try out.appendSlice(gpa, &self.key);
        try out.appendSlice(gpa, &self.parent);
        try wire.encodeUvarint(&out, gpa, self.seq);
        try wire.encodeUvarint(&out, gpa, self.nonce);
        try wire.encodeUvarint(&out, gpa, self.port);
        return out.toOwnedSlice(gpa);
    }

    /// Verify both signatures (node's and parent's) over the announcement.
    pub fn check(self: *const RouterAnnounce, gpa: Allocator) bool {
        if (self.port == 0 and !std.mem.eql(u8, &self.key, &self.parent)) return false;
        const bs = self.bytesForSig(gpa) catch return false;
        defer gpa.free(bs);
        return Crypto.verify(&self.key, bs, &self.sig) and
            Crypto.verify(&self.parent, bs, &self.psig);
    }

    pub fn toWire(self: *const RouterAnnounce) wire.Announce {
        return .{
            .key = self.key,
            .parent = self.parent,
            .sig_res = .{ .seq = self.seq, .nonce = self.nonce, .port = self.port, .psig = self.psig },
            .sig = self.sig,
        };
    }

    pub fn fromWire(ann: *const wire.Announce) RouterAnnounce {
        return .{
            .key = ann.key,
            .parent = ann.parent,
            .seq = ann.sig_res.seq,
            .nonce = ann.sig_res.nonce,
            .port = ann.sig_res.port,
            .psig = ann.sig_res.psig,
            .sig = ann.sig,
        };
    }
};

/// Minimal peer info needed by the router for routing decisions.
pub const PeerEntry = struct {
    id: PeerId,
    key: PublicKey,
    port: PeerPort,
    prio: u8,
    order: u64,
};

const SigReqState = struct {
    seq: u64,
    nonce: u64,
};

const SigResState = struct {
    seq: u64,
    nonce: u64,
    port: PeerPort,
    psig: Sig,
};

// ---------------------------------------------------------------------------
// RouterAction: outbound work for the networking layer
// ---------------------------------------------------------------------------

pub const RouterAction = union(enum) {
    send_sig_req: struct { peer_id: PeerId, req: wire.SigReq },
    send_sig_res: struct { peer_id: PeerId, res: wire.SigRes },
    send_announce: struct { peer_id: PeerId, ann: wire.Announce },
    send_bloom: struct { peer_id: PeerId, bloom: BloomFilter },
    send_traffic: struct { peer_id: PeerId, traffic: TrafficPacket },
    send_path_notify: struct { peer_id: PeerId, notify: wire.PathNotify },
    send_path_lookup: struct { peer_id: PeerId, lookup: wire.PathLookup },
    send_path_broken: struct { peer_id: PeerId, broken: wire.PathBroken },
    deliver_traffic: struct { traffic: TrafficPacket },
    path_notify_callback: struct { key: PublicKey },

    /// Free any heap memory owned by this action.
    pub fn deinit(self: *RouterAction, gpa: Allocator) void {
        switch (self.*) {
            .send_traffic => |*a| a.traffic.deinit(gpa),
            .deliver_traffic => |*a| a.traffic.deinit(gpa),
            .send_path_notify => |*a| a.notify.deinit(gpa),
            .send_path_lookup => |*a| a.lookup.deinit(gpa),
            .send_path_broken => |*a| a.broken.deinit(gpa),
            else => {},
        }
    }
};

/// A growable list of actions with ownership helpers.
pub const ActionList = struct {
    items: std.ArrayListUnmanaged(RouterAction) = .empty,
    gpa: Allocator,

    pub fn init(gpa: Allocator) ActionList {
        return .{ .gpa = gpa };
    }

    pub fn append(self: *ActionList, action: RouterAction) Allocator.Error!void {
        try self.items.append(self.gpa, action);
    }

    pub fn extend(self: *ActionList, other: []RouterAction) Allocator.Error!void {
        try self.items.appendSlice(self.gpa, other);
    }

    /// Transfer ownership of the action slice to the caller.
    pub fn toOwned(self: *ActionList) Allocator.Error![]RouterAction {
        return self.items.toOwnedSlice(self.gpa);
    }

    /// Free every action and the backing storage.
    pub fn deinit(self: *ActionList) void {
        for (self.items.items) |*a| a.deinit(self.gpa);
        self.items.deinit(self.gpa);
    }
};

/// Free a slice of actions returned by router methods.
pub fn deinitActions(gpa: Allocator, actions: []RouterAction) void {
    for (actions) |*a| a.deinit(gpa);
    gpa.free(actions);
}

// signature input shared by announce/sigres: node || parent || uvarint(seq,nonce,port)
fn sigBytes(gpa: Allocator, node: *const PublicKey, parent: *const PublicKey, seq: u64, nonce: u64, port: PeerPort) Allocator.Error![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, node);
    try out.appendSlice(gpa, parent);
    try wire.encodeUvarint(&out, gpa, seq);
    try wire.encodeUvarint(&out, gpa, nonce);
    try wire.encodeUvarint(&out, gpa, port);
    return out.toOwnedSlice(gpa);
}

fn randU64() u64 {
    var b: [8]u8 = undefined;
    cryptomod.secureRandomBytes(&b);
    return std.mem.readInt(u64, &b, .little);
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const PeerMap = KeyMap(PeerId, PeerEntry);
const KeySet = KeyMap(PublicKey, void);

pub const Router = struct {
    gpa: Allocator,
    crypto: Crypto,
    pathfinder: Pathfinder,
    blooms: Blooms,

    // Peer tracking.
    peers: KeyMap(PublicKey, PeerMap) = .{}, // key -> {id -> entry}
    sent: KeyMap(PublicKey, KeySet) = .{}, // key -> set of announced keys
    ports: KeyMap(PeerPort, PublicKey) = .{},

    // Tree state.
    infos: KeyMap(PublicKey, RouterInfo) = .{},
    info_times: KeyMap(PublicKey, Instant) = .{},
    ancs: KeyMap(PublicKey, []PublicKey) = .{},
    cache: KeyMap(PublicKey, []PeerPort) = .{},

    // Latency tracking.
    lags: KeyMap(PeerId, u64) = .{}, // nanoseconds
    sig_req_times: KeyMap(PeerId, Instant) = .{},

    // Signature protocol.
    requests: KeyMap(PublicKey, SigReqState) = .{},
    responses: KeyMap(PublicKey, SigResState) = .{},
    responded: KeyMap(PeerId, void) = .{},
    res_seqs: KeyMap(PublicKey, u64) = .{},
    res_seq_ctr: u64 = 0,

    // Flags / timers.
    refresh: bool = false,
    do_root1: bool = false,
    do_root2: bool = true,
    last_refresh: Instant,
    last_status_log: Instant,

    // Config.
    router_refresh_ns: u64,
    router_timeout_ns: u64,
    path_timeout_ns: u64,
    path_throttle_ns: u64,
    bloom_transform: ?config.BloomTransformFn,

    pub fn init(gpa: Allocator, crypto: Crypto, cfg: *const config.Config) Allocator.Error!Router {
        const pf = try Pathfinder.init(gpa, &crypto);
        return .{
            .gpa = gpa,
            .crypto = crypto,
            .pathfinder = pf,
            .blooms = Blooms.init(gpa, cfg.bloom_transform),
            .last_refresh = Instant.now(),
            .last_status_log = Instant.now(),
            .router_refresh_ns = cfg.router_refresh_ns,
            .router_timeout_ns = cfg.router_timeout_ns,
            .path_timeout_ns = cfg.path_timeout_ns,
            .path_throttle_ns = cfg.path_throttle_ns,
            .bloom_transform = cfg.bloom_transform,
        };
    }

    pub fn deinit(self: *Router) void {
        self.pathfinder.deinit();
        self.blooms.deinit();

        var pit = self.peers.valueIterator();
        while (pit.next()) |pm| pm.deinit(self.gpa);
        self.peers.deinit(self.gpa);

        var sit = self.sent.valueIterator();
        while (sit.next()) |s| s.deinit(self.gpa);
        self.sent.deinit(self.gpa);

        self.ports.deinit(self.gpa);
        self.infos.deinit(self.gpa);
        self.info_times.deinit(self.gpa);

        var ait = self.ancs.valueIterator();
        while (ait.next()) |a| self.gpa.free(a.*);
        self.ancs.deinit(self.gpa);

        var cit = self.cache.valueIterator();
        while (cit.next()) |c| self.gpa.free(c.*);
        self.cache.deinit(self.gpa);

        self.lags.deinit(self.gpa);
        self.sig_req_times.deinit(self.gpa);
        self.requests.deinit(self.gpa);
        self.responses.deinit(self.gpa);
        self.responded.deinit(self.gpa);
        self.res_seqs.deinit(self.gpa);
    }

    pub fn selfKey(self: *const Router) PublicKey {
        return self.crypto.public_key;
    }

    // -- cache management ----------------------------------------------------

    fn resetCache(self: *Router) void {
        var it = self.cache.valueIterator();
        while (it.next()) |c| self.gpa.free(c.*);
        self.cache.clearRetainingCapacity();
    }

    // -- ancestry ------------------------------------------------------------

    /// Backwards ancestry (key -> ... -> root). Caller owns the slice.
    fn backwardsAncestry(self: *const Router, key: *const PublicKey) Allocator.Error![]PublicKey {
        var anc = std.ArrayListUnmanaged(PublicKey).empty;
        errdefer anc.deinit(self.gpa);
        var here = key.*;
        while (true) {
            // loop guard: stop if `here` already present
            var dup = false;
            for (anc.items) |a| {
                if (std.mem.eql(u8, &a, &here)) {
                    dup = true;
                    break;
                }
            }
            if (dup) break;
            if (self.infos.getPtr(here)) |info| {
                try anc.append(self.gpa, here);
                here = info.parent;
            } else break;
        }
        return anc.toOwnedSlice(self.gpa);
    }

    /// Root-first ancestry (root -> ... -> key). Caller owns the slice.
    fn getAncestry(self: *const Router, key: *const PublicKey) Allocator.Error![]PublicKey {
        const anc = try self.backwardsAncestry(key);
        std.mem.reverse(PublicKey, anc);
        return anc;
    }

    fn updateAncestries(self: *Router) Allocator.Error!void {
        var keys = std.ArrayListUnmanaged(PublicKey).empty;
        defer keys.deinit(self.gpa);
        var kit = self.peers.keyIterator();
        while (kit.next()) |k| try keys.append(self.gpa, k.*);

        for (keys.items) |pkey| {
            const anc = try self.getAncestry(&pkey);
            const old = self.ancs.get(pkey);
            const diff = if (old) |o| !eqlKeySlices(o, anc) else true;
            if (diff) {
                if (self.ancs.fetchRemove(pkey)) |kv| self.gpa.free(kv.value);
                try self.ancs.put(self.gpa, pkey, anc);
            } else {
                self.gpa.free(anc);
            }
        }
    }

    // -- tree traversal ------------------------------------------------------

    pub const RootAndDists = struct { root: PublicKey, dists: KeyMap(PublicKey, u64) };

    /// Root and per-node distances from `dest` up the tree. Caller deinits dists.
    pub fn getRootAndDists(self: *const Router, dest: *const PublicKey) Allocator.Error!RootAndDists {
        var dists = KeyMap(PublicKey, u64){};
        errdefer dists.deinit(self.gpa);
        var next = dest.*;
        var root = [_]u8{0} ** 32;
        var dist: u64 = 0;
        while (true) {
            if (dists.contains(next)) break;
            if (self.infos.getPtr(next)) |info| {
                root = next;
                try dists.put(self.gpa, next, dist);
                dist += 1;
                next = info.parent;
            } else break;
        }
        return .{ .root = root, .dists = dists };
    }

    pub const RootAndPath = struct { root: PublicKey, path: []PeerPort };

    /// Root and coordinates (ports root->dest). Caller owns path.
    pub fn getRootAndPath(self: *const Router, dest: *const PublicKey) Allocator.Error!RootAndPath {
        var ports = std.ArrayListUnmanaged(PeerPort).empty;
        errdefer ports.deinit(self.gpa);
        var visited = KeySet{};
        defer visited.deinit(self.gpa);
        var root = dest.*;
        var next = dest.*;
        while (true) {
            if (visited.contains(next)) {
                ports.clearRetainingCapacity();
                return .{ .root = dest.*, .path = try ports.toOwnedSlice(self.gpa) };
            }
            if (self.infos.getPtr(next)) |info| {
                root = next;
                try visited.put(self.gpa, next, {});
                if (std.mem.eql(u8, &next, &info.parent)) break; // reached root
                try ports.append(self.gpa, info.port);
                next = info.parent;
            } else {
                ports.clearRetainingCapacity();
                return .{ .root = dest.*, .path = try ports.toOwnedSlice(self.gpa) };
            }
        }
        const slice = try ports.toOwnedSlice(self.gpa);
        std.mem.reverse(PeerPort, slice);
        return .{ .root = root, .path = slice };
    }

    /// Cached coordinates for a key (computes and caches if absent).
    /// Returns a borrowed slice valid until the next resetCache.
    fn cachedCoords(self: *Router, key: *const PublicKey) Allocator.Error![]const PeerPort {
        if (self.cache.get(key.*)) |cached| return cached;
        const rp = try self.getRootAndPath(key);
        try self.cache.put(self.gpa, key.*, rp.path);
        return rp.path;
    }

    /// Tree-space distance between a path and a key's coordinates.
    fn getDist(self: *Router, dest_path: []const PeerPort, key: *const PublicKey) Allocator.Error!u64 {
        const key_path = try self.cachedCoords(key);
        const end = @min(dest_path.len, key_path.len);
        var dist: u64 = @intCast(key_path.len + dest_path.len);
        var idx: usize = 0;
        while (idx < end) : (idx += 1) {
            if (key_path[idx] == dest_path[idx]) {
                dist -= 2;
            } else break;
        }
        return dist;
    }

    pub fn getCost(self: *const Router, peer_id: PeerId) u64 {
        const lag = self.lags.get(peer_id) orelse UNKNOWN_LATENCY_NS;
        const c = lag / std.time.ns_per_ms;
        return if (c == 0) 1 else c;
    }

    // -- signature protocol --------------------------------------------------

    fn newReq(self: *const Router) SigReqState {
        const nonce = randU64();
        const seq = (if (self.infos.getPtr(self.selfKey())) |i| i.seq else 0) + 1;
        return .{ .seq = seq, .nonce = nonce };
    }

    /// Handle an incoming signature request; returns a SendSigRes action.
    pub fn handleRequestWithData(self: *Router, peer: *const PeerEntry, req: *const wire.SigReq) Allocator.Error!RouterAction {
        const res_bytes = try sigBytes(self.gpa, &peer.key, &self.selfKey(), req.seq, req.nonce, peer.port);
        defer self.gpa.free(res_bytes);
        const psig = self.crypto.sign(res_bytes);
        return .{ .send_sig_res = .{
            .peer_id = peer.id,
            .res = .{ .seq = req.seq, .nonce = req.nonce, .port = peer.port, .psig = psig },
        } };
    }

    pub fn handleResponse(self: *Router, peer_id: PeerId, key: *const PublicKey, res: *const wire.SigRes) Allocator.Error!void {
        const req_match = if (self.requests.getPtr(key.*)) |r| (r.seq == res.seq and r.nonce == res.nonce) else false;
        const rtt: u64 = if (self.sig_req_times.getPtr(peer_id)) |t| t.elapsedNanos() else 0;

        if (!self.responses.contains(key.*) and req_match) {
            self.res_seq_ctr += 1;
            try self.res_seqs.put(self.gpa, key.*, self.res_seq_ctr);
            try self.responses.put(self.gpa, key.*, .{
                .seq = res.seq,
                .nonce = res.nonce,
                .port = res.port,
                .psig = res.psig,
            });
        }

        if (!self.responded.contains(peer_id) and req_match) {
            try self.responded.put(self.gpa, peer_id, {});
            const lag = self.lags.get(peer_id) orelse UNKNOWN_LATENCY_NS;
            const new_lag = if (lag == UNKNOWN_LATENCY_NS)
                rtt * 2 // penalty for new links
            else blk: {
                const prev = lag;
                var l = lag * 7 / 8;
                l += @min(rtt, prev * 2) / 8;
                break :blk l;
            };
            try self.lags.put(self.gpa, peer_id, new_lag);
        }
    }

    fn clearReqs(self: *Router) void {
        self.requests.clearRetainingCapacity();
        self.responses.clearRetainingCapacity();
        self.res_seqs.clearRetainingCapacity();
        self.res_seq_ctr = 0;
    }

    fn sendReqs(self: *Router) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();
        self.clearReqs();

        // Snapshot (key, [ids]) pairs.
        const Pair = struct { key: PublicKey, ids: []PeerId };
        var pairs = std.ArrayListUnmanaged(Pair).empty;
        defer {
            for (pairs.items) |p| self.gpa.free(p.ids);
            pairs.deinit(self.gpa);
        }
        var it = self.peers.iterator();
        while (it.next()) |entry| {
            var ids = std.ArrayListUnmanaged(PeerId).empty;
            var iit = entry.value_ptr.keyIterator();
            while (iit.next()) |id| try ids.append(self.gpa, id.*);
            try pairs.append(self.gpa, .{ .key = entry.key_ptr.*, .ids = try ids.toOwnedSlice(self.gpa) });
        }

        const now = Instant.now();
        for (pairs.items) |pair| {
            const req = self.newReq();
            try self.requests.put(self.gpa, pair.key, req);
            for (pair.ids) |peer_id| {
                _ = self.responded.remove(peer_id);
                try self.sig_req_times.put(self.gpa, peer_id, now);
                try actions.append(.{ .send_sig_req = .{
                    .peer_id = peer_id,
                    .req = .{ .seq = req.seq, .nonce = req.nonce },
                } });
            }
        }
        return actions.toOwned();
    }

    // -- tree update ---------------------------------------------------------

    /// Process a tree announcement. Returns true if accepted (CRDT ordering).
    pub fn update(self: *Router, ann: *const RouterAnnounce) Allocator.Error!bool {
        if (self.infos.getPtr(ann.key)) |info| {
            // CRDT ordering — identical to Go; do not change.
            if (info.seq > ann.seq) {
                return false;
            } else if (info.seq < ann.seq) {
                // accept
            } else if (orderKeys(&info.parent, &ann.parent) == .lt) {
                return false;
            } else if (orderKeys(&ann.parent, &info.parent) == .lt) {
                // accept
            } else if (ann.nonce < info.nonce) {
                // accept
            } else {
                return false;
            }
        }

        // Clean up sent info for this key.
        var sit = self.sent.valueIterator();
        while (sit.next()) |s| _ = s.remove(ann.key);
        self.resetCache();

        try self.infos.put(self.gpa, ann.key, .{
            .parent = ann.parent,
            .seq = ann.seq,
            .nonce = ann.nonce,
            .port = ann.port,
            .psig = ann.psig,
            .sig = ann.sig,
        });
        try self.info_times.put(self.gpa, ann.key, Instant.now());
        return true;
    }

    /// Handle an announcement from a peer. Returns actions.
    pub fn handleAnnounce(self: *Router, peer_id: PeerId, peer_key: *const PublicKey, ann: *const RouterAnnounce) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();

        if (try self.update(ann)) {
            if (std.mem.eql(u8, &ann.key, &self.selfKey())) self.refresh = true;
            if (self.sent.getPtr(peer_key.*)) |sent| try sent.put(self.gpa, ann.key, {});
        } else {
            const new_info = RouterInfo{
                .parent = ann.parent,
                .seq = ann.seq,
                .nonce = ann.nonce,
                .port = ann.port,
                .psig = ann.psig,
                .sig = ann.sig,
            };
            if (self.infos.getPtr(ann.key)) |old_info| {
                if (!old_info.eql(&new_info)) {
                    if (self.sent.getPtr(peer_key.*)) |sent| try sent.put(self.gpa, ann.key, {});
                    try actions.append(.{ .send_announce = .{
                        .peer_id = peer_id,
                        .ann = old_info.getAnnounce(ann.key).toWire(),
                    } });
                } else {
                    if (self.sent.getPtr(peer_key.*)) |sent| try sent.put(self.gpa, ann.key, {});
                }
            }
        }
        return actions.toOwned();
    }

    /// Become root: create and apply a self-signed announcement.
    pub fn becomeRoot(self: *Router) Allocator.Error!bool {
        const req = self.newReq();
        const sk = self.selfKey();
        const res_bytes = try sigBytes(self.gpa, &sk, &sk, req.seq, req.nonce, 0);
        defer self.gpa.free(res_bytes);
        const psig = self.crypto.sign(res_bytes);
        const ann = RouterAnnounce{
            .key = sk,
            .parent = sk,
            .seq = req.seq,
            .nonce = req.nonce,
            .port = 0,
            .psig = psig,
            .sig = psig, // self-signed
        };
        return self.update(&ann);
    }

    fn useResponse(self: *Router, peer_key: *const PublicKey, res: *const SigResState) Allocator.Error!bool {
        const sk = self.selfKey();
        const bs = try sigBytes(self.gpa, &sk, peer_key, res.seq, res.nonce, res.port);
        defer self.gpa.free(bs);
        const sig = self.crypto.sign(bs);
        const ann = RouterAnnounce{
            .key = sk,
            .parent = peer_key.*,
            .seq = res.seq,
            .nonce = res.nonce,
            .port = res.port,
            .psig = res.psig,
            .sig = sig,
        };
        return self.update(&ann);
    }

    // -- parent selection (fix) ---------------------------------------------

    fn fix(self: *Router) Allocator.Error![]RouterAction {
        const self_key = self.selfKey();
        var best_root = self_key;
        var best_parent = self_key;
        var best_cost: u64 = std.math.maxInt(u64);

        const self_info_parent = if (self.infos.getPtr(self_key)) |i| i.parent else self_key;

        // Check current parent.
        if (self.peers.contains(self_info_parent)) {
            var rd = try self.getRootAndDists(&self_key);
            defer rd.dists.deinit(self.gpa);
            if (orderKeys(&rd.root, &best_root) == .lt) {
                var cost: u64 = std.math.maxInt(u64);
                if (self.peers.getPtr(self_info_parent)) |peers| {
                    var vit = peers.valueIterator();
                    while (vit.next()) |entry| {
                        const dist_to_root = rd.dists.get(rd.root) orelse std.math.maxInt(u64);
                        const c = saturatingMul(dist_to_root, self.getCost(entry.id));
                        if (c < cost) cost = c;
                    }
                }
                best_root = rd.root;
                best_parent = self_info_parent;
                best_cost = cost;
            }
        }

        // Check all peers with responses.
        var response_keys = std.ArrayListUnmanaged(PublicKey).empty;
        defer response_keys.deinit(self.gpa);
        var rkit = self.responses.keyIterator();
        while (rkit.next()) |k| try response_keys.append(self.gpa, k.*);

        for (response_keys.items) |pk| {
            if (!self.infos.contains(pk)) continue;
            var prd = try self.getRootAndDists(&pk);
            defer prd.dists.deinit(self.gpa);
            if (prd.dists.contains(self_key)) continue; // would loop
            var cost: u64 = std.math.maxInt(u64);
            if (self.peers.getPtr(pk)) |peers| {
                var vit = peers.valueIterator();
                while (vit.next()) |entry| {
                    const dist_to_root = prd.dists.get(prd.root) orelse std.math.maxInt(u64);
                    const c = saturatingMul(dist_to_root, self.getCost(entry.id));
                    if (c < cost) cost = c;
                }
            }
            if (orderKeys(&prd.root, &best_root) == .lt) {
                best_root = prd.root;
                best_parent = pk;
                best_cost = cost;
            } else if (!std.mem.eql(u8, &prd.root, &best_root)) {
                continue;
            }
            if ((self.refresh and cost * 2 < best_cost) or
                (!std.mem.eql(u8, &best_parent, &self_info_parent) and cost < best_cost))
            {
                best_root = prd.root;
                best_parent = pk;
                best_cost = cost;
            }
        }

        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();

        if (self.refresh or self.do_root1 or self.do_root2 or !std.mem.eql(u8, &self_info_parent, &best_parent)) {
            const res = self.responses.get(best_parent);
            if (res) |r| {
                if (!std.mem.eql(u8, &best_root, &self_key) and try self.useResponse(&best_parent, &r)) {
                    self.refresh = false;
                    self.do_root1 = false;
                    self.do_root2 = false;
                    const reqs = try self.sendReqs();
                    defer self.gpa.free(reqs);
                    try actions.extend(reqs);
                    return actions.toOwned();
                }
            }

            if (self.do_root2) {
                _ = try self.becomeRoot();
                self.refresh = false;
                self.do_root1 = false;
                self.do_root2 = false;
                const reqs = try self.sendReqs();
                defer self.gpa.free(reqs);
                try actions.extend(reqs);
            } else if (!self.do_root1) {
                self.do_root1 = true;
            }
        }
        return actions.toOwned();
    }

    // -- announcements -------------------------------------------------------

    fn sendAnnounces(self: *Router) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();
        const self_key = self.selfKey();
        const self_anc = try self.getAncestry(&self_key);
        defer self.gpa.free(self_anc);

        var peer_keys = std.ArrayListUnmanaged(PublicKey).empty;
        defer peer_keys.deinit(self.gpa);
        var skit = self.sent.keyIterator();
        while (skit.next()) |k| try peer_keys.append(self.gpa, k.*);

        for (peer_keys.items) |peer_key| {
            const peer_anc = try self.getAncestry(&peer_key);
            defer self.gpa.free(peer_anc);

            var to_send = std.ArrayListUnmanaged(PublicKey).empty;
            defer to_send.deinit(self.gpa);

            const sent = self.sent.getPtr(peer_key).?;
            for (self_anc) |k| {
                if (!sent.contains(k)) {
                    try to_send.append(self.gpa, k);
                    try sent.put(self.gpa, k, {});
                }
            }
            for (peer_anc) |k| {
                if (!sent.contains(k)) {
                    try to_send.append(self.gpa, k);
                    try sent.put(self.gpa, k, {});
                }
            }

            if (self.peers.getPtr(peer_key)) |peers| {
                for (to_send.items) |k| {
                    if (self.infos.getPtr(k)) |info| {
                        const w = info.getAnnounce(k).toWire();
                        var vit = peers.valueIterator();
                        while (vit.next()) |entry| {
                            try actions.append(.{ .send_announce = .{ .peer_id = entry.id, .ann = w } });
                        }
                    }
                }
            }
        }
        return actions.toOwned();
    }

    // -- greedy routing ------------------------------------------------------

    /// Find the best next-hop peer for a destination path. Updates watermark.
    pub fn lookup(self: *Router, path: []const PeerPort, watermark: *u64) Allocator.Error!?PeerId {
        const self_key = self.selfKey();
        const self_dist = try self.getDist(path, &self_key);
        if (self_dist >= watermark.*) return null;
        var best_dist = self_dist;
        watermark.* = self_dist;

        // Collect candidate entries (peers closer than us).
        var candidates = std.ArrayListUnmanaged(PeerEntry).empty;
        defer candidates.deinit(self.gpa);
        var peer_keys = std.ArrayListUnmanaged(PublicKey).empty;
        defer peer_keys.deinit(self.gpa);
        var kit = self.peers.keyIterator();
        while (kit.next()) |k| try peer_keys.append(self.gpa, k.*);

        for (peer_keys.items) |k| {
            const dist = try self.getDist(path, &k);
            if (dist < best_dist) {
                if (self.peers.getPtr(k)) |peers| {
                    var vit = peers.valueIterator();
                    while (vit.next()) |entry| try candidates.append(self.gpa, entry.*);
                }
            }
        }

        var best_peer: ?PeerEntry = null;
        var best_cost: u64 = std.math.maxInt(u64);
        best_dist = std.math.maxInt(u64);

        for (candidates.items) |p| {
            const dist = try self.getDist(path, &p.key);
            const cost = self.getCost(p.id);
            if (best_peer == null) {
                best_peer = p;
                best_cost = cost;
                best_dist = dist;
                continue;
            }
            const bp = best_peer.?;
            if (std.mem.eql(u8, &p.key, &bp.key) and p.prio < bp.prio) {
                best_peer = p; best_cost = cost; best_dist = dist;
            } else if (std.mem.eql(u8, &p.key, &bp.key) and p.prio > bp.prio) {
                continue;
            } else if (saturatingMul(cost, dist) < saturatingMul(best_cost, best_dist)) {
                best_peer = p; best_cost = cost; best_dist = dist;
            } else if (saturatingMul(cost, dist) > saturatingMul(best_cost, best_dist)) {
                continue;
            } else if (dist < best_dist) {
                best_peer = p; best_cost = cost; best_dist = dist;
            } else if (dist > best_dist) {
                continue;
            } else if (cost < best_cost) {
                best_peer = p; best_cost = cost; best_dist = dist;
            } else if (cost > best_cost) {
                continue;
            } else if (p.order < bp.order) {
                best_peer = p; best_cost = cost; best_dist = dist;
            }
        }
        if (best_peer) |p| return p.id;
        return null;
    }

    fn bestPeerForKey(self: *const Router, key: *const PublicKey) ?PeerId {
        const peers = self.peers.getPtr(key.*) orelse return null;
        var best: ?PeerEntry = null;
        var vit = peers.valueIterator();
        while (vit.next()) |e| {
            if (best == null or e.prio < best.?.prio) best = e.*;
        }
        return if (best) |b| b.id else null;
    }

    // -- traffic handling ----------------------------------------------------

    /// Outbound traffic from the local application. Consumes `tr`.
    pub fn sendTraffic(self: *Router, tr_in: TrafficPacket) Allocator.Error![]RouterAction {
        var tr = tr_in;
        if (self.pathfinder.getPath(&tr.dest)) |path| {
            try tr.setPath(self.gpa, path);
            const sk = self.selfKey();
            const coords = try self.cachedCoords(&sk);
            try tr.setFrom(self.gpa, coords);
            if (self.pathfinder.needsTrafficCache(&tr.dest)) {
                const cached = try tr.clone(self.gpa);
                self.pathfinder.cacheTraffic(&tr.dest, cached);
            }
            return self.routeTraffic(tr);
        }

        // No path — initiate a lookup, caching the packet in a rumor.
        const dest = tr.dest;
        const xform = self.blooms.xKey(&dest);
        _ = try self.pathfinder.ensureRumor(xform);
        self.pathfinder.cacheRumorTraffic(&xform, tr); // takes ownership

        if (!self.pathfinder.shouldThrottleRumor(&xform, self.path_throttle_ns)) {
            self.pathfinder.markRumorSent(&xform);
            return self.doSendLookup(&dest);
        }
        return self.gpa.alloc(RouterAction, 0);
    }

    /// Route traffic to the next hop or deliver locally. Consumes `tr`.
    pub fn routeTraffic(self: *Router, tr_in: TrafficPacket) Allocator.Error![]RouterAction {
        var tr = tr_in;
        var watermark = tr.watermark;
        if (try self.lookup(tr.path, &watermark)) |peer_id| {
            tr.watermark = watermark;
            var actions = ActionList.init(self.gpa);
            errdefer actions.deinit();
            try actions.append(.{ .send_traffic = .{ .peer_id = peer_id, .traffic = tr } });
            return actions.toOwned();
        } else if (std.mem.eql(u8, &tr.dest, &self.selfKey())) {
            self.pathfinder.resetTimeout(&tr.source);
            var actions = ActionList.init(self.gpa);
            errdefer actions.deinit();
            try actions.append(.{ .deliver_traffic = .{ .traffic = tr } });
            return actions.toOwned();
        } else {
            const actions = try self.doBroken(&tr);
            tr.deinit(self.gpa);
            return actions;
        }
    }

    /// Incoming traffic from a peer. Consumes `tr`.
    pub fn handleTraffic(self: *Router, tr: TrafficPacket) Allocator.Error![]RouterAction {
        return self.routeTraffic(tr);
    }

    // -- path discovery ------------------------------------------------------

    fn doSendLookup(self: *Router, dest: *const PublicKey) Allocator.Error![]RouterAction {
        if (self.pathfinder.shouldThrottleLookup(dest, self.path_throttle_ns)) {
            return self.gpa.alloc(RouterAction, 0);
        }
        self.pathfinder.markLookupSent(dest);
        const self_key = self.selfKey();
        const from = try self.cachedCoords(&self_key);
        var lookup_msg = wire.PathLookup{
            .source = self_key,
            .dest = dest.*,
            .from = try self.gpa.dupe(PeerPort, from),
        };
        defer lookup_msg.deinit(self.gpa);
        return self.handleLookupInternal(&self_key, &lookup_msg);
    }

    /// Force a path lookup, bypassing the rumor throttle. Consumes nothing.
    pub fn forceLookup(self: *Router, dest: PublicKey) Allocator.Error![]RouterAction {
        const xform = self.blooms.xKey(&dest);
        if (self.pathfinder.rumors.getPtr(xform)) |rumor| {
            rumor.send_time = null;
        } else {
            _ = try self.pathfinder.ensureRumor(xform);
        }
        return self.doSendLookup(&dest);
    }

    fn handleLookupInternal(self: *Router, from_key: *const PublicKey, lookup_msg: *const wire.PathLookup) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();

        // Multicast to matching peers.
        var targets = std.ArrayListUnmanaged(PublicKey).empty;
        defer targets.deinit(self.gpa);
        try self.blooms.getMulticastTargets(from_key, &lookup_msg.dest, &targets, self.gpa);
        if (@import("builtin").mode == .Debug) {
            var peer_it = self.peers.keyIterator();
            var n_on_tree: usize = 0;
            while (peer_it.next()) |pk| {
                if (self.blooms.isOnTree(pk)) n_on_tree += 1;
            }
            std.debug.print("[router] handleLookup dest_x={x} peers={d} on_tree={d} targets={d}\n", .{ self.blooms.xKey(&lookup_msg.dest), self.peers.count(), n_on_tree, targets.items.len });
        }
        for (targets.items) |target_key| {
            if (self.bestPeerForKey(&target_key)) |peer_id| {
                const dup_from = try self.gpa.dupe(PeerPort, lookup_msg.from);
                try actions.append(.{ .send_path_lookup = .{
                    .peer_id = peer_id,
                    .lookup = .{ .source = lookup_msg.source, .dest = lookup_msg.dest, .from = dup_from },
                } });
            }
        }

        // If we match the destination, generate a notify back to the source.
        const dx = self.blooms.xKey(&lookup_msg.dest);
        const sx = self.blooms.xKey(&self.selfKey());
        if (std.mem.eql(u8, &dx, &sx)) {
            const self_key = self.selfKey();
            const path = try self.cachedCoords(&self_key);
            const seq = timemod.wallClockSeconds();

            var candidate = OwnPathInfo{ .seq = seq, .path = try self.gpa.dupe(PeerPort, path) };
            if (!self.pathfinder.info.contentEqual(&candidate)) {
                try candidate.sign(self.gpa, &self.crypto);
                self.pathfinder.info.deinit(self.gpa);
                self.pathfinder.info = candidate; // move
            } else {
                candidate.deinit(self.gpa);
            }

            const notify = wire.PathNotify{
                .path = try self.gpa.dupe(PeerPort, lookup_msg.from),
                .watermark = std.math.maxInt(u64),
                .source = self_key,
                .dest = lookup_msg.source,
                .info = .{
                    .seq = self.pathfinder.info.seq,
                    .path = try self.gpa.dupe(PeerPort, self.pathfinder.info.path),
                    .sig = self.pathfinder.info.sig,
                },
            };
            var notify_mut = notify;
            const inner = try self.handleNotifyInternal(&self_key, &notify_mut);
            notify_mut.deinit(self.gpa);
            defer self.gpa.free(inner);
            try actions.extend(inner);
        }
        return actions.toOwned();
    }

    /// Handle an incoming lookup from a peer (drops if peer not on tree).
    pub fn handleLookup(self: *Router, peer_key: *const PublicKey, lookup_msg: *const wire.PathLookup) Allocator.Error![]RouterAction {
        if (!self.blooms.isOnTree(peer_key)) return self.gpa.alloc(RouterAction, 0);
        return self.handleLookupInternal(peer_key, lookup_msg);
    }

    fn handleNotifyInternal(self: *Router, _from_key: *const PublicKey, notify: *const wire.PathNotify) Allocator.Error![]RouterAction {
        _ = _from_key;
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();

        // Try to route towards the destination first.
        var watermark = notify.watermark;
        if (try self.lookup(notify.path, &watermark)) |peer_id| {
            var fwd = try cloneNotify(self.gpa, notify);
            fwd.watermark = watermark;
            try actions.append(.{ .send_path_notify = .{ .peer_id = peer_id, .notify = fwd } });
            return actions.toOwned();
        }

        // Otherwise it must be for us.
        if (!std.mem.eql(u8, &notify.dest, &self.selfKey())) return actions.toOwned();

        // Verify the signed path info.
        var sigbuf = std.ArrayListUnmanaged(u8).empty;
        defer sigbuf.deinit(self.gpa);
        try wire.encodeUvarint(&sigbuf, self.gpa, notify.info.seq);
        try wire.encodePath(&sigbuf, self.gpa, notify.info.path);
        if (!Crypto.verify(&notify.source, sigbuf.items, &notify.info.sig)) return actions.toOwned();

        const xformed_source = self.blooms.xKey(&notify.source);
        const res = try self.pathfinder.acceptNotify(
            notify.source,
            xformed_source,
            notify.info.seq,
            try self.gpa.dupe(PeerPort, notify.info.path),
        );

        if (res.traffic) |cached| {
            var t = cached;
            try t.setPath(self.gpa, notify.info.path);
            const sk = self.selfKey();
            const coords = try self.cachedCoords(&sk);
            try t.setFrom(self.gpa, coords);
            const routed = try self.routeTraffic(t); // consumes t
            defer self.gpa.free(routed);
            try actions.extend(routed);
        }

        if (res.accepted) {
            try actions.append(.{ .path_notify_callback = .{ .key = notify.source } });
        }
        return actions.toOwned();
    }

    pub fn handleNotify(self: *Router, peer_key: *const PublicKey, notify: *const wire.PathNotify) Allocator.Error![]RouterAction {
        return self.handleNotifyInternal(peer_key, notify);
    }

    fn doBroken(self: *Router, tr: *const TrafficPacket) Allocator.Error![]RouterAction {
        var broken = wire.PathBroken{
            .path = try self.gpa.dupe(PeerPort, tr.from),
            .watermark = std.math.maxInt(u64),
            .source = tr.source,
            .dest = tr.dest,
        };
        defer broken.deinit(self.gpa);
        return self.handleBrokenInternal(&broken);
    }

    fn handleBrokenInternal(self: *Router, broken: *const wire.PathBroken) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();
        var watermark = broken.watermark;
        if (try self.lookup(broken.path, &watermark)) |peer_id| {
            var fwd = wire.PathBroken{
                .path = try self.gpa.dupe(PeerPort, broken.path),
                .watermark = watermark,
                .source = broken.source,
                .dest = broken.dest,
            };
            _ = &fwd;
            try actions.append(.{ .send_path_broken = .{ .peer_id = peer_id, .broken = fwd } });
            return actions.toOwned();
        }

        if (!std.mem.eql(u8, &broken.source, &self.selfKey())) return actions.toOwned();

        // For us: mark path broken and re-initiate lookup.
        self.pathfinder.handleBroken(&broken.dest);
        if (!self.pathfinder.shouldThrottleLookup(&broken.dest, self.path_throttle_ns)) {
            const lk = try self.doSendLookup(&broken.dest);
            defer self.gpa.free(lk);
            try actions.extend(lk);
        }
        return actions.toOwned();
    }

    pub fn handleBroken(self: *Router, broken: *const wire.PathBroken) Allocator.Error![]RouterAction {
        return self.handleBrokenInternal(broken);
    }

    pub fn handleBloom(self: *Router, peer_key: *const PublicKey, filter: BloomFilter) void {
        self.blooms.handleBloom(peer_key, filter);
    }

    // -- maintenance ---------------------------------------------------------

    fn bloomsMaintenance(self: *Router) Allocator.Error![]RouterAction {
        const self_key = self.selfKey();
        const self_parent = if (self.infos.getPtr(self_key)) |i| i.parent else self_key;

        // Build parent map for the blooms manager.
        var parent_map = KeyMap(PublicKey, PublicKey){};
        defer parent_map.deinit(self.gpa);
        var it = self.infos.iterator();
        while (it.next()) |entry| try parent_map.put(self.gpa, entry.key_ptr.*, entry.value_ptr.parent);

        const to_send = try self.blooms.doMaintenance(&self_key, &self_parent, &parent_map);
        defer self.gpa.free(to_send);

        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();
        for (to_send) |kb| {
            if (self.peers.getPtr(kb.key)) |peers| {
                var vit = peers.valueIterator();
                while (vit.next()) |entry| {
                    try actions.append(.{ .send_bloom = .{ .peer_id = entry.id, .bloom = kb.filter } });
                }
            }
        }
        return actions.toOwned();
    }

    /// Periodic maintenance (call ~every second). Returns actions to execute.
    pub fn doMaintenance(self: *Router) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();

        if (self.last_status_log.elapsedNanos() >= 60 * std.time.ns_per_s) {
            self.last_status_log = Instant.now();
        }
        if (self.last_refresh.elapsedNanos() >= self.router_refresh_ns) {
            self.refresh = true;
            self.last_refresh = Instant.now();
        }

        self.do_root2 = self.do_root2 or self.do_root1;
        self.resetCache();
        try self.updateAncestries();

        const a_fix = try self.fix();
        defer self.gpa.free(a_fix);
        try actions.extend(a_fix);

        const a_ann = try self.sendAnnounces();
        defer self.gpa.free(a_ann);
        try actions.extend(a_ann);

        const a_bloom = try self.bloomsMaintenance();
        defer self.gpa.free(a_bloom);
        try actions.extend(a_bloom);

        self.pathfinder.cleanupExpired(self.path_timeout_ns);
        return actions.toOwned();
    }

    // -- peer management -----------------------------------------------------

    /// Add a peer connection. Returns actions to execute.
    pub fn addPeer(self: *Router, entry: PeerEntry) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();
        const key = entry.key;
        const peer_id = entry.id;

        if (!self.peers.contains(key)) {
            try self.peers.put(self.gpa, key, PeerMap{});
            try self.sent.put(self.gpa, key, KeySet{});
            try self.ports.put(self.gpa, entry.port, key);
            try self.blooms.addInfo(key);
        } else {
            // Send already-sent announcements to the new connection.
            if (self.sent.getPtr(key)) |sent| {
                var sent_keys = std.ArrayListUnmanaged(PublicKey).empty;
                defer sent_keys.deinit(self.gpa);
                var skit = sent.keyIterator();
                while (skit.next()) |k| try sent_keys.append(self.gpa, k.*);
                for (sent_keys.items) |k| {
                    if (self.infos.getPtr(k)) |info| {
                        try actions.append(.{ .send_announce = .{ .peer_id = peer_id, .ann = info.getAnnounce(k).toWire() } });
                    }
                }
            }
        }

        try self.peers.getPtr(key).?.put(self.gpa, entry.id, entry);
        try self.lags.put(self.gpa, peer_id, UNKNOWN_LATENCY_NS);

        if (!self.requests.contains(key)) {
            try self.requests.put(self.gpa, key, self.newReq());
        }
        const req = self.requests.get(key).?;
        _ = self.responded.remove(peer_id);
        try self.sig_req_times.put(self.gpa, peer_id, Instant.now());
        try actions.append(.{ .send_sig_req = .{ .peer_id = peer_id, .req = .{ .seq = req.seq, .nonce = req.nonce } } });

        if (self.blooms.getSendBloom(&key)) |bloom| {
            try actions.append(.{ .send_bloom = .{ .peer_id = peer_id, .bloom = bloom } });
        }
        return actions.toOwned();
    }

    /// Remove a peer connection. Returns actions to execute.
    pub fn removePeer(self: *Router, peer_id: PeerId, key: PublicKey, port: PeerPort) Allocator.Error![]RouterAction {
        var actions = ActionList.init(self.gpa);
        errdefer actions.deinit();
        _ = self.lags.remove(peer_id);
        _ = self.responded.remove(peer_id);
        _ = self.sig_req_times.remove(peer_id);

        if (self.peers.getPtr(key)) |peers| {
            _ = peers.remove(peer_id);
            if (peers.count() == 0) {
                if (self.peers.fetchRemove(key)) |kv| {
                    var pm = kv.value;
                    pm.deinit(self.gpa);
                }
                if (self.sent.fetchRemove(key)) |kv| {
                    var s = kv.value;
                    s.deinit(self.gpa);
                }
                _ = self.ports.remove(port);
                _ = self.requests.remove(key);
                _ = self.responses.remove(key);
                _ = self.res_seqs.remove(key);
                if (self.ancs.fetchRemove(key)) |kv| self.gpa.free(kv.value);
                if (self.cache.fetchRemove(key)) |kv| self.gpa.free(kv.value);
                self.blooms.removeInfo(&key);
            } else {
                if (self.blooms.getSendBloom(&key)) |bloom| {
                    var vit = peers.valueIterator();
                    while (vit.next()) |entry| {
                        try actions.append(.{ .send_bloom = .{ .peer_id = entry.id, .bloom = bloom } });
                    }
                }
            }
        }
        return actions.toOwned();
    }

    /// Force an immediate refresh on the next maintenance tick.
    pub fn forceRefresh(self: *Router) void {
        self.refresh = true;
        self.do_root1 = true;
        self.do_root2 = true;
        const now = Instant.now();
        self.last_refresh = .{ .nanos = if (now.nanos > self.router_refresh_ns) now.nanos - self.router_refresh_ns else 0 };
    }

    /// Expire old router infos.
    pub fn expireInfos(self: *Router) Allocator.Error!void {
        const self_key = self.selfKey();
        var expired = std.ArrayListUnmanaged(PublicKey).empty;
        defer expired.deinit(self.gpa);

        var it = self.info_times.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            const age = entry.value_ptr.elapsedNanos();
            const limit = if (std.mem.eql(u8, &k, &self_key)) self.router_refresh_ns else self.router_timeout_ns;
            if (age >= limit) try expired.append(self.gpa, k);
        }

        for (expired.items) |key| {
            if (std.mem.eql(u8, &key, &self_key)) {
                self.refresh = true;
            } else {
                _ = self.infos.remove(key);
                _ = self.info_times.remove(key);
                var sit = self.sent.valueIterator();
                while (sit.next()) |s| _ = s.remove(key);
                self.resetCache();
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn orderKeys(a: *const PublicKey, b: *const PublicKey) std.math.Order {
    return std.mem.order(u8, a, b);
}

fn eqlKeySlices(a: []const PublicKey, b: []const PublicKey) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, &x, &y)) return false;
    }
    return true;
}

fn saturatingMul(a: u64, b: u64) u64 {
    const r = @mulWithOverflow(a, b);
    return if (r[1] != 0) std.math.maxInt(u64) else r[0];
}

fn cloneNotify(gpa: Allocator, n: *const wire.PathNotify) Allocator.Error!wire.PathNotify {
    const path = try gpa.dupe(PeerPort, n.path);
    errdefer gpa.free(path);
    const ipath = try gpa.dupe(PeerPort, n.info.path);
    return .{
        .path = path,
        .watermark = n.watermark,
        .source = n.source,
        .dest = n.dest,
        .info = .{ .seq = n.info.seq, .path = ipath, .sig = n.info.sig },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeRouter(gpa: Allocator) !Router {
    const crypto = Crypto.generate();
    const cfg = config.Config.default();
    return Router.init(gpa, crypto, &cfg);
}

test "become root on first maintenance" {
    const gpa = testing.allocator;
    var router = try makeRouter(gpa);
    defer router.deinit();
    const self_key = router.selfKey();

    const actions = try router.doMaintenance();
    defer deinitActions(gpa, actions);

    try testing.expect(router.infos.contains(self_key));
    const info = router.infos.getPtr(self_key).?;
    try testing.expectEqualSlices(u8, &self_key, &info.parent); // self-rooted
}

test "update accepts newer seq from another node" {
    const gpa = testing.allocator;
    var router = try makeRouter(gpa);
    defer router.deinit();
    _ = try router.becomeRoot();

    const c2 = Crypto.generate();
    var ann = RouterAnnounce{
        .key = c2.public_key,
        .parent = c2.public_key,
        .seq = 1,
        .nonce = 42,
        .port = 0,
        .psig = undefined,
        .sig = undefined,
    };
    const bs = try ann.bytesForSig(gpa);
    defer gpa.free(bs);
    const sig = c2.sign(bs);
    ann.psig = sig;
    ann.sig = sig;

    try testing.expect(ann.check(gpa));
    try testing.expect(try router.update(&ann));
    try testing.expect(router.infos.contains(c2.public_key));
}

test "get_root_and_path for self-root is empty" {
    const gpa = testing.allocator;
    var router = try makeRouter(gpa);
    defer router.deinit();
    _ = try router.becomeRoot();
    const self_key = router.selfKey();

    var rp = try router.getRootAndPath(&self_key);
    defer gpa.free(rp.path);
    try testing.expectEqualSlices(u8, &self_key, &rp.root);
    try testing.expectEqual(@as(usize, 0), rp.path.len);
}

test "get_dist same node empty path is zero" {
    const gpa = testing.allocator;
    var router = try makeRouter(gpa);
    defer router.deinit();
    _ = try router.becomeRoot();
    const self_key = router.selfKey();
    const dist = try router.getDist(&[_]PeerPort{}, &self_key);
    try testing.expectEqual(@as(u64, 0), dist);
}

test "announce check validates self-signed root" {
    const gpa = testing.allocator;
    const crypto = Crypto.generate();
    var ann = RouterAnnounce{
        .key = crypto.public_key,
        .parent = crypto.public_key,
        .seq = 1,
        .nonce = 42,
        .port = 0,
        .psig = undefined,
        .sig = undefined,
    };
    const bs = try ann.bytesForSig(gpa);
    defer gpa.free(bs);
    const sig = crypto.sign(bs);
    ann.psig = sig;
    ann.sig = sig;
    try testing.expect(ann.check(gpa));
}

test "add and remove peer cleans up state" {
    const gpa = testing.allocator;
    var router = try makeRouter(gpa);
    defer router.deinit();

    const peer_key = [_]u8{0x55} ** 32;
    const entry = PeerEntry{ .id = 1, .key = peer_key, .port = 7, .prio = 0, .order = 0 };

    const add_actions = try router.addPeer(entry);
    defer deinitActions(gpa, add_actions);
    try testing.expect(router.peers.contains(peer_key));
    // addPeer emits at least a SendSigReq.
    var saw_req = false;
    for (add_actions) |a| {
        if (a == .send_sig_req) saw_req = true;
    }
    try testing.expect(saw_req);

    const rm_actions = try router.removePeer(1, peer_key, 7);
    defer deinitActions(gpa, rm_actions);
    try testing.expect(!router.peers.contains(peer_key));
}

test "send_traffic with no path initiates lookup and caches packet" {
    const gpa = testing.allocator;
    var router = try makeRouter(gpa);
    defer router.deinit();
    _ = try router.becomeRoot();

    const dest = [_]u8{0x77} ** 32;
    const tr = TrafficPacket.init(router.selfKey(), dest, try gpa.dupe(u8, "hi"));
    const actions = try router.sendTraffic(tr); // consumes tr (cached in rumor)
    defer deinitActions(gpa, actions);

    // A rumor must now exist for the (transformed) destination.
    const xform = router.blooms.xKey(&dest);
    try testing.expect(router.pathfinder.rumors.contains(xform));
}
