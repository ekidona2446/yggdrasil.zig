//! Node core: wires ironwood router, peers, and encrypted sessions together.
//!
//! This is the central coordinator that manages peer connections, dispatches
//! router actions, and demuxes incoming session traffic. Unlike the previous
//! version, this actually serializes `RouterAction`s to wire bytes destined
//! for specific peers, and pipes decrypted `deliver` traffic from the session
//! layer back through the router for tree-routed forwarding -- matching the
//! reference Go implementation data flow:
//!
//!   peer bytes -> wire.decodeFrame -> Router.handle* -> RouterAction(s)
//!                                                          |
//!                                                          v
//!                                        (send_traffic/announce/... -> peer bytes)
//!
//!   Router.deliver_traffic (dest == self) -> SessionManager.handleData
//!                                               |
//!                                               +-> OutAction.deliver -> app (TUN)
//!                                               +-> OutAction.send_to_inner -> Router.sendTraffic (session handshake bytes travel as tree traffic)

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const crypto = ironwood.crypto;
const wire = ironwood.wire;
const router_mod = ironwood.router;
const peers_mod = ironwood.peers;
const traffic_mod = ironwood.traffic;
const encrypted = ironwood.encrypted;
const bloom_mod = ironwood.bloom;

const PublicKey = crypto.PublicKey;
const Router = router_mod.Router;
const RouterAction = router_mod.RouterAction;
const RouterAnnounce = router_mod.RouterAnnounce;
const PeerEntry = router_mod.PeerEntry;
const PeerId = router_mod.PeerId;
const Peers = peers_mod.Peers;
const PeerHandle = peers_mod.PeerHandle;
const SessionManager = encrypted.session.SessionManager;
const OutAction = encrypted.session.OutAction;
const GroupAuth = encrypted.GroupAuth;
const CurvePrivateKey = encrypted.CurvePrivateKey;
const TrafficPacket = traffic_mod.TrafficPacket;

/// Session type bytes prepended to payloads carried inside a session (used by
/// higher layers, e.g. TUN traffic vs in-band protocol messages).
pub const TYPE_SESSION_TRAFFIC: u8 = 0x01;
pub const TYPE_SESSION_PROTO: u8 = 0x02;

/// Explicit error set to break the mutual-recursion inference cycle between
/// `processRoutedActions` / `handleSessionData` / `injectTreeTraffic`.
const PumpError = std.mem.Allocator.Error || error{
    Decode,
    Encode,
    BadKey,
    AuthenticationFailed,
    WeakPublicKey,
    IdentityElement,
    NonCanonical,
    InvalidEncoding,
};

/// A serialized message ready to hand to the transport layer for a given peer.
pub const OutgoingFrame = struct {
    peer_id: PeerId,
    /// Allocator-owned bytes; caller (network layer) must free after sending.
    data: []u8,
};

/// A fully decrypted, demultiplexed application payload delivered from a peer.
pub const DeliveredPayload = struct {
    source: PublicKey,
    /// Allocator-owned; caller must free.
    data: []u8,
};

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

pub const Core = struct {
    gpa: std.mem.Allocator,
    crypto: crypto.Crypto,
    router: Router,
    peers: Peers,
    sessions: SessionManager,
    curve_priv: CurvePrivateKey,

    /// Our address and subnet.
    address: node.Address,
    subnet: node.Subnet,

    /// Ironwood config.
    config: ironwood.Config,

    /// Allowed peer keys (empty = allow all).
    allowed_keys: std.AutoHashMapUnmanaged(PublicKey, void),

    pub fn init(gpa: std.mem.Allocator, id: crypto.Crypto, cfg: ironwood.Config, group_password: []const u8) !Core {
        const public_key = id.public_key;
        const addr = node.addrForKey(&public_key);
        const subnet = node.subnetForKey(&public_key);

        const curve_priv = try encrypted.crypto.ed25519PrivateToCurve25519(id.key_pair);
        const ga = encrypted.GroupAuth.init(group_password);

        const rt = try Router.init(gpa, id, &cfg);

        return Core{
            .gpa = gpa,
            .crypto = id,
            .router = rt,
            .peers = Peers.init(gpa),
            .sessions = SessionManager.init(gpa, ga),
            .curve_priv = curve_priv,
            .address = addr,
            .subnet = subnet,
            .config = cfg,
            .allowed_keys = .{},
        };
    }

    pub fn deinit(self: *Core) void {
        self.router.deinit();
        self.peers.deinit();
        self.sessions.deinit();
        self.allowed_keys.deinit(self.gpa);
    }

    /// Add an allowed public key for access control.
    pub fn addAllowedKey(self: *Core, key: PublicKey) !void {
        try self.allowed_keys.put(self.gpa, key, {});
    }

    /// Check if a key is allowed.
    pub fn isAllowed(self: *const Core, key: *const PublicKey) bool {
        if (self.allowed_keys.count() == 0) return true;
        return self.allowed_keys.contains(key.*);
    }

    /// Get the router's own public key.
    pub fn selfKey(self: *const Core) PublicKey {
        return self.router.selfKey();
    }

    // -------------------------------------------------------------------
    // Peer lifecycle
    // -------------------------------------------------------------------

    /// Handle a new peer connection. Adds the peer to the router and peers
    /// manager, and serializes the resulting RouterActions (sig-req, etc.)
    /// into outgoing frames for the caller (network layer) to transmit.
    /// Caller must free the returned slice and each frame's `data` (use
    /// `freeFrames`).
    pub fn addPeer(self: *Core, key: PublicKey, prio: u8) !struct { handle: PeerHandle, frames: []OutgoingFrame } {
        if (!self.isAllowed(&key)) return error.PeerNotAllowed;

        const handle = try self.peers.allocatePeer(key, prio);
        const entry = handle.toEntry();

        const actions = try self.router.addPeer(entry);
        defer router_mod.deinitActions(self.gpa, actions);

        const frames = try self.serializeActions(actions);
        return .{ .handle = handle, .frames = frames };
    }

    /// Remove a peer connection. Returns actions serialized to frames for any
    /// peers that need updated bloom filters, etc.
    pub fn removePeer(self: *Core, peer_id: PeerId, key: PublicKey) ![]OutgoingFrame {
        const port = self.peers.removePeer(peer_id, &key) orelse return &[_]OutgoingFrame{};
        const actions = try self.router.removePeer(peer_id, key, port);
        defer router_mod.deinitActions(self.gpa, actions);
        return self.serializeActions(actions);
    }

    // -------------------------------------------------------------------
    // Incoming wire frame handling (bytes received from a peer connection)
    // -------------------------------------------------------------------

    pub const HandleResult = struct {
        /// Frames to transmit to (possibly other) peers.
        frames: []OutgoingFrame,
        /// Fully decrypted application payloads addressed to us.
        delivered: []DeliveredPayload,
        /// Public keys for which a new path was just discovered/confirmed
        /// (caller should update address/subnet -> key caches, e.g. TUN's
        /// ipv6rwc, and flush any packets buffered for them).
        discovered_keys: []PublicKey,
    };

    /// Decode and handle a single wire frame's payload (post packet-type byte
    /// dispatch is done here). `peer_id`/`peer_key` identify the sender.
    /// Frees nothing owned by the caller; caller retains ownership of `payload`.
    pub fn handleFrame(
        self: *Core,
        peer_id: PeerId,
        peer_key: *const PublicKey,
        frame: wire.DecodedFrame,
    ) !HandleResult {
        var out_frames = std.ArrayListUnmanaged(OutgoingFrame).empty;
        errdefer freeFrameList(self.gpa, &out_frames);
        var delivered = std.ArrayListUnmanaged(DeliveredPayload).empty;
        errdefer freeDeliveredList(self.gpa, &delivered);
        var discovered = std.ArrayListUnmanaged(PublicKey).empty;
        errdefer discovered.deinit(self.gpa);

        switch (frame.packet_type) {
            .dummy, .keep_alive => {},
            .proto_sig_req => {
                var r = wire.WireReader.init(frame.payload);
                const req = wire.SigReq.decode(&r) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                const entry = (self.peers.getHandle(peer_id) orelse return error.PeerNotFound).toEntry();
                const action = try self.router.handleRequestWithData(&entry, &req);
                var actions = [_]RouterAction{action};
                try self.appendSerialized(&out_frames, &actions);
                actions[0].deinit(self.gpa);
            },
            .proto_sig_res => {
                var r = wire.WireReader.init(frame.payload);
                const res = wire.SigRes.decode(&r) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                try self.router.handleResponse(peer_id, peer_key, &res);
                const actions = try self.router.doMaintenance();
                defer router_mod.deinitActions(self.gpa, actions);
                try self.appendSerialized(&out_frames, actions);
            },
            .proto_announce => {
                const ann = wire.Announce.decode(frame.payload) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                const rann = RouterAnnounce.fromWire(&ann);
                if (!rann.check(self.gpa)) return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                const actions = try self.router.handleAnnounce(peer_id, peer_key, &rann);
                defer router_mod.deinitActions(self.gpa, actions);
                try self.appendSerialized(&out_frames, actions);
            },
            .proto_bloom_filter => {
                const bf = bloom_mod.BloomFilter.decode(frame.payload) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                std.debug.print("[core] recv bloom_filter from {x} ones={d}\n", .{ peer_key.*, bf.countOnes() });
                self.router.handleBloom(peer_key, bf);
            },
            .proto_path_lookup => {
                var lookup = wire.PathLookup.decode(self.gpa, frame.payload) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                defer lookup.deinit(self.gpa);
                std.debug.print("[core] recv path_lookup dest={x} on_tree(peer)={}\n", .{ lookup.dest, self.router.blooms.isOnTree(peer_key) });
                const actions = try self.router.handleLookup(peer_key, &lookup);
                defer router_mod.deinitActions(self.gpa, actions);
                std.debug.print("[core] path_lookup produced {d} actions\n", .{actions.len});
                try self.appendSerialized(&out_frames, actions);
            },
            .proto_path_notify => {
                var notify = wire.PathNotify.decode(self.gpa, frame.payload) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                defer notify.deinit(self.gpa);
                std.debug.print("[core] recv path_notify dest={x} source={x}\n", .{ notify.dest, notify.source });
                const actions = try self.router.handleNotify(peer_key, &notify);
                defer router_mod.deinitActions(self.gpa, actions);
                std.debug.print("[core] path_notify produced {d} actions\n", .{actions.len});
                try self.processRoutedActions(&out_frames, &delivered, &discovered, actions);
            },
            .proto_path_broken => {
                var broken = wire.PathBroken.decode(self.gpa, frame.payload) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                defer broken.deinit(self.gpa);
                const actions = try self.router.handleBroken(&broken);
                defer router_mod.deinitActions(self.gpa, actions);
                try self.appendSerialized(&out_frames, actions);
            },
            .traffic => {
                var tr = wire.Traffic.decode(self.gpa, frame.payload) catch return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
                const pkt = TrafficPacket{
                    .path = tr.path,
                    .from = tr.from,
                    .source = tr.source,
                    .dest = tr.dest,
                    .watermark = tr.watermark,
                    .payload = tr.payload,
                };
                tr.path = &.{};
                tr.from = &.{};
                tr.payload = &.{};
                const actions = try self.router.handleTraffic(pkt);
                defer router_mod.deinitActions(self.gpa, actions);
                try self.processRoutedActions(&out_frames, &delivered, &discovered, actions);
            },
        }

        return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
    }

    /// Process router actions that may include `deliver_traffic` (routed to
    /// us): feed those into the session layer, which may itself produce more
    /// tree traffic (handshake replies) or fully decrypted application data.
    fn processRoutedActions(
        self: *Core,
        out_frames: *std.ArrayListUnmanaged(OutgoingFrame),
        delivered: *std.ArrayListUnmanaged(DeliveredPayload),
        discovered: *std.ArrayListUnmanaged(PublicKey),
        actions: []RouterAction,
    ) PumpError!void {
        for (actions) |*action| {
            switch (action.*) {
                .deliver_traffic => |*d| {
                    try self.handleSessionData(&d.traffic.source, d.traffic.payload, out_frames, delivered, discovered);
                },
                .path_notify_callback => |*pn| {
                    try discovered.append(self.gpa, pn.key);
                },
                else => {
                    var single = [_]RouterAction{action.*};
                    try self.appendSerialized(out_frames, &single);
                },
            }
        }
    }

    /// Feed raw session-layer bytes (received tree traffic addressed to us)
    /// through the SessionManager, routing any resulting handshake replies
    /// back out as tree traffic and appending fully-decrypted app data to
    /// `delivered`.
    fn handleSessionData(
        self: *Core,
        from_key: *const PublicKey,
        data: []const u8,
        out_frames: *std.ArrayListUnmanaged(OutgoingFrame),
        delivered: *std.ArrayListUnmanaged(DeliveredPayload),
        discovered: *std.ArrayListUnmanaged(PublicKey),
    ) PumpError!void {
        const session_actions = try self.sessions.handleData(from_key, data, &self.curve_priv, &self.crypto);
        defer encrypted.session.deinitActions(self.gpa, session_actions);

        for (session_actions) |*action| {
            switch (action.*) {
                .deliver => |*d| {
                    if (d.data.len > 0) {
                        const owned = try self.gpa.dupe(u8, d.data);
                        try delivered.append(self.gpa, .{ .source = from_key.*, .data = owned });
                    }
                },
                .send_to_inner => |*si| {
                    // Handshake / ack bytes travel back to the peer as ordinary
                    // tree traffic (dest = from_key), just like session.writeTo.
                    try self.injectTreeTraffic(si.dest, si.data, out_frames, delivered, discovered);
                },
            }
        }
    }

    /// Route `payload` as a traffic packet to `dest` through the tree,
    /// serializing the resulting router actions (which may recursively
    /// deliver to ourselves if dest == self, though that shouldn't happen
    /// in practice for session traffic).
    fn injectTreeTraffic(
        self: *Core,
        dest: PublicKey,
        payload: []const u8,
        out_frames: *std.ArrayListUnmanaged(OutgoingFrame),
        delivered: *std.ArrayListUnmanaged(DeliveredPayload),
        discovered: *std.ArrayListUnmanaged(PublicKey),
    ) PumpError!void {
        const owned = try self.gpa.dupe(u8, payload);
        const pkt = TrafficPacket.init(self.crypto.public_key, dest, owned);
        const actions = try self.router.sendTraffic(pkt);
        defer router_mod.deinitActions(self.gpa, actions);
        try self.processRoutedActions(out_frames, delivered, discovered, actions);
    }

    // -------------------------------------------------------------------
    // Outbound application writes (e.g. from TUN)
    // -------------------------------------------------------------------

    /// Write an application payload to `dest`. Handles session encryption and
    /// tree routing, returning frames to transmit to directly-connected peers.
    /// Caller must free the returned slice (and each frame's data).
    pub fn writeTo(self: *Core, dest: *const PublicKey, data: []const u8, session_type: u8) ![]OutgoingFrame {
        var buf = try self.gpa.alloc(u8, 1 + data.len);
        defer self.gpa.free(buf);
        buf[0] = session_type;
        @memcpy(buf[1..], data);

        var out_frames = std.ArrayListUnmanaged(OutgoingFrame).empty;
        errdefer freeFrameList(self.gpa, &out_frames);
        // We never expect deliveries or discoveries as a side effect of a
        // local write, but route through the same helper for consistency.
        var delivered = std.ArrayListUnmanaged(DeliveredPayload).empty;
        defer freeDeliveredList(self.gpa, &delivered);
        var discovered = std.ArrayListUnmanaged(PublicKey).empty;
        defer discovered.deinit(self.gpa);

        const actions = try self.sessions.writeTo(dest, buf, &self.crypto);
        defer encrypted.session.deinitActions(self.gpa, actions);

        for (actions) |*action| {
            switch (action.*) {
                .send_to_inner => |*si| try self.injectTreeTraffic(si.dest, si.data, &out_frames, &delivered, &discovered),
                .deliver => {},
            }
        }
        return out_frames.toOwnedSlice(self.gpa);
    }

    /// Force a path lookup for a partial/unknown key (e.g. TUN destination
    /// address resolution). Returns frames to transmit.
    pub fn sendLookup(self: *Core, dest: PublicKey) ![]OutgoingFrame {
        const actions = try self.router.forceLookup(dest);
        defer router_mod.deinitActions(self.gpa, actions);
        std.debug.print("[core] sendLookup dest={x} -> {d} actions\n", .{ dest, actions.len });
        for (actions) |a| {
            std.debug.print("[core]   action tag={s}\n", .{@tagName(a)});
        }
        return self.serializeActions(actions);
    }

    // -------------------------------------------------------------------
    // Maintenance
    // -------------------------------------------------------------------

    pub const MaintenanceResult = struct {
        frames: []OutgoingFrame,
        delivered: []DeliveredPayload,
        discovered_keys: []PublicKey,
    };

    /// Run periodic maintenance: expire old infos, refresh tree, cleanup
    /// sessions. Returns any resulting frames/deliveries.
    pub fn maintenance(self: *Core) !MaintenanceResult {
        var out_frames = std.ArrayListUnmanaged(OutgoingFrame).empty;
        errdefer freeFrameList(self.gpa, &out_frames);
        var delivered = std.ArrayListUnmanaged(DeliveredPayload).empty;
        errdefer freeDeliveredList(self.gpa, &delivered);
        var discovered = std.ArrayListUnmanaged(PublicKey).empty;
        errdefer discovered.deinit(self.gpa);

        const actions = try self.router.doMaintenance();
        defer router_mod.deinitActions(self.gpa, actions);
        try self.processRoutedActions(&out_frames, &delivered, &discovered, actions);

        try self.router.expireInfos();
        self.sessions.cleanupExpired();

        return .{ .frames = try out_frames.toOwnedSlice(self.gpa), .delivered = try delivered.toOwnedSlice(self.gpa), .discovered_keys = try discovered.toOwnedSlice(self.gpa) };
    }

    // -------------------------------------------------------------------
    // Serialization helpers
    // -------------------------------------------------------------------

    fn serializeActions(self: *Core, actions: []RouterAction) ![]OutgoingFrame {
        var out = std.ArrayListUnmanaged(OutgoingFrame).empty;
        errdefer freeFrameList(self.gpa, &out);
        try self.appendSerialized(&out, actions);
        return out.toOwnedSlice(self.gpa);
    }

    fn appendSerialized(self: *Core, out: *std.ArrayListUnmanaged(OutgoingFrame), actions: []RouterAction) !void {
        for (actions) |*action| {
            if (try self.serializeOne(action)) |frame| {
                try out.append(self.gpa, frame);
            }
        }
    }

    /// Serialize a single RouterAction into a wire frame targeted at a peer,
    /// or null if the action has no direct wire representation here
    /// (deliver_traffic / path_notify_callback are handled by the caller).
    fn serializeOne(self: *Core, action: *const RouterAction) !?OutgoingFrame {
        const gpa = self.gpa;
        return switch (action.*) {
            .send_sig_req => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.req.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_sig_req, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_sig_res => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.res.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_sig_res, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_announce => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.ann.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_announce, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_bloom => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.bloom.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_bloom_filter, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_path_lookup => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.lookup.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_path_lookup, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_path_notify => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.notify.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_path_notify, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_path_broken => |a| blk: {
                var body = std.ArrayListUnmanaged(u8).empty;
                defer body.deinit(gpa);
                try a.broken.encode(&body, gpa);
                const frame = try wire.encodeFrame(gpa, .proto_path_broken, body.items);
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .send_traffic => |a| blk: {
                const frame = try wire.encodeTrafficFrame(
                    gpa,
                    a.traffic.path,
                    a.traffic.from,
                    &a.traffic.source,
                    &a.traffic.dest,
                    a.traffic.watermark,
                    a.traffic.payload,
                );
                break :blk .{ .peer_id = a.peer_id, .data = frame };
            },
            .deliver_traffic, .path_notify_callback => null,
        };
    }
};

/// Free a list of outgoing frames along with their data.
pub fn freeFrameList(gpa: std.mem.Allocator, list: *std.ArrayListUnmanaged(OutgoingFrame)) void {
    for (list.items) |f| gpa.free(f.data);
    list.deinit(gpa);
}

pub fn freeFrames(gpa: std.mem.Allocator, frames: []OutgoingFrame) void {
    for (frames) |f| gpa.free(f.data);
    gpa.free(frames);
}

fn freeDeliveredList(gpa: std.mem.Allocator, list: *std.ArrayListUnmanaged(DeliveredPayload)) void {
    for (list.items) |d| gpa.free(d.data);
    list.deinit(gpa);
}

pub fn freeDelivered(gpa: std.mem.Allocator, items: []DeliveredPayload) void {
    for (items) |d| gpa.free(d.data);
    gpa.free(items);
}

pub fn freeDiscovered(gpa: std.mem.Allocator, items: []PublicKey) void {
    gpa.free(items);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "core init and self key" {
    const gpa = testing.allocator;
    const id = crypto.Crypto.generate();
    const cfg = ironwood.Config.default();

    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();

    try testing.expectEqualSlices(u8, &id.public_key, &core.selfKey());
    try testing.expect(core.address.isValid());
    try testing.expect(core.subnet.isValid());
}

test "core add and remove peer" {
    const gpa = testing.allocator;
    const id = crypto.Crypto.generate();
    const cfg = ironwood.Config.default();

    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();

    const peer_key = [_]u8{0x55} ** 32;
    const added = try core.addPeer(peer_key, 0);
    defer freeFrames(gpa, added.frames);
    try testing.expectEqual(@as(PeerId, 1), added.handle.id);
    try testing.expect(added.frames.len > 0); // at least a sig_req frame

    const rm_frames = try core.removePeer(1, peer_key);
    defer freeFrames(gpa, rm_frames);
}

test "two cores exchange sig_req/sig_res via handleFrame" {
    const gpa = testing.allocator;
    const id_a = crypto.Crypto.generate();
    const id_b = crypto.Crypto.generate();
    const cfg = ironwood.Config.default();

    var core_a = try Core.init(gpa, id_a, cfg, "");
    defer core_a.deinit();
    var core_b = try Core.init(gpa, id_b, cfg, "");
    defer core_b.deinit();

    // Both sides add each other as a peer (id 1 on both sides for simplicity).
    const added_a = try core_a.addPeer(id_b.public_key, 0);
    defer freeFrames(gpa, added_a.frames);
    const added_b = try core_b.addPeer(id_a.public_key, 0);
    defer freeFrames(gpa, added_b.frames);

    // A's sig_req frame(s) go to B.
    var saw_ack = false;
    for (added_a.frames) |f| {
        const decoded = try wire.decodeFrame(f.data);
        if (decoded.packet_type != .proto_sig_req) continue;
        const result_b = try core_b.handleFrame(added_b.handle.id, &id_a.public_key, decoded);
        defer freeFrames(gpa, result_b.frames);
        defer freeDelivered(gpa, result_b.delivered);
        defer freeDiscovered(gpa, result_b.discovered_keys);
        for (result_b.frames) |bf| {
            const bdecoded = try wire.decodeFrame(bf.data);
            if (bdecoded.packet_type == .proto_sig_res) saw_ack = true;
            // Feed B's sig_res back to A.
            const result_a = try core_a.handleFrame(added_a.handle.id, &id_b.public_key, bdecoded);
            defer freeFrames(gpa, result_a.frames);
            defer freeDelivered(gpa, result_a.delivered);
            defer freeDiscovered(gpa, result_a.discovered_keys);
        }
    }
    try testing.expect(saw_ack);
}
