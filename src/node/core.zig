//! Node core: wires ironwood router, peers, and encrypted sessions together.
//!
//! This is the central coordinator that manages peer connections, dispatches
//! router actions, and demuxes incoming session traffic.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const crypto = ironwood.crypto;
const router_mod = ironwood.router;
const peers_mod = ironwood.peers;
const traffic_mod = ironwood.traffic;
const encrypted = ironwood.encrypted;

const PublicKey = crypto.PublicKey;
const Router = router_mod.Router;
const RouterAction = router_mod.RouterAction;
const PeerEntry = router_mod.PeerEntry;
const PeerId = router_mod.PeerId;
const Peers = peers_mod.Peers;
const PeerHandle = peers_mod.PeerHandle;
const SessionManager = encrypted.session.SessionManager;
const OutAction = encrypted.session.OutAction;
const GroupAuth = encrypted.GroupAuth;
const CurvePrivateKey = encrypted.CurvePrivateKey;

/// Session type bytes prepended to payloads.
pub const TYPE_SESSION_TRAFFIC: u8 = 0x01;
pub const TYPE_SESSION_PROTO: u8 = 0x02;

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

    /// Delivery queue for incoming traffic.
    delivery: traffic_mod.DeliveryQueue,

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
        const delivery = traffic_mod.DeliveryQueue.init(gpa, 65535);

        return Core{
            .gpa = gpa,
            .crypto = id,
            .router = rt,
            .peers = Peers.init(gpa),
            .sessions = SessionManager.init(gpa, ga),
            .curve_priv = curve_priv,
            .delivery = delivery,
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
        self.delivery.deinit();
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

    /// Handle a new peer connection. Adds the peer to the router and peers manager.
    pub fn addPeer(self: *Core, key: PublicKey, prio: u8) !PeerHandle {
        if (!self.isAllowed(&key)) return error.PeerNotAllowed;

        const handle = try self.peers.allocatePeer(key, prio);
        const entry = handle.toEntry();

        const actions = try self.router.addPeer(entry);
        defer router_mod.deinitActions(self.gpa, actions);

        return handle;
    }

    /// Remove a peer connection.
    pub fn removePeer(self: *Core, peer_id: PeerId, key: PublicKey) !void {
        const port = self.peers.removePeer(peer_id, &key) orelse return;
        const actions = try self.router.removePeer(peer_id, key, port);
        defer router_mod.deinitActions(self.gpa, actions);
    }

    /// Handle incoming encrypted data from a peer. Returns decrypted payloads.
    pub fn handlePeerData(
        self: *Core,
        from_key: *const PublicKey,
        data: []const u8,
    ) ![]struct { source: PublicKey, data: []u8 } {
        const session_actions = try self.sessions.handleData(
            from_key,
            data,
            &self.curve_priv,
            &self.crypto,
        );
        defer encrypted.session.deinitActions(self.gpa, session_actions);

        var results = std.ArrayListUnmanaged(struct { source: PublicKey, data: []u8 }){};
        errdefer {
            for (results.items) |r| self.gpa.free(r.data);
            results.deinit(self.gpa);
        }

        for (session_actions) |*action| {
            switch (action.*) {
                .deliver => |*d| {
                    // Copy and demux by session type byte
                    if (d.data.len > 0) {
                        const owned = try self.gpa.dupe(u8, d.data);
                        errdefer self.gpa.free(owned);
                        try results.append(self.gpa, .{ .source = from_key.*, .data = owned });
                    }
                },
                .send_to_inner => {},
            }
        }

        return results.toOwnedSlice(self.gpa);
    }

    /// Write traffic to a peer. Handles session encryption.
    pub fn writeTo(
        self: *Core,
        dest: *const PublicKey,
        data: []const u8,
        session_type: u8,
    ) !void {
        // Prepend session type byte
        var buf = try self.gpa.alloc(u8, 1 + data.len);
        defer self.gpa.free(buf);
        buf[0] = session_type;
        @memcpy(buf[1..], data);

        const actions = try self.sessions.writeTo(dest, buf, &self.crypto);
        defer encrypted.session.deinitActions(self.gpa, actions);
    }

    /// Send traffic through the ironwood network.
    pub fn sendTraffic(self: *Core, dest: *const PublicKey, payload: []const u8) !void {
        const pkt = traffic_mod.TrafficPacket.init(self.crypto.public_key, dest.*, try self.gpa.dupe(u8, payload));
        const actions = try self.router.sendTraffic(pkt);
        defer router_mod.deinitActions(self.gpa, actions);
    }

    /// Run periodic maintenance: expire old infos, refresh tree, cleanup sessions.
    pub fn maintenance(self: *Core) !void {
        const actions = try self.router.doMaintenance();
        defer router_mod.deinitActions(self.gpa, actions);

        try self.router.expireInfos();
        self.sessions.cleanupExpired();
    }

    /// Get the router's own public key.
    pub fn selfKey(self: *const Core) PublicKey {
        return self.router.selfKey();
    }
};

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
    const handle = try core.addPeer(peer_key, 0);
    try testing.expectEqual(@as(PeerId, 1), handle.id);

    try core.removePeer(1, peer_key);
}
