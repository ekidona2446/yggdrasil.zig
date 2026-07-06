//! Async TCP transport for Yggdrasil peer links, built on libxev.
//!
//! Handles: outbound dialing (with DNS resolution + reconnect/backoff),
//! inbound listening/accepting, the version-metadata handshake, and framed
//! read/write of ironwood wire messages, feeding decoded frames into
//! `Core.handleFrame` and flushing the resulting `OutgoingFrame`s back out.

const std = @import("std");
const xev = @import("xev");
const ironwood = @import("ironwood");
const node = @import("node.zig");
const dns = @import("dns.zig");
const tls_wolfssl = @import("tls_wolfssl.zig");

const Core = node.core.Core;
const Metadata = node.version.Metadata;
const PublicKey = ironwood.PublicKey;
const PeerId = ironwood.router.PeerId;
const wire = ironwood.wire;
const TlsConn = tls_wolfssl.TlsConn;

pub const HANDSHAKE_TIMEOUT_NS: u64 = 10 * std.time.ns_per_s;
pub const DEFAULT_BACKOFF_LIMIT_NS: u64 = 4096 * std.time.ns_per_s;
pub const MINIMUM_BACKOFF_NS: u64 = 1 * std.time.ns_per_s;
pub const READ_BUF_SIZE: usize = 65536;
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

/// How often to check whether a keepalive is due / a reply has timed out.
pub const KEEPALIVE_TICK_MS: u64 = 250;
/// After receiving non-keepalive traffic, send a keepalive (acknowledging
/// we're alive) if we haven't sent anything ourselves within this long.
/// Matches the reference implementation's `peerKeepAliveDelay`.
pub const PEER_KEEPALIVE_DELAY_NS: u64 = 1 * std.time.ns_per_s;
/// After sending non-keepalive traffic, drop the connection if we don't
/// receive *any* reply (even just a keepalive) within this long. Matches
/// the reference implementation's `peerTimeout`. Note this is NOT a general
/// idle timeout -- a quiet connection with no traffic in either direction
/// is never timed out, exactly like the reference.
pub const PEER_TIMEOUT_NS: u64 = 4 * std.time.ns_per_s;

fn monotonicNs() u64 {
    return @import("util").time.monotonicNanos();
}

/// Options parsed out of (or supplied alongside) a peer URI.
pub const LinkOptions = struct {
    priority: u8 = 0,
    password: []const u8 = &.{},
    max_backoff_ns: u64 = DEFAULT_BACKOFF_LIMIT_NS,
    persistent: bool = true,
    /// Whether to wrap this link in a real TLS 1.3 session (set for
    /// "tls://" peer/listener URIs, unset for "tcp://").
    use_tls: bool = false,
    /// Optional TLS SNI hostname override (client-side only). Falls back to
    /// the dialed hostname when null and `use_tls` is set.
    tls_sni: ?[]const u8 = null,
};

fn logInfo(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[ygg] " ++ fmt ++ "\n", args);
}

// ---------------------------------------------------------------------------
// Peer URI parsing (tcp://host:port, tls://host:port). "tls" wraps the same
// underlying TCP byte stream in a real TLS 1.3 session via wolfSSL (see
// tls_wolfssl.zig), with every node presenting a self-signed certificate
// bound to its own Ed25519 identity key -- peer *authentication* still
// happens one layer up, in the signed ironwood metadata handshake, exactly
// like the reference implementations; TLS here adds transport
// confidentiality/integrity and SNI support for traversing SNI-aware
// middleboxes.
// ---------------------------------------------------------------------------

pub const ParsedURI = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
};

pub fn parsePeerURI(uri: []const u8) !ParsedURI {
    const scheme_end = std.mem.indexOf(u8, uri, "://") orelse return error.InvalidURI;
    const scheme = uri[0..scheme_end];
    const rest = uri[scheme_end + 3 ..];
    const addr_part = if (std.mem.indexOfScalar(u8, rest, '?')) |qpos| rest[0..qpos] else rest;
    const hp = try extractHostPort(addr_part);
    return .{ .scheme = scheme, .host = hp.host, .port = hp.port };
}

const HostPort = struct { host: []const u8, port: u16 };

fn extractHostPort(addr_part: []const u8) !HostPort {
    if (addr_part.len == 0) return error.InvalidURI;
    if (addr_part[0] == '[') {
        const closing = std.mem.indexOfScalar(u8, addr_part, ']') orelse return error.InvalidURI;
        const after_bracket = addr_part[closing + 1 ..];
        if (after_bracket.len == 0 or after_bracket[0] != ':') return error.InvalidURI;
        const port_str = after_bracket[1..];
        return .{ .host = addr_part[1..closing], .port = try std.fmt.parseInt(u16, port_str, 10) };
    } else {
        const colon = std.mem.lastIndexOfScalar(u8, addr_part, ':') orelse return error.InvalidURI;
        const port_str = addr_part[colon + 1 ..];
        return .{ .host = addr_part[0..colon], .port = try std.fmt.parseInt(u16, port_str, 10) };
    }
}

/// One entry in a `PeerConn`'s outbound write queue: the raw bytes to send
/// on the wire (post-encryption, for TLS links) plus, if these bytes
/// correspond to exactly one decoded ironwood wire frame, its packet type
/// (used for keepalive/timeout bookkeeping in `onWrite`).
const WriteItem = struct {
    data: []u8,
    packet_type: ?wire.PacketType,
};

// ---------------------------------------------------------------------------
// PeerConn: one TCP connection to/from a peer, post-handshake
// ---------------------------------------------------------------------------

const PeerConn = struct {
    manager: *NetworkManager,
    tcp: xev.TCP,
    peer_id: PeerId = 0,
    peer_key: PublicKey = [_]u8{0} ** 32,
    /// Intrusive list node embedded directly (no separate allocation).
    list_node: std.DoublyLinkedList.Node = .{},

    // Read state: growable buffer holding not-yet-fully-parsed bytes (always
    // *decrypted* plaintext -- the ironwood handshake/wire-frame parser
    // never sees raw TLS ciphertext).
    read_buf: std.ArrayListUnmanaged(u8) = .empty,
    read_scratch: [READ_BUF_SIZE]u8 = undefined,
    read_completion: xev.Completion = undefined,

    // TLS state (only set for "tls://" links; null means plain TCP).
    use_tls: bool = false,
    tls: ?*TlsConn = null,
    tls_handshake_done: bool = false,
    /// Priority/password to use for the *ironwood* Metadata handshake, sent
    /// once the TLS handshake finishes (for plain TCP links this is used
    /// immediately in `spawnConn` instead). Slices here are assumed to
    /// outlive the connection, matching how `LinkOptions.password` is
    /// already used elsewhere (CLI args / long-lived URI-derived strings).
    pending_options: LinkOptions = .{},

    // Write state: a simple serial queue (one write in flight at a time) --
    // sufficient for our moderate traffic volumes and much simpler than
    // libxev's intrusive WriteQueue to get right across zig 0.16 API churn.
    // Each item carries the *raw* bytes actually written to the socket
    // (ciphertext, for TLS links) plus the logical ironwood packet type (if
    // any) for keepalive/timeout bookkeeping -- decided at queue time,
    // before encryption, since ciphertext can't be decoded back into a
    // wire frame the way plaintext can.
    write_queue: std.ArrayListUnmanaged(WriteItem) = .empty,
    write_in_flight: bool = false,
    write_completion: xev.Completion = undefined,

    closing: bool = false,
    established: bool = false,

    /// Per-slot "is a libxev completion outstanding in this slot" flags. We
    /// must not free `PeerConn` until every slot that ever had a completion
    /// submitted against it has fired its callback for the last time --
    /// otherwise a completion that fires after `destroy()` reads/writes
    /// freed memory. This was a real use-after-free/segfault observed with
    /// 2+ simultaneous peers before this tracking was added: `closeConn`
    /// used to call `destroy()` synchronously from `onClose` while the read
    /// loop and keepalive timer could still be in flight (and `close()` was
    /// even reusing `write_completion`, clobbering an in-flight write).
    read_active: bool = false,
    keepalive_active: bool = false,
    close_active: bool = false,
    close_completion: xev.Completion = undefined,
    destroyed: bool = false,

    // Keepalive/timeout tracking (post-handshake only), modeled directly on
    // the reference ironwood `peerMonitor`:
    //   - `sent(pType)`: sending non-keepalive traffic arms a read deadline
    //     (we expect *some* reply, even just a keepalive); sending anything
    //     at all cancels any pending keepalive-send timer (no need to nudge
    //     an already-live connection).
    //   - `recv(pType)`: receiving anything clears the read deadline; if
    //     what we received was non-keepalive, arm a keepalive-send timer
    //     (the peer is expecting *some* reply from us).
    // Critically, an idle connection with no traffic in either direction
    // has NO deadline at all and will not be timed out -- this matches the
    // reference and was the root cause of one earlier bug where an
    // unconditional "idle too long" timeout tore down healthy connections.
    read_deadline_ns: ?u64 = null,
    keepalive_due_ns: ?u64 = null,
    keepalive_timer: xev.Timer = undefined,
    keepalive_completion: xev.Completion = undefined,

    // Outbound-only reconnect state (null for inbound connections).
    dial: ?*DialState = null,

    /// Destroy `self` iff we're closing and no slot has an outstanding
    /// completion anymore. Safe to call redundantly from multiple callback
    /// sites; the event loop is single-threaded so there's no real race,
    /// just sequential transitions, and `destroyed` guards against any
    /// accidental double free.
    fn maybeDestroy(self: *PeerConn) void {
        if (!self.closing or self.destroyed) return;
        if (self.read_active or self.write_in_flight or self.keepalive_active or self.close_active) return;
        self.destroyed = true;
        self.destroy();
    }

    fn destroy(self: *PeerConn) void {
        const gpa = self.manager.gpa;
        self.read_buf.deinit(gpa);
        for (self.write_queue.items) |w| gpa.free(w.data);
        self.write_queue.deinit(gpa);
        self.keepalive_timer.deinit();
        if (self.tls) |t| t.deinit();
        gpa.destroy(self);
    }
};

const DialState = struct {
    manager: *NetworkManager,
    host: []u8,
    port: u16,
    options: LinkOptions,
    backoff_ns: u64,
    cancelled: bool = false,
    timer: xev.Timer,
    timer_completion: xev.Completion = undefined,
    connect_completion: xev.Completion = undefined,
    tcp: xev.TCP = undefined,
};

// ---------------------------------------------------------------------------
// TLS state: shared wolfSSL contexts + our identity certificate
// ---------------------------------------------------------------------------

const TlsState = struct {
    client_ctx: *tls_wolfssl.WOLFSSL_CTX,
    server_ctx: *tls_wolfssl.WOLFSSL_CTX,
    identity: tls_wolfssl.IdentityCert,
};

// ---------------------------------------------------------------------------
// NetworkManager
// ---------------------------------------------------------------------------

pub const NetworkManager = struct {
    gpa: std.mem.Allocator,
    loop: *xev.Loop,
    core: *Core,
    our_id: ironwood.Crypto,
    conns: std.DoublyLinkedList = .{},
    listeners: std.ArrayListUnmanaged(*ListenerState) = .empty,
    dials: std.ArrayListUnmanaged(*DialState) = .empty,
    /// Fired whenever a peer's session delivers a decrypted app payload.
    on_deliver: ?*const fn (ud: ?*anyopaque, source: *const PublicKey, data: []const u8) void = null,
    on_deliver_ud: ?*anyopaque = null,
    /// Fired whenever the router discovers/confirms a path to a key (used
    /// to refresh TUN's address/subnet -> key cache and flush buffered
    /// outbound packets).
    on_discover: ?*const fn (ud: ?*anyopaque, key: *const PublicKey) void = null,
    on_discover_ud: ?*anyopaque = null,
    /// Fired whenever the tree topology changes materially (new peer up/down).
    stop: bool = false,

    /// wolfSSL contexts + our self-signed identity certificate, created
    /// lazily on first TLS use (most nodes never dial/listen on "tls://" at
    /// all, so we avoid the wolfSSL_Init()/cert-gen cost otherwise).
    tls_state: ?TlsState = null,

    pub fn init(gpa: std.mem.Allocator, loop: *xev.Loop, core: *Core, our_id: ironwood.Crypto) NetworkManager {
        return .{ .gpa = gpa, .loop = loop, .core = core, .our_id = our_id };
    }

    /// Lazily initialize wolfSSL + generate our TLS identity certificate
    /// (bound to `our_id`'s Ed25519 key) the first time a "tls://" peer or
    /// listener is configured.
    fn ensureTlsState(self: *NetworkManager) !*TlsState {
        if (self.tls_state) |*s| return s;

        try tls_wolfssl.globalInit();
        errdefer tls_wolfssl.globalDeinit();

        var key_hex_buf: [64]u8 = undefined;
        const key_hex = std.fmt.bufPrint(&key_hex_buf, "{x}", .{self.our_id.public_key}) catch unreachable;

        var ident = try tls_wolfssl.generateIdentityCert(self.gpa, self.our_id.key_pair.secret_key.seed(), key_hex);
        errdefer ident.deinit(self.gpa);

        const client_ctx = try tls_wolfssl.newClientCtx();
        errdefer tls_wolfssl.freeCtx(client_ctx);
        try tls_wolfssl.configureIdentity(client_ctx, ident.cert_der, ident.key_der);
        tls_wolfssl.installMemoryIO(client_ctx);

        const server_ctx = try tls_wolfssl.newServerCtx();
        errdefer tls_wolfssl.freeCtx(server_ctx);
        try tls_wolfssl.configureIdentity(server_ctx, ident.cert_der, ident.key_der);
        tls_wolfssl.installMemoryIO(server_ctx);

        self.tls_state = .{ .client_ctx = client_ctx, .server_ctx = server_ctx, .identity = ident };
        return &self.tls_state.?;
    }

    pub fn deinit(self: *NetworkManager) void {
        var it = self.conns.first;
        while (it) |n| {
            const next = n.next;
            it = next;
        }
        for (self.listeners.items) |l| self.gpa.destroy(l);
        self.listeners.deinit(self.gpa);
        if (self.tls_state) |*s| {
            tls_wolfssl.freeCtx(s.client_ctx);
            tls_wolfssl.freeCtx(s.server_ctx);
            s.identity.deinit(self.gpa);
            tls_wolfssl.globalDeinit();
        }
        for (self.dials.items) |d| {
            self.gpa.free(d.host);
            self.gpa.destroy(d);
        }
        self.dials.deinit(self.gpa);
    }

    // -----------------------------------------------------------------
    // Frame flushing: push Core-produced OutgoingFrame(s) to peer sockets
    // -----------------------------------------------------------------

    fn findConnByPeerId(self: *NetworkManager, peer_id: PeerId) ?*PeerConn {
        var it = self.conns.first;
        while (it) |n| : (it = n.next) {
            const conn: *PeerConn = @fieldParentPtr("list_node", n);
            if (conn.peer_id == peer_id and conn.established) return conn;
        }
        return null;
    }

    /// Send frames produced by Core to their target peer connections.
    /// Consumes (frees) the frames.
    pub fn flushFrames(self: *NetworkManager, frames: []node.core.OutgoingFrame) void {
        for (frames) |f| {
            if (self.findConnByPeerId(f.peer_id)) |conn| {
                queueWrite(conn, f.data); // transfers ownership of f.data
            } else {
                self.gpa.free(f.data);
            }
        }
        self.gpa.free(frames);
    }

    pub fn deliverPayloads(self: *NetworkManager, items: []node.core.DeliveredPayload) void {
        for (items) |d| {
            if (self.on_deliver) |cb| cb(self.on_deliver_ud, &d.source, d.data);
            self.gpa.free(d.data);
        }
        self.gpa.free(items);
    }

    pub fn notifyDiscovered(self: *NetworkManager, keys: []PublicKey) void {
        for (keys) |*k| {
            if (self.on_discover) |cb| cb(self.on_discover_ud, k);
        }
        self.gpa.free(keys);
    }

    // -----------------------------------------------------------------
    // Outbound dialing with DNS + exponential backoff
    // -----------------------------------------------------------------

    pub fn addOutboundPeer(self: *NetworkManager, uri: []const u8, options_in: LinkOptions) !void {
        const parsed = try parsePeerURI(uri);
        const host_dup = try self.gpa.dupe(u8, parsed.host);
        errdefer self.gpa.free(host_dup);

        var options = options_in;
        options.use_tls = std.mem.eql(u8, parsed.scheme, "tls");

        const dial = try self.gpa.create(DialState);
        dial.* = .{
            .manager = self,
            .host = host_dup,
            .port = parsed.port,
            .options = options,
            .backoff_ns = MINIMUM_BACKOFF_NS,
            .timer = try xev.Timer.init(),
        };
        try self.dials.append(self.gpa, dial);
        self.attemptDial(dial);
    }

    fn attemptDial(self: *NetworkManager, dial: *DialState) void {
        _ = self;
        if (dial.cancelled) return;
        // Resolve on the calling thread. This blocks the event loop briefly,
        // which is acceptable for the modest number of configured peers a
        // Yggdrasil node typically has (a handful to a few dozen).
        const addrs = dns.resolve(dial.manager.gpa, dial.host, dial.port) catch |err| {
            logInfo("resolve {s}:{d} failed: {}", .{ dial.host, dial.port, err });
            scheduleRedial(dial);
            return;
        };
        defer dial.manager.gpa.free(addrs);
        if (addrs.len == 0) {
            scheduleRedial(dial);
            return;
        }
        const addr = addrs[0];

        dial.tcp = xev.TCP.init(addr) catch |err| {
            logInfo("socket() failed for {s}:{d}: {}", .{ dial.host, dial.port, err });
            scheduleRedial(dial);
            return;
        };
        dial.tcp.connect(dial.manager.loop, &dial.connect_completion, addr, DialState, dial, onConnectComplete);
    }

    fn onConnectComplete(ud: ?*DialState, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, r: xev.ConnectError!void) xev.CallbackAction {
        _ = loop;
        _ = c;
        const dial = ud.?;
        if (dial.cancelled) return .disarm;
        r catch |err| {
            logInfo("connect to {s}:{d} failed: {}", .{ dial.host, dial.port, err });
            scheduleRedial(dial);
            return .disarm;
        };
        dial.backoff_ns = MINIMUM_BACKOFF_NS; // reset on success
        dial.manager.spawnConn(tcp, dial.options, dial) catch |err| {
            logInfo("spawnConn failed: {}", .{err});
        };
        return .disarm;
    }

    fn scheduleRedial(dial: *DialState) void {
        if (dial.cancelled) return;
        const wait_ns = dial.backoff_ns;
        dial.backoff_ns = @min(dial.backoff_ns * 2, dial.options.max_backoff_ns);
        const wait_ms: u64 = wait_ns / std.time.ns_per_ms;
        dial.timer.run(dial.manager.loop, &dial.timer_completion, wait_ms, DialState, dial, onRedialTimer);
    }

    fn onRedialTimer(ud: ?*DialState, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = r catch {};
        const dial = ud.?;
        if (dial.cancelled) return .disarm;
        dial.manager.attemptDial(dial);
        return .disarm;
    }

    // -----------------------------------------------------------------
    // Inbound listening
    // -----------------------------------------------------------------

    pub fn addListener(self: *NetworkManager, uri: []const u8) !void {
        const parsed = try parsePeerURI(uri);
        const addrs = try dns.resolve(self.gpa, parsed.host, parsed.port);
        defer self.gpa.free(addrs);
        if (addrs.len == 0) return error.NoAddresses;
        const addr = addrs[0];

        const listener = try self.gpa.create(ListenerState);
        listener.* = .{ .manager = self, .tcp = try xev.TCP.init(addr), .use_tls = std.mem.eql(u8, parsed.scheme, "tls") };
        try listener.tcp.bind(addr);
        try listener.tcp.listen(128);
        try self.listeners.append(self.gpa, listener);
        listener.tcp.accept(self.loop, &listener.accept_completion, ListenerState, listener, onAccept);
        logInfo("listening on {f} (tls={})", .{ addr, listener.use_tls });
    }

    fn onAccept(ud: ?*ListenerState, loop: *xev.Loop, c: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
        _ = c;
        const listener = ud.?;
        const tcp = r catch |err| {
            logInfo("accept error: {}", .{err});
            listener.tcp.accept(loop, &listener.accept_completion, ListenerState, listener, onAccept);
            return .disarm;
        };
        listener.manager.spawnConn(tcp, .{ .persistent = false, .use_tls = listener.use_tls }, null) catch |err| {
            logInfo("spawnConn (inbound) failed: {}", .{err});
        };
        // Re-arm the listener for the next incoming connection.
        listener.tcp.accept(loop, &listener.accept_completion, ListenerState, listener, onAccept);
        return .disarm;
    }

    // -----------------------------------------------------------------
    // Connection setup: handshake then enter frame read loop
    // -----------------------------------------------------------------

    fn spawnConn(self: *NetworkManager, tcp: xev.TCP, options: LinkOptions, dial: ?*DialState) !void {
        const conn = try self.gpa.create(PeerConn);
        conn.* = .{
            .manager = self,
            .tcp = tcp,
            .dial = dial,
            .keepalive_timer = try xev.Timer.init(),
            .use_tls = options.use_tls,
            .pending_options = options,
        };
        self.conns.append(&conn.list_node);

        if (options.use_tls) {
            const state = try self.ensureTlsState();
            const is_server = (dial == null);
            const ctx = if (is_server) state.server_ctx else state.client_ctx;
            const sni = if (is_server) null else (options.tls_sni orelse if (dial) |d| d.host else null);
            conn.tls = try TlsConn.init(self.gpa, ctx, sni);
            // Kick the handshake off; any resulting ciphertext is flushed
            // by `pumpTlsHandshake`. The ironwood Metadata handshake is
            // sent only once the TLS handshake itself completes (see
            // `pumpTlsHandshake`).
            try self.pumpTlsHandshake(conn, is_server);
        } else {
            // Plain TCP: send our ironwood handshake metadata immediately;
            // queueWrite handles the async write via the same path used
            // for post-handshake frames.
            const meta = Metadata.init(self.our_id.public_key, options.priority);
            const msg = try meta.encode(&self.our_id, options.password, self.gpa);
            queueWrite(conn, msg);
        }

        // Kick off the read loop; handshake bytes are parsed by
        // `tryParseHandshake` before we switch to wire-frame parsing.
        conn.read_active = true;
        conn.tcp.read(self.loop, &conn.read_completion, .{ .slice = &conn.read_scratch }, PeerConn, conn, onRead);

        // Kick off the keepalive/timeout tick for this connection.
        conn.keepalive_active = true;
        conn.keepalive_timer.run(self.loop, &conn.keepalive_completion, KEEPALIVE_TICK_MS, PeerConn, conn, onKeepaliveTick);
    }

    /// Drive the TLS handshake state machine for `conn` one step, flushing
    /// any resulting ciphertext to the raw socket. Once wolfSSL reports the
    /// handshake finished, sends the ironwood Metadata handshake over the
    /// now-encrypted channel.
    fn pumpTlsHandshake(self: *NetworkManager, conn: *PeerConn, is_server: bool) !void {
        const tls = conn.tls orelse return;
        const result = tls.pumpHandshake(is_server);
        if (tls.hasPendingCiphertext()) {
            const bytes = try tls.drainCiphertext();
            queueRawWrite(conn, bytes);
        }
        switch (result) {
            .fatal, .closed => return error.TlsHandshakeFailed,
            .want_read, .want_write => {}, // wait for more socket I/O
            .ok => {
                if (tls.isHandshakeDone() and !conn.tls_handshake_done) {
                    conn.tls_handshake_done = true;
                    const meta = Metadata.init(self.our_id.public_key, conn.pending_options.priority);
                    const msg = try meta.encode(&self.our_id, conn.pending_options.password, self.gpa);
                    queueWrite(conn, msg); // encrypted via conn.tls automatically
                }
            },
        }
    }

    fn onKeepaliveTick(ud: ?*PeerConn, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const conn = ud.?;
        if (conn.closing) {
            conn.keepalive_active = false;
            conn.maybeDestroy();
            return .disarm;
        }
        const now = monotonicNs();

        // Read deadline: only armed while we're waiting on a reply to
        // non-keepalive traffic we sent (see `onWritten`/`onFrameReceived`).
        if (conn.read_deadline_ns) |deadline| {
            if (now >= deadline) {
                logInfo("peer {x} timed out waiting for a reply", .{conn.peer_key});
                conn.keepalive_active = false;
                conn.manager.closeConn(conn);
                return .disarm;
            }
        }
        // Keepalive-send due: only armed after receiving non-keepalive
        // traffic that we haven't yet acknowledged with a reply of our own.
        if (conn.keepalive_due_ns) |due| {
            if (now >= due) {
                conn.keepalive_due_ns = null;
                const frame = wire.encodeFrame(conn.manager.gpa, .keep_alive, &.{}) catch null;
                if (frame) |f| queueWrite(conn, f);
            }
        }
        conn.keepalive_timer.run(loop, c, KEEPALIVE_TICK_MS, PeerConn, conn, onKeepaliveTick);
        return .disarm;
    }

    /// Called whenever we finish sending a frame of type `pType` to `conn`.
    /// Mirrors `peerMonitor.sent`: non-keepalive traffic arms a read
    /// deadline (we expect some reply); any send cancels a pending
    /// keepalive-send timer (no need to nudge a connection we're actively
    /// using).
    fn onFrameSent(conn: *PeerConn, ptype: wire.PacketType) void {
        conn.keepalive_due_ns = null;
        switch (ptype) {
            .dummy, .keep_alive => {},
            else => {
                if (conn.read_deadline_ns == null) {
                    conn.read_deadline_ns = monotonicNs() + PEER_TIMEOUT_NS;
                }
            },
        }
    }

    /// Called whenever we finish receiving a frame of type `pType` from
    /// `conn`. Mirrors `peerMonitor.recv`: receiving anything clears our
    /// read deadline (the peer is alive); non-keepalive traffic means the
    /// peer expects a reply, so arm a keepalive-send timer unless one is
    /// already pending.
    fn onFrameReceived(conn: *PeerConn, ptype: wire.PacketType) void {
        conn.read_deadline_ns = null;
        switch (ptype) {
            .dummy, .keep_alive => {},
            else => {
                if (conn.keepalive_due_ns == null) {
                    conn.keepalive_due_ns = monotonicNs() + PEER_KEEPALIVE_DELAY_NS;
                }
            },
        }
    }

    fn closeConn(self: *NetworkManager, conn: *PeerConn) void {
        if (conn.closing) return;
        conn.closing = true;
        if (conn.established) {
            if (self.core.removePeer(conn.peer_id, conn.peer_key)) |frames| {
                self.flushFrames(frames);
            } else |_| {}
            logInfo("peer disconnected: {x}", .{conn.peer_key});
        }
        self.conns.remove(&conn.list_node);
        conn.close_active = true;
        conn.tcp.close(self.loop, &conn.close_completion, PeerConn, conn, onClose);
        // Cancel the keepalive timer so it doesn't keep firing (and holding
        // the connection alive) after close; its callback will still run
        // once (with error.Canceled or similar) to clear `keepalive_active`.
    }

    fn onClose(ud: ?*PeerConn, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, r: xev.CloseError!void) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = tcp;
        _ = r catch {};
        const conn = ud.?;
        conn.close_active = false;
        if (conn.dial) |dial| {
            if (dial.options.persistent and !dial.cancelled) {
                scheduleRedial(dial);
            }
        }
        conn.maybeDestroy();
        return .disarm;
    }

    // -----------------------------------------------------------------
    // Read path
    // -----------------------------------------------------------------

    fn onRead(ud: ?*PeerConn, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, buf: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
        _ = c;
        _ = tcp;
        const conn = ud.?;
        const n = r catch |err| {
            if (err != error.EOF) logInfo("read error: {}", .{err});
            conn.read_active = false;
            conn.manager.closeConn(conn);
            conn.maybeDestroy();
            return .disarm;
        };
        if (n == 0) {
            conn.read_active = false;
            conn.manager.closeConn(conn);
            conn.maybeDestroy();
            return .disarm;
        }
        const raw = buf.slice[0..n];

        if (conn.tls) |tls| {
            conn.manager.handleTlsReadable(conn, tls, raw) catch |err| {
                logInfo("tls processing error, dropping peer: {}", .{err});
                conn.read_active = false;
                conn.manager.closeConn(conn);
                conn.maybeDestroy();
                return .disarm;
            };
        } else {
            conn.read_buf.appendSlice(conn.manager.gpa, raw) catch {
                conn.read_active = false;
                conn.manager.closeConn(conn);
                conn.maybeDestroy();
                return .disarm;
            };
            conn.manager.processBuffered(conn) catch |err| {
                logInfo("frame processing error, dropping peer: {}", .{err});
                conn.read_active = false;
                conn.manager.closeConn(conn);
                conn.maybeDestroy();
                return .disarm;
            };
        }

        if (conn.closing) {
            conn.read_active = false;
            conn.maybeDestroy();
            return .disarm;
        }
        // Re-arm the read.
        conn.tcp.read(loop, &conn.read_completion, .{ .slice = &conn.read_scratch }, PeerConn, conn, onRead);
        return .disarm;
    }

    /// Feed raw ciphertext just read from the socket into `conn`'s TLS
    /// session. While the handshake is still in progress, drives it
    /// forward (flushing any resulting handshake ciphertext back out).
    /// Once established, decrypts as much application-layer plaintext as
    /// is available into `conn.read_buf` and hands it to the normal
    /// ironwood handshake/wire-frame parser via `processBuffered`.
    fn handleTlsReadable(self: *NetworkManager, conn: *PeerConn, tls: *TlsConn, raw: []const u8) !void {
        try tls.feedCiphertext(raw);

        if (!tls.isHandshakeDone()) {
            const is_server = (conn.dial == null);
            try self.pumpTlsHandshake(conn, is_server);
            if (!tls.isHandshakeDone()) return; // still handshaking
        }

        var scratch: [READ_BUF_SIZE]u8 = undefined;
        while (true) {
            const outcome = tls.readPlaintext(&scratch);
            switch (outcome) {
                .data => |n| {
                    if (n == 0) break;
                    try conn.read_buf.appendSlice(self.gpa, scratch[0..n]);
                },
                .result => |r| switch (r) {
                    .want_read => break, // no more plaintext available right now
                    .closed => return error.TlsClosed,
                    .fatal => return error.TlsFatal,
                    else => break,
                },
            }
        }
        try self.processBuffered(conn);
    }

    /// Consume as many complete units (handshake message, then wire frames)
    /// as are available in `conn.read_buf`.
    fn processBuffered(self: *NetworkManager, conn: *PeerConn) !void {
        if (!conn.established) {
            if (try self.tryParseHandshake(conn)) |consumed| {
                const remaining = conn.read_buf.items[consumed..];
                std.mem.copyForwards(u8, conn.read_buf.items[0..remaining.len], remaining);
                conn.read_buf.shrinkRetainingCapacity(remaining.len);
            } else {
                return; // need more bytes
            }
        }
        while (conn.established) {
            const decoded = wire.decodeFrame(conn.read_buf.items) catch |err| switch (err) {
                error.Decode => {
                    // Could be "not enough bytes yet" (decodeUvarint returns
                    // Decode both for malformed AND incomplete input at this
                    // layer) -- try to distinguish via a length probe.
                    if (isIncompleteFrame(conn.read_buf.items)) return;
                    return err;
                },
                else => return err,
            };
            if (decoded.consumed > MAX_MESSAGE_SIZE) return error.OversizedMessage;
            try self.dispatchFrame(conn, decoded);
            const remaining = conn.read_buf.items[decoded.consumed..];
            std.mem.copyForwards(u8, conn.read_buf.items[0..remaining.len], remaining);
            conn.read_buf.shrinkRetainingCapacity(remaining.len);
            if (conn.closing) return;
        }
    }

    fn dispatchFrame(self: *NetworkManager, conn: *PeerConn, decoded: wire.DecodedFrame) !void {
        onFrameReceived(conn, decoded.packet_type);
        switch (decoded.packet_type) {
            .proto_path_lookup, .proto_path_notify, .proto_path_broken, .traffic => {
                logInfo("dispatch {s} from {x}", .{ @tagName(decoded.packet_type), conn.peer_key });
            },
            else => {},
        }
        const result = try self.core.handleFrame(conn.peer_id, &conn.peer_key, decoded);
        self.flushFrames(result.frames);
        self.deliverPayloads(result.delivered);
        self.notifyDiscovered(result.discovered_keys);
    }

    /// Try to parse the fixed handshake format ("meta" + u16 len + body +
    /// sig) from the front of the buffer. Returns bytes consumed on success.
    fn tryParseHandshake(self: *NetworkManager, conn: *PeerConn) !?usize {
        const buf = conn.read_buf.items;
        if (buf.len < 6) return null;
        if (!std.mem.eql(u8, buf[0..4], "meta")) return error.BadHandshake;
        const body_len = std.mem.readInt(u16, buf[4..6][0..2], .big);
        if (body_len > 8192) return error.OversizedHandshake;
        const total = 6 + @as(usize, body_len);
        if (buf.len < total) return null;

        const peer_meta = Metadata.decode(buf[0..total], "", self.gpa) catch |err| {
            return err;
        };
        if (!peer_meta.check()) return error.IncompatibleVersion;
        if (std.mem.eql(u8, &peer_meta.public_key, &self.our_id.public_key)) {
            return error.ConnectedToSelf;
        }
        if (!self.core.isAllowed(&peer_meta.public_key)) return error.PeerNotAllowed;

        conn.peer_key = peer_meta.public_key;
        var prio: u8 = peer_meta.priority;
        if (conn.dial) |dial| prio = @max(prio, dial.options.priority);

        const added = self.core.addPeer(peer_meta.public_key, prio) catch |err| {
            return err;
        };
        conn.peer_id = added.handle.id;
        conn.established = true;
        self.flushFrames(added.frames);
        logInfo("peer connected: {x} (id={d})", .{ conn.peer_key, conn.peer_id });
        return total;
    }

    // -----------------------------------------------------------------
    // Write path (serial queue: one write in flight at a time)
    // -----------------------------------------------------------------

    /// Queue `data` for writing. `data` must be plaintext -- an ironwood
    /// handshake message or wire frame (its packet type, if decodable, is
    /// recorded for keepalive/timeout bookkeeping). For TLS links, `data`
    /// is encrypted via wolfSSL first and only the resulting ciphertext is
    /// queued for the raw socket; `data` itself is freed either way.
    fn queueWriteImpl(conn: *PeerConn, data: []u8) void {
        const packet_type: ?wire.PacketType = if (wire.decodeFrame(data)) |decoded| decoded.packet_type else |_| null;

        if (conn.tls) |tls| {
            const result = tls.writePlaintext(data);
            conn.manager.gpa.free(data);
            switch (result) {
                .fatal, .closed => {
                    conn.manager.closeConn(conn);
                    return;
                },
                else => {},
            }
            if (tls.hasPendingCiphertext()) {
                const bytes = tls.drainCiphertext() catch return;
                queueRawWriteTyped(conn, bytes, packet_type);
            }
            return;
        }

        queueRawWriteTyped(conn, data, packet_type);
    }

    /// Queue already-final wire bytes (ciphertext, or plaintext for
    /// non-TLS links) directly for the socket, tagged with an optional
    /// logical packet type for keepalive bookkeeping.
    fn queueRawWriteTyped(conn: *PeerConn, data: []u8, packet_type: ?wire.PacketType) void {
        conn.write_queue.append(conn.manager.gpa, .{ .data = data, .packet_type = packet_type }) catch {
            conn.manager.gpa.free(data);
            return;
        };
        pumpWrite(conn);
    }

    fn pumpWrite(conn: *PeerConn) void {
        if (conn.write_in_flight or conn.closing) return;
        if (conn.write_queue.items.len == 0) return;
        const data = conn.write_queue.items[0].data;
        conn.write_in_flight = true;
        conn.tcp.write(conn.manager.loop, &conn.write_completion, .{ .slice = data }, PeerConn, conn, onWrite);
    }

    fn onWrite(ud: ?*PeerConn, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, buf: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = tcp;
        const conn = ud.?;
        const n = r catch |err| {
            logInfo("write error: {}", .{err});
            conn.write_in_flight = false;
            conn.manager.closeConn(conn);
            conn.maybeDestroy();
            return .disarm;
        };
        const full = buf.slice;
        if (n < full.len) {
            // Partial write: shrink the queued buffer in place and retry.
            const remaining_data = conn.manager.gpa.dupe(u8, full[n..]) catch {
                conn.write_in_flight = false;
                conn.manager.closeConn(conn);
                conn.maybeDestroy();
                return .disarm;
            };
            conn.manager.gpa.free(conn.write_queue.items[0].data);
            conn.write_queue.items[0].data = remaining_data;
            conn.write_in_flight = false;
            if (conn.closing) {
                conn.maybeDestroy();
                return .disarm;
            }
            pumpWrite(conn);
            return .disarm;
        }
        // Full write completed: note the packet type (for keepalive/timeout
        // bookkeeping) before freeing, then pop.
        if (conn.established) {
            if (conn.write_queue.items[0].packet_type) |ptype| onFrameSent(conn, ptype);
        }
        conn.manager.gpa.free(conn.write_queue.orderedRemove(0).data);
        conn.write_in_flight = false;
        if (conn.closing) {
            conn.maybeDestroy();
            return .disarm;
        }
        pumpWrite(conn);
        return .disarm;
    }

    // -----------------------------------------------------------------
    // Broadcast helpers
    // -----------------------------------------------------------------

    /// Run one maintenance tick and flush the results.
    pub fn runMaintenance(self: *NetworkManager) !void {
        const result = try self.core.maintenance();
        self.flushFrames(result.frames);
        self.deliverPayloads(result.delivered);
        self.notifyDiscovered(result.discovered_keys);
    }

    /// Number of currently-established peer connections.
    pub fn peerCount(self: *NetworkManager) usize {
        var count: usize = 0;
        var it = self.conns.first;
        while (it) |n| : (it = n.next) {
            const conn: *PeerConn = @fieldParentPtr("list_node", n);
            if (conn.established) count += 1;
        }
        return count;
    }
};

/// Queue plaintext `data` (encrypted first if the link is TLS).
fn queueWrite(conn: *PeerConn, data: []u8) void {
    NetworkManager.queueWriteImpl(conn, data);
}

/// Queue already-final bytes for the raw socket with no packet-type
/// association (used for TLS handshake ciphertext, which isn't an
/// ironwood wire frame at all).
fn queueRawWrite(conn: *PeerConn, data: []u8) void {
    NetworkManager.queueRawWriteTyped(conn, data, null);
}

/// Heuristic: does the buffer look like a frame header that simply hasn't
/// arrived in full yet, vs. genuinely malformed input? We treat any
/// `Decode` error from a buffer shorter than 10 bytes (max uvarint header)
/// as "incomplete", and otherwise as a real error, by re-parsing just the
/// length varint.
fn isIncompleteFrame(buf: []const u8) bool {
    const len_result = wire.decodeUvarint(buf) catch return true; // header itself incomplete
    const total = len_result.len + @as(usize, @intCast(len_result.value));
    return buf.len < total;
}

const ListenerState = struct {
    manager: *NetworkManager,
    tcp: xev.TCP,
    accept_completion: xev.Completion = undefined,
    use_tls: bool = false,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse peer uri tcp" {
    const parsed = try parsePeerURI("tcp://example.com:1234");
    try testing.expectEqualStrings("tcp", parsed.scheme);
    try testing.expectEqualStrings("example.com", parsed.host);
    try testing.expectEqual(@as(u16, 1234), parsed.port);
}

test "parse peer uri ipv6 literal" {
    const parsed = try parsePeerURI("tls://[::1]:9999");
    try testing.expectEqualStrings("tls", parsed.scheme);
    try testing.expectEqualStrings("::1", parsed.host);
    try testing.expectEqual(@as(u16, 9999), parsed.port);
}

test "parse peer uri with query string" {
    const parsed = try parsePeerURI("tcp://1.2.3.4:1337?key=abcd");
    try testing.expectEqualStrings("1.2.3.4", parsed.host);
    try testing.expectEqual(@as(u16, 1337), parsed.port);
}

test "isIncompleteFrame detects short buffers" {
    try testing.expect(isIncompleteFrame(&.{}));
    try testing.expect(isIncompleteFrame(&[_]u8{0x05})); // says 5 bytes follow, none present
    const full = try wire.encodeFrame(testing.allocator, .dummy, "hi");
    defer testing.allocator.free(full);
    try testing.expect(!isIncompleteFrame(full));
    try testing.expect(isIncompleteFrame(full[0 .. full.len - 1]));
}
