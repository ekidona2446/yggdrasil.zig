//! Async TCP transport for Yggdrasil peer links, built on libxev.
//!
//! Handles: outbound dialing (with DNS resolution + reconnect/backoff),
//! inbound listening/accepting, the version-metadata handshake, and framed
//! read/write of ironwood wire messages, feeding decoded frames into
//! `Core.handleFrame` and flushing the resulting `OutgoingFrame`s back out.

const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");
const ironwood = @import("ironwood");
const node = @import("node.zig");
const dns = @import("dns.zig");
const tls_wolfssl = @import("tls_wolfssl.zig");
const ws = @import("ws.zig");
const quic_mod = @import("quic.zig");
const unix_socket = @import("unix_socket.zig");
const socks = @import("socks.zig");

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
    /// Wrap the byte stream in RFC 6455 WebSocket frames (`ws://` / `wss://`).
    use_ws: bool = false,
    /// QUIC/UDP instead of TCP (`quic://`).
    use_quic: bool = false,
    /// Unix domain socket instead of TCP (`unix://`).
    use_unix: bool = false,
    /// Tunnel through a SOCKS5 proxy (`socks://`, `sockstls://`). The proxy is
    /// the URI's `host:port`; `socks_target` is the peer we ask it to reach,
    /// taken from the URI path like the reference does.
    use_socks: bool = false,
    socks_target: []const u8 = "",
    socks_user: []const u8 = "",
    socks_pass: []const u8 = "",
    /// HTTP path for the WebSocket upgrade (default `/`).
    ws_path: []const u8 = "/",
    /// Host header / SNI name for WebSocket/TLS (not necessarily an IP).
    ws_host: []const u8 = "",
    /// Pinned remote signing keys (`?key=HEX`, repeatable). When non-empty, a
    /// peer whose handshake carries a different key is rejected, exactly like
    /// the reference's `linkInfo.pinnedEd25519Keys`.
    pinned_keys: []const PublicKey = &.{},
    /// Normalised URI (query string stripped), as reported by `getPeers`.
    uri: []const u8 = "",
    /// Source interface for the link (`interface` in an admin `addPeer`). The
    /// reference uses it both to `SO_BINDTODEVICE` the socket and as half of the
    /// duplicate-link key; we honour the key (so `addPeer` with the same URI on a
    /// different interface is a new link, as in Go) but do not bind the socket --
    /// that needs `CAP_NET_RAW`, and the dial path has no socket-option hook yet.
    sintf: []const u8 = "",
};

/// Errors the reference's `links.add` can report for a malformed URI; the
/// admin `addPeer` handler surfaces the same strings.
/// Everything an admin-initiated peering change can fail with: the URI
/// handling in `LinkError` plus the allocation/parse failures the helpers
/// propagate. Kept as one named set so `admin.zig` (whose error set is
/// `LinkError || {...}`) can surface all of them with distinct messages.
pub const PeerOpError = LinkError || error{OutOfMemory};

/// `src/core/link.go`'s `linkError` constants, which is what the admin API
/// reports verbatim when a peering URI is rejected.
pub const LinkError = error{
    InvalidURI,
    UnknownScheme,
    PinnedKeyInvalid,
    PriorityInvalid,
    PasswordInvalid,
    MaxBackoffInvalid,
    UnsupportedSNI,
    PeerExists,
    PeerNotFound,
    ResolveFailed,
    NoSuitableIPs,
    ConnectFailed,
    ConnectedToSelf,
    NotSupported,
};

/// Percent-decode `s` into `out` (query-string values may be escaped).
fn percentDecode(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(gpa);
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch return LinkError.InvalidURI;
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch return error.InvalidURI;
            try buf.append(gpa, hi * 16 + lo);
            i += 3;
        } else if (c == '+') {
            try buf.append(gpa, ' ');
            i += 1;
        } else {
            try buf.append(gpa, c);
            i += 1;
        }
    }
    return buf.toOwnedSlice(gpa);
}

/// Parse the query string of a peer/listen URI into `LinkOptions`, matching the
/// reference's accepted keys: `key` (repeatable), `priority`, `password`,
/// `maxbackoff` and `sni`.
pub fn parseLinkQuery(gpa: std.mem.Allocator, uri: []const u8, base: LinkOptions) PeerOpError!LinkOptions {
    const qpos = std.mem.indexOfScalar(u8, uri, '?') orelse return base;
    var opts = base;
    const query = uri[qpos + 1 ..];

    var pinned = std.ArrayListUnmanaged(PublicKey).empty;
    errdefer pinned.deinit(gpa);

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const raw_key = pair[0..eq];
        const raw_val = pair[eq + 1 ..];
        const key = try percentDecode(gpa, raw_key);
        defer gpa.free(key);
        const val = try percentDecode(gpa, raw_val);
        defer gpa.free(val);

        if (std.mem.eql(u8, key, "key")) {
            if (val.len != 64) return LinkError.PinnedKeyInvalid;
            var pk: PublicKey = undefined;
            _ = std.fmt.hexToBytes(&pk, val) catch return LinkError.PinnedKeyInvalid;
            try pinned.append(gpa, pk);
        } else if (std.mem.eql(u8, key, "priority")) {
            const p = std.fmt.parseInt(u8, val, 10) catch return LinkError.PriorityInvalid;
            opts.priority = p;
        } else if (std.mem.eql(u8, key, "password")) {
            if (val.len > 64) return LinkError.PasswordInvalid; // blake2b.KeySize
            // The LinkOptions.password slice must outlive the link; the URI
            // text is owned by the config/CLI layer, so take a copy of the
            // decoded value owned by the manager.
            opts.password = try gpa.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "maxbackoff")) {
            const secs = std.fmt.parseInt(u64, val, 10) catch return LinkError.MaxBackoffInvalid;
            opts.max_backoff_ns = secs * std.time.ns_per_s;
        } else if (std.mem.eql(u8, key, "sni")) {
            opts.tls_sni = try gpa.dupe(u8, val);
        }
    }
    if (pinned.items.len > 0) opts.pinned_keys = try pinned.toOwnedSlice(gpa);
    return opts;
}

/// Strip scheme-query from a URI the way the reference's `urlForLinkInfo` does
/// (`u.RawQuery = ""` before `String()`).
pub fn normalizePeerUri(gpa: std.mem.Allocator, uri: []const u8) error{OutOfMemory}![]u8 {
    const q = std.mem.indexOfScalar(u8, uri, '?') orelse return gpa.dupe(u8, uri);
    return gpa.dupe(u8, uri[0..q]);
}

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
    path: []const u8,
    /// `user:password@` userinfo, as `url.URL.User` in the reference. Only
    /// `socks://` uses it (as proxy credentials); empty for every other scheme.
    user: []const u8 = "",
    pass: []const u8 = "",
};

pub fn parsePeerURI(uri: []const u8) LinkError!ParsedURI {
    // `url.Parse` accepts anything without a scheme; the *scheme* is checked
    // separately by the reference (`links.dialerFor`'s switch), so a missing or
    // unknown one reports "link schema unknown" rather than a parse error.
    const scheme_end = std.mem.indexOf(u8, uri, "://") orelse return error.UnknownScheme;
    const scheme = uri[0..scheme_end];
    const known = [_][]const u8{ "tcp", "tls", "unix", "ws", "wss", "quic", "socks", "sockstls" };
    var known_scheme = false;
    for (known) |k| {
        if (std.ascii.eqlIgnoreCase(scheme, k)) known_scheme = true;
    }
    if (!known_scheme) return error.UnknownScheme;
    const rest = uri[scheme_end + 3 ..];
    var addr_part = if (std.mem.indexOfScalar(u8, rest, '?')) |qpos| rest[0..qpos] else rest;

    // Userinfo precedes the host and ends at the last `@` *before* the path
    // (`socks://user:pass@proxy:1080/peer:1234`). It is not stripped by simple
    // prefix handling because the path may itself contain an `@`.
    var user: []const u8 = "";
    var pass: []const u8 = "";
    const head = if (std.mem.indexOfScalar(u8, addr_part, '/')) |slash| addr_part[0..slash] else addr_part;
    if (std.mem.lastIndexOfScalar(u8, head, '@')) |at| {
        const ui = head[0..at];
        if (std.mem.indexOfScalar(u8, ui, ':')) |colon| {
            user = ui[0..colon];
            pass = ui[colon + 1 ..];
        } else {
            user = ui;
        }
        addr_part = addr_part[at + 1 ..];
    }

    if (std.ascii.eqlIgnoreCase(scheme, "unix")) {
        // `unix:///path/to.sock` / `unix://@abstract` have no `host:port`;
        // the whole remainder is the socket path.
        if (addr_part.len == 0) return error.InvalidURI;
        return .{ .scheme = scheme, .host = addr_part, .port = 0, .path = "/", .user = user, .pass = pass };
    }
    const hp = try extractHostPort(addr_part);
    return .{ .scheme = scheme, .host = hp.host, .port = hp.port, .path = hp.path, .user = user, .pass = pass };
}

const HostPort = struct { host: []const u8, port: u16, path: []const u8 };

fn stripPath(hostport: []const u8) struct { hp: []const u8, path: []const u8 } {
    if (std.mem.indexOfScalar(u8, hostport, '/')) |s| {
        const path = hostport[s..];
        return .{ .hp = hostport[0..s], .path = if (path.len == 0) "/" else path };
    }
    return .{ .hp = hostport, .path = "/" };
}

/// Split `host:port` / `[v6host]:port` / `[v6host]:port/path`. A bad port is a
/// bad URI, so `parseInt`'s own errors are folded into `InvalidURI` -- that
/// keeps the whole URI parser's error set at exactly `LinkError`, which the
/// admin layer maps to Go's `unable to parse peering URI`.
fn extractHostPort(addr_part: []const u8) LinkError!HostPort {
    if (addr_part.len == 0) return error.InvalidURI;
    if (addr_part[0] == '[') {
        const closing = std.mem.indexOfScalar(u8, addr_part, ']') orelse return error.InvalidURI;
        const after_bracket = addr_part[closing + 1 ..];
        if (after_bracket.len == 0 or after_bracket[0] != ':') return error.InvalidURI;
        const split = stripPath(after_bracket[1..]);
        const port = std.fmt.parseInt(u16, split.hp, 10) catch return error.InvalidURI;
        return .{ .host = addr_part[1..closing], .port = port, .path = split.path };
    } else {
        // The path is split off *before* looking for the port colon: a
        // `socks://proxy:1080/peer:1234` URI has a colon inside its path, and
        // treating that one as the port separator would make the host
        // `proxy:1080/peer` (which then fails to resolve).
        const split = stripPath(addr_part);
        const colon = std.mem.lastIndexOfScalar(u8, split.hp, ':') orelse return error.InvalidURI;
        const port = std.fmt.parseInt(u16, split.hp[colon + 1 ..], 10) catch return error.InvalidURI;
        return .{ .host = split.hp[0..colon], .port = port, .path = split.path };
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

/// `setsockopt(2)` from ws2_32, for the Windows branch of setTcpNoDelay.
/// SOCKET is UINT_PTR, so `usize` is the right width on every supported
/// Windows ABI.
const win_setsockopt = if (builtin.os.tag == .windows) struct {
    extern "ws2_32" fn setsockopt(
        s: usize,
        level: i32,
        optname: i32,
        optval: ?*const anyopaque,
        optlen: i32,
    ) i32;
}.setsockopt else void;

/// IPPROTO_TCP and TCP_NODELAY are 6 and 1 in every <netinet/tcp.h> we target
/// (Linux, macOS, FreeBSD/OpenBSD/NetBSD) and in winsock2.h.
///
/// Zig's std does NOT give us the names portably: `std.posix.TCP` and
/// `std.posix.IPPROTO` are only defined for Linux and emscripten, and are
/// `void` everywhere else, so `std.posix.TCP.NODELAY` is a compile error on
/// macOS and the BSDs. Hence the literals.
const IPPROTO_TCP: u32 = 6;
const TCP_NODELAY: u32 = 1;

/// Turn off Nagle's algorithm on a link socket.
///
/// Go's `net` package sets TCP_NODELAY on every TCP connection it creates, so
/// yggdrasil-go never sees Nagle delays. We did not set it at all, and the
/// consequence was measurable rather than theoretical: ironwood's control
/// frames (sigReq/sigRes, announces, path lookups) are tiny, so Nagle holds
/// them until outstanding data is ACKed -- while the peer does the same under
/// delayed-ACK. That is the classic ~40 ms stall.
///
/// On a veth pair, one sigReq/sigRes round trip measured 20-56 ms between two
/// yggdrasil.zig nodes against 0.5 ms between two yggdrasil-go nodes. Because
/// the RTT feeds `Router.getCost`, and cost feeds parent selection, the stall
/// distorted routing decisions as well as the `getPeers` latency figure.
///
/// A failure here is not fatal: the link still works, only slower.
fn setTcpNoDelay(tcp: xev.TCP) void {
    var on: c_int = 1;
    if (builtin.os.tag == .windows) {
        // std.posix.setsockopt is a hard compile error on Windows ("use std.Io
        // instead"), and xev's fd there is a HANDLE rather than a socket_t.
        _ = win_setsockopt(
            @intFromPtr(tcp.fd),
            @intCast(IPPROTO_TCP),
            @intCast(TCP_NODELAY),
            &on,
            @sizeOf(c_int),
        );
    } else {
        std.posix.setsockopt(tcp.fd, IPPROTO_TCP, TCP_NODELAY, std.mem.asBytes(&on)) catch |err| {
            logInfo("setsockopt(TCP_NODELAY) failed: {}", .{err});
        };
    }
}

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
    use_ws: bool = false,
    ws_handshake_done: bool = false,
    ws_key_b64: [24]u8 = undefined,
    ws_accept_b64: [28]u8 = undefined,
    /// Raw HTTP/WebSocket bytes. After the RFC 6455 upgrade, incoming TCP/TLS
    /// bytes go here and are decoded into `read_buf` (ironwood plaintext).
    /// Mixing the two in one buffer is what dropped live `ws://` peers.
    ws_raw: std.ArrayListUnmanaged(u8) = .empty,
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

    // ---- admin-visible link state ---------------------------------------
    // The reference implementation wraps every peer connection in a
    // `linkConn` that counts bytes and records when the link came up, and
    // keeps the (query-string-stripped) peering URI as the link's identity;
    // all three are reported through the admin socket, so we track them here
    // rather than in the router, where they don't belong.

    /// Normalised peer URI (`tcp://host:port`, no query string) as it appears
    /// in `getPeers`' `remote` field. Empty (omitempty) until assigned.
    uri: []const u8 = "",
    /// True for connections we accepted rather than dialled.
    inbound: bool = false,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    /// Counters and timestamp as of the previous `snapshotPeers` call, used
    /// to derive the one-second-window rates the reference reports.
    rate_last_rx: u64 = 0,
    rate_last_tx: u64 = 0,
    rate_last_ns: u64 = 0,
    rx_rate: u64 = 0,
    tx_rate: u64 = 0,
    /// Guard so the dial reference is returned exactly once even if close is
    /// reached twice through different paths.
    dial_ref_released: bool = false,
    /// Set when the handshake completes, i.e. `uptime` in the admin output
    /// measures the *peering*, not the raw TCP connection (a connection that
    /// never completes a handshake has no uptime to report).
    up_ns: u64 = 0,
    /// Last link-level failure, surfaced as `last_error`/`last_error_time`.
    last_error: []const u8 = "",
    last_error_ns: u64 = 0,

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
    /// QUIC session (null for TCP/TLS/WS). When set, socket I/O goes through
    /// zquic instead of `tcp`.
    quic: ?*QuicLink = null,
    /// Inbound QUIC session (null except for accepted `quic://` listeners).
    /// When set, socket I/O goes through the shared zquic `Server` instead of
    /// `tcp`.
    quic_srv: ?*QuicSrvConn = null,

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
        self.ws_raw.deinit(gpa);
        if (self.uri.len > 0) gpa.free(self.uri);
        if (self.last_error.len > 0) gpa.free(self.last_error);
        for (self.write_queue.items) |w| gpa.free(w.data);
        self.write_queue.deinit(gpa);
        self.keepalive_timer.deinit();
        if (self.tls) |t| t.deinit();
        if (self.quic) |link| {
            link.tick.deinit();
            quic_mod.destroyClient(gpa, link.client);
            gpa.free(link.host);
            gpa.destroy(link);
        }
        gpa.destroy(self);
    }
};

const DialState = struct {
    manager: *NetworkManager,
    host: []u8,
    port: u16,
    /// Normalised URI (query string stripped) -- this is the identity the
    /// reference uses both for `getPeers`' `remote` field and for
    /// `removePeer` lookups.
    uri: []const u8 = "",
    options: LinkOptions,
    backoff_ns: u64,
    cancelled: bool = false,
    last_error: bool = false,
    /// How many things may still touch this dial: the dial table itself, any
    /// completion in flight (`connect_completion`, `timer_completion`) and
    /// each `PeerConn` spawned from it. `removeOutboundPeer` cannot simply
    /// `destroy()` the state -- the event loop may already hold a queued
    /// callback whose userdata points at it -- so teardown goes through
    /// `retireDial`/`releaseDialRef` and the memory is freed by whichever
    /// reference is dropped last.
    refs: usize = 1,
    retired: bool = false,
    timer: xev.Timer,
    timer_completion: xev.Completion = undefined,
    connect_completion: xev.Completion = undefined,
    tcp: xev.TCP = undefined,

    // ---- SOCKS5 handshake state (only used for `socks://` / `sockstls://`) --
    // The tunnel negotiation runs on the same socket before the ironwood
    // handshake does, so it needs its own completion slot: the connect
    // completion is already done by then, and `spawnConn`'s read/write slots
    // belong to the `PeerConn` that does not exist yet.
    socks_stage: SocksStage = .none,
    socks_completion: xev.Completion = undefined,
    /// Bytes already read for the stage currently in flight.
    socks_recv: std.ArrayListUnmanaged(u8) = .empty,
    /// Outgoing request bytes, which must outlive the write completion.
    socks_out: [socks_buf_len]u8 = undefined,
    socks_out_len: usize = 0,
    /// Scratch for the reply currently being read (`socks_recv` accumulates
    /// across reads, this is only the read window).
    socks_in: [socks_buf_len]u8 = undefined,
};

/// Buffer for SOCKS request/response bytes. The largest thing we ever build is
/// a CONNECT request with a 255-byte domain name (4 + 1 + 255 + 2), and the
/// largest reply is 4 + 1 + 255 + 2 as well.
const socks_buf_len: usize = 320;

/// Where a `socks://` dial is inside RFC 1928.
const SocksStage = enum {
    none,
    /// Greeting sent, waiting for the two-byte method selection.
    method,
    /// Username/password sub-negotiation sent, waiting for its two-byte reply.
    auth,
    /// CONNECT sent, waiting for the reply (4-byte header + address + port).
    connect,
};

/// One outbound `quic://` peer. zquic owns the UDP socket; we poll it with
/// libxev and pump STREAM bytes into the same ironwood handshake/frame path
/// used by TCP.
const QuicLink = struct {
    manager: *NetworkManager,
    conn: *PeerConn,
    client: *quic_mod.Client,
    host: []u8,
    options: LinkOptions,
    stream_id: u64 = 0,
    send_off: u64 = 0,
    recv_off: usize = 0,
    stream_opened: bool = false,
    udp: xev.UDP,
    udp_c: xev.Completion = undefined,
    udp_st: xev.UDP.State = undefined,
    recv_scratch: [2048]u8 = undefined,
    tick: xev.Timer,
    tick_c: xev.Completion = undefined,
    closing: bool = false,
};

/// One accepted `quic://` inbound connection. The shared listener owns the UDP
/// socket and drives zquic's `Server`; this struct ties the per-connection
/// zquic `ConnState` (and its client-initiated raw-app stream) onto the same
/// ironwood handshake/frame path used by TCP and outbound QUIC.
const QuicSrvConn = struct {
    manager: *NetworkManager,
    conn: *PeerConn,
    listener: *QuicServerListener,
    server: *quic_mod.Server,
    quic_conn: *quic_mod.io.ConnState,
    stream_id: u64 = 0,
    stream_found: bool = false,
    send_off: u64 = 0,
    recv_off: usize = 0,
    closed: bool = false,
};

/// One `quic://` listener. Owns a zquic `Server` (bound UDP socket) plus a
/// 20 ms drive tick, mirroring the outbound `QuicLink` pump. On every tick it
/// drains the socket, drives zquic, promotes freshly handshaked conns to
/// `PeerConn`s, and pumps raw-app STREAM bytes into the ironwood path.
const QuicServerListener = struct {
    manager: *NetworkManager,
    server: *quic_mod.Server,
    tick: xev.Timer,
    tick_c: xev.Completion = undefined,
    recv_scratch: [2048]u8 = undefined,
    /// Listener link options (priority/password/pinned keys from the listen
    /// URI); copied onto each accepted connection for the metadata handshake.
    options: LinkOptions = .{},
    /// Live accepted connections, keyed by the zquic `ConnState` pointer.
    conns: std.ArrayListUnmanaged(*QuicSrvConn) = .empty,

    fn deinit(self: *QuicServerListener, gpa: std.mem.Allocator) void {
        for (self.conns.items) |srv| gpa.destroy(srv);
        self.conns.deinit(gpa);
        if (self.options.uri.len > 0) gpa.free(self.options.uri);
        if (self.options.password.len > 0) gpa.free(self.options.password);
        if (self.options.sintf.len > 0) gpa.free(self.options.sintf);
        self.tick.deinit();
        quic_mod.destroyServer(gpa, self.server);
        gpa.destroy(self);
    }
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
    /// `quic://` listeners (owned zquic Servers + their drive ticks).
    quic_listeners: std.ArrayListUnmanaged(*QuicServerListener) = .empty,
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
        for (self.listeners.items) |l| l.deinit(self.gpa);
        self.listeners.deinit(self.gpa);
        for (self.quic_listeners.items) |ql| ql.deinit(self.gpa);
        self.quic_listeners.deinit(self.gpa);
        if (self.tls_state) |*s| {
            tls_wolfssl.freeCtx(s.client_ctx);
            tls_wolfssl.freeCtx(s.server_ctx);
            s.identity.deinit(self.gpa);
            tls_wolfssl.globalDeinit();
        }
        while (self.dials.pop()) |d| {
            d.retired = true;
            d.cancelled = true;
            d.refs = 1; // nothing else is alive at this point
            self.releaseDialRef(d);
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

    pub fn addOutboundPeer(self: *NetworkManager, uri: []const u8, options_in: LinkOptions) PeerOpError!void {
        const parsed = try parsePeerURI(uri);
        const host_dup = try self.gpa.dupe(u8, parsed.host);
        errdefer self.gpa.free(host_dup);

        var options = try parseLinkQuery(self.gpa, uri, options_in);
        options.use_tls = std.mem.eql(u8, parsed.scheme, "tls") or std.mem.eql(u8, parsed.scheme, "wss");
        options.use_ws = std.mem.eql(u8, parsed.scheme, "ws") or std.mem.eql(u8, parsed.scheme, "wss");
        options.use_quic = std.mem.eql(u8, parsed.scheme, "quic");
        options.use_unix = std.mem.eql(u8, parsed.scheme, "unix");
        // `socks://` tunnels to the peer named by the path; `sockstls://` is
        // the same plus a TLS session over the tunnel (SNI defaults to the
        // proxy hostname, overridable with `?sni=`, exactly like the
        // reference's `linkSOCKS.dial`).
        options.use_socks = std.mem.eql(u8, parsed.scheme, "socks") or std.mem.eql(u8, parsed.scheme, "sockstls");
        if (std.mem.eql(u8, parsed.scheme, "sockstls")) options.use_tls = true;
        options.ws_path = parsed.path;
        options.ws_host = parsed.host;
        options.uri = try normalizePeerUri(self.gpa, uri);
        errdefer self.gpa.free(options.uri);

        if (options.use_socks) {
            // A `socks://` URI without a peer address in the path has nothing
            // to tunnel to, so reject it while the caller can still report it
            // (the reference would only fail once the handshake ran).
            _ = socks.parseTarget(parsed.path) catch return error.InvalidURI;
            options.socks_target = try self.gpa.dupe(u8, parsed.path);
            errdefer self.gpa.free(options.socks_target);
            options.socks_user = try self.gpa.dupe(u8, parsed.user);
            errdefer self.gpa.free(options.socks_user);
            options.socks_pass = try self.gpa.dupe(u8, parsed.pass);
            errdefer self.gpa.free(options.socks_pass);
        }

        // `unix://` needs AF_UNIX, which only Unix-like targets provide
        // (see `unix_socket.supported`). Refuse it there rather than let a
        // peer URI silently never connect.
        if (comptime !unix_socket.supported) {
            if (options.use_unix) {
                unix_socket.reportUnsupported("peer", options.uri);
                // `options.uri` is released by the `errdefer` above.
                return error.NotSupported;
            }
        }

        // Refuse a duplicate the way the reference does (`link already exists`),
        // so `addPeer` over the admin socket reports the same thing.
        for (self.dials.items) |d| {
            // The `errdefer` above owns `options.uri` until the dial table takes
            // it over, so an early error return must not free it as well.
            // Go keys a link on (uri, source interface), so both must match.
            if (std.mem.eql(u8, d.uri, options.uri) and std.mem.eql(u8, d.options.sintf, options.sintf)) {
                return LinkError.PeerExists;
            }
        }

        if (options.use_quic) {
            self.startQuicDial(host_dup, parsed.port, options) catch |err| {
                logInfo("quic://{s}:{d} setup failed: {}", .{ parsed.host, parsed.port, err });
                self.gpa.free(host_dup);
                self.gpa.free(options.uri);
            };
            return;
        }

        if (options.sintf.len > 0) {
            options.sintf = try self.gpa.dupe(u8, options.sintf);
        }
        const dial = try self.gpa.create(DialState);
        dial.* = .{
            .manager = self,
            .host = host_dup,
            .port = parsed.port,
            .uri = options.uri,
            .options = options,
            .backoff_ns = MINIMUM_BACKOFF_NS,
            .timer = try xev.Timer.init(),
        };
        try self.dials.append(self.gpa, dial);
        self.attemptDial(dial);
    }

    fn refDial(dial: *DialState) void {
        dial.refs += 1;
    }

    /// Drop the dial table's reference (or a connection's) and free the state
    /// once nothing can reach it any more.
    fn retireDial(self: *NetworkManager, dial: *DialState) void {
        dial.retired = true;
        dial.cancelled = true;
        dial.manager = self;
        self.releaseDialRef(dial);
    }

    fn releaseDialRef(self: *NetworkManager, dial: *DialState) void {
        std.debug.assert(dial.refs > 0); // an unbalanced release is a bug, not a state
        dial.refs -= 1;
        if (dial.refs != 0 or !dial.retired) return;
        // Only reached once the dial has left `self.dials`, so no dangling
        // entry is left behind in the table.
        if (dial.host.len > 0) self.gpa.free(dial.host);
        if (dial.uri.len > 0) self.gpa.free(dial.uri);
        if (dial.options.password.len > 0) self.gpa.free(dial.options.password);
        if (dial.options.sintf.len > 0) self.gpa.free(dial.options.sintf);
        if (dial.options.pinned_keys.len > 0) self.gpa.free(dial.options.pinned_keys);
        if (dial.options.socks_target.len > 0) self.gpa.free(dial.options.socks_target);
        if (dial.options.socks_user.len > 0) self.gpa.free(dial.options.socks_user);
        if (dial.options.socks_pass.len > 0) self.gpa.free(dial.options.socks_pass);
        dial.socks_recv.deinit(self.gpa);
        dial.timer.deinit();
        self.gpa.destroy(dial);
    }

    /// Drop a configured outbound peer (and disconnect it if it is currently
    /// up). Mirrors `core.RemovePeer`, which matches on the query-stripped URI.
    /// Drop a configured dial. `sintf` is the source interface the link was added
    /// with; a link only matches when both the URI and the interface agree, as in
    /// the reference (`removePeer` with the wrong interface reports
    /// `peer is not configured`).
    pub fn removeOutboundPeer(self: *NetworkManager, uri: []const u8, sintf: []const u8) PeerOpError!void {
        const want = try normalizePeerUri(self.gpa, uri);
        defer self.gpa.free(want);
        var found = false;
        for (self.dials.items, 0..) |d, i| {
            if (!std.mem.eql(u8, d.uri, want) or !std.mem.eql(u8, d.options.sintf, sintf)) continue;
            found = true;
            _ = self.dials.orderedRemove(i);
            // A queued `onRedialTimer`/`onConnectComplete` may still name this
            // dial, so hand over a reference that those callbacks drop rather
            // than freeing it here. No `Timer.cancel` is issued: libxev's
            // cancel needs a second live completion slot, which a dial that is
            // being torn down has none of, and `cancelled` already makes the
            // outstanding callback a no-op.
            d.retired = true;
            d.cancelled = true;
            self.releaseDialRef(d);
            break;
        }
        // Also hang up any live connection that came from this dial.
        var it = self.conns.first;
        while (it) |n| {
            const next = n.next;
            const conn: *PeerConn = @fieldParentPtr("list_node", n);
            if (conn.dial) |d| {
                if (std.mem.eql(u8, d.uri, want) and std.mem.eql(u8, d.options.sintf, sintf)) self.closeConn(conn);
            }
            it = next;
        }
        if (!found) return LinkError.PeerNotFound;
    }

    fn attemptDial(self: *NetworkManager, dial: *DialState) void {
        _ = self;
        if (dial.cancelled) return;

        if (dial.options.use_unix) {
            // Unix domain socket: no DNS, and the connect completes
            // synchronously (it's a local socket), so spawn the connection
            // directly instead of going through an async connect completion.
            const addr = unix_socket.Address.init(dial.host) catch |err| {
                logInfo("unix://{s} bad path: {}", .{ dial.host, err });
                scheduleRedial(dial);
                return;
            };
            dial.tcp = unix_socket.dial(addr) catch |err| {
                logInfo("unix://{s} connect failed: {}", .{ dial.host, err });
                scheduleRedial(dial);
                return;
            };
            dial.backoff_ns = MINIMUM_BACKOFF_NS;
            dial.manager.spawnConn(dial.tcp, dial.options, dial) catch |err| {
                logInfo("spawnConn failed: {}", .{err});
            };
            return;
        }

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
        // The reference belongs to the in-flight connect; `onConnectComplete` drops
        // it whichever way the dial went. Without it the accounting is short by one
        // for every failed connection, which underflows `refs` (and would free a
        // dial that is still in the table) on the second attempt.
        refDial(dial);
        dial.tcp.connect(dial.manager.loop, &dial.connect_completion, addr, DialState, dial, onConnectComplete);
    }

    fn onConnectComplete(ud: ?*DialState, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, r: xev.ConnectError!void) xev.CallbackAction {
        _ = loop;
        _ = c;
        const dial = ud.?;
        defer dial.manager.releaseDialRef(dial);
        if (dial.cancelled) return .disarm;
        r catch |err| {
            logInfo("connect to {s}:{d} failed: {}", .{ dial.host, dial.port, err });
            // The reference records the dial failure on the link state; we only
            // have a link once a socket exists, so remember it on the dial and
            // let a later snapshot surface it if one ever gets attached.
            dial.last_error = true;
            scheduleRedial(dial);
            return .disarm;
        };
        dial.backoff_ns = MINIMUM_BACKOFF_NS; // reset on success
        if (dial.options.use_socks) {
            // The socket is connected to the *proxy*; the ironwood handshake
            // only starts once SOCKS says the tunnel to the peer is up.
            startSocksHandshake(dial, tcp);
            return .disarm;
        }
        dial.manager.spawnConn(tcp, dial.options, dial) catch |err| {
            logInfo("spawnConn failed: {}", .{err});
        };
        return .disarm;
    }

    // -----------------------------------------------------------------
    // SOCKS5 tunnel negotiation (socks://, sockstls://)
    // -----------------------------------------------------------------

    /// Kick off RFC 1928: offer authentication methods, then authenticate if
    /// the proxy wants username/password, then CONNECT to the peer named by
    /// the URI path. Every step is a libxev read/write completion on the same
    /// socket, so the event loop is never blocked.
    fn startSocksHandshake(dial: *DialState, tcp: xev.TCP) void {
        dial.tcp = tcp;
        // Held for the duration of the negotiation and released when the last
        // stage hands the socket over to `spawnConn` (or gives up).
        refDial(dial);
        dial.socks_stage = .method;
        dial.socks_recv.clearRetainingCapacity();
        dial.socks_out_len = 0;
        const body = socks.greeting(&dial.socks_out, dial.options.socks_user.len > 0) catch |err| {
            logInfo("socks greeting failed: {}", .{err});
            finishSocksFailure(dial);
            return;
        };
        dial.socks_out_len = body.len;
        socksWrite(dial);
    }

    fn socksWrite(dial: *DialState) void {
        dial.tcp.write(
            dial.manager.loop,
            &dial.socks_completion,
            .{ .slice = dial.socks_out[0..dial.socks_out_len] },
            DialState,
            dial,
            onSocksWrite,
        );
    }

    fn onSocksWrite(ud: ?*DialState, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, buf: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = tcp;
        _ = buf;
        const dial = ud.?;
        const n = r catch |err| {
            logInfo("socks write to {s}:{d} failed: {}", .{ dial.host, dial.port, err });
            finishSocksFailure(dial);
            return .disarm;
        };
        // The requests are a handful of bytes, so a short write means the
        // proxy saw a partial message: give up on this attempt and let the
        // normal redial backoff retry the whole thing.
        if (n < dial.socks_out_len) {
            logInfo("socks: short write to {s}:{d}", .{ dial.host, dial.port });
            finishSocksFailure(dial);
            return .disarm;
        }
        socksReadMore(dial);
        return .disarm;
    }

    /// Read until the stage in flight has all the bytes it needs.
    fn socksReadMore(dial: *DialState) void {
        const need = socksNeedBytes(dial);
        if (need == 0 or dial.socks_recv.items.len >= need) {
            socksStageComplete(dial);
            return;
        }
        // Read at most the bytes this stage still needs, into the read
        // scratch; whatever arrives is appended to `socks_recv`, which is
        // what the stages interpret (`socks_out` keeps the request that a
        // write completion may still be pointing at).
        const have = dial.socks_recv.items.len;
        const space = dial.socks_in[0 .. need - have];
        dial.tcp.read(
            dial.manager.loop,
            &dial.socks_completion,
            .{ .slice = space },
            DialState,
            dial,
            onSocksRead,
        );
    }

    fn onSocksRead(ud: ?*DialState, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, buf: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = tcp;
        const dial = ud.?;
        const n = r catch |err| {
            logInfo("socks read from {s}:{d} failed: {}", .{ dial.host, dial.port, err });
            finishSocksFailure(dial);
            return .disarm;
        };
        if (n == 0) {
            logInfo("socks: {s}:{d} closed during handshake", .{ dial.host, dial.port });
            finishSocksFailure(dial);
            return .disarm;
        }
        dial.socks_recv.appendSlice(dial.manager.gpa, buf.slice[0..n]) catch |err| {
            logInfo("socks read: {}", .{err});
            finishSocksFailure(dial);
            return .disarm;
        };
        socksStageComplete(dial);
        return .disarm;
    }

    /// Minimum bytes the current stage must have before it can be interpreted.
    /// For the CONNECT reply the header decides the real length, so a short
    /// read is normal there and `socksStageComplete` asks for more.
    fn socksNeedBytes(dial: *DialState) usize {
        return switch (dial.socks_stage) {
            .none => 0,
            .method, .auth => 2,
            .connect => if (socks.replyLength(dial.socks_recv.items)) |n| n else |_| 4,
        };
    }

    fn socksStageComplete(dial: *DialState) void {
        const received = dial.socks_recv.items;
        switch (dial.socks_stage) {
            .none => finishSocksFailure(dial),
            .method => {
                const method = socks.selectedMethod(received[0..2]) catch |err| {
                    logInfo("socks: {s}:{d} method selection failed: {}", .{ dial.host, dial.port, err });
                    finishSocksFailure(dial);
                    return;
                };
                dial.socks_recv.clearRetainingCapacity();
                if (method == socks.METHOD_USERPASS) {
                    socksSendAuth(dial);
                    return;
                }
                socksSendConnect(dial);
            },
            .auth => {
                const ok = socks.authSucceeded(received[0..2]) catch |err| {
                    logInfo("socks: {s}:{d} auth reply: {}", .{ dial.host, dial.port, err });
                    finishSocksFailure(dial);
                    return;
                };
                dial.socks_recv.clearRetainingCapacity();
                if (!ok) {
                    logInfo("socks: {s}:{d} rejected the proxy credentials", .{ dial.host, dial.port });
                    finishSocksFailure(dial);
                    return;
                }
                socksSendConnect(dial);
            },
            .connect => {
                const need = socks.replyLength(received) catch |err| {
                    logInfo("socks: {s}:{d} bad reply: {}", .{ dial.host, dial.port, err });
                    finishSocksFailure(dial);
                    return;
                };
                if (received.len < need) {
                    socksReadMore(dial);
                    return;
                }
                socks.replyOk(received) catch {
                    const rep = received[1];
                    logInfo("socks: {s}:{d} CONNECT to {s} failed: {s} (0x{x})", .{
                        dial.host, dial.port, dial.options.socks_target, socks.replyText(rep), rep,
                    });
                    finishSocksFailure(dial);
                    return;
                };
                // Tunnel established: the socket now speaks to the peer, so
                // hand it to the normal connection path (which adds TLS for
                // `sockstls://` and then the ironwood handshake).
                const tcp = dial.tcp;
                dial.socks_stage = .none;
                dial.socks_recv.clearRetainingCapacity();
                dial.manager.spawnConn(tcp, dial.options, dial) catch |err| {
                    logInfo("spawnConn failed after socks: {}", .{err});
                };
                dial.manager.releaseDialRef(dial);
            },
        }
    }

    fn socksSendAuth(dial: *DialState) void {
        dial.socks_stage = .auth;
        const body = socks.authRequest(
            &dial.socks_out,
            dial.options.socks_user,
            dial.options.socks_pass,
        ) catch |err| {
            logInfo("socks auth request failed: {}", .{err});
            finishSocksFailure(dial);
            return;
        };
        dial.socks_out_len = body.len;
        socksWrite(dial);
    }

    fn socksSendConnect(dial: *DialState) void {
        const target = socks.parseTarget(dial.options.socks_target) catch |err| {
            logInfo("socks: bad target {s}: {}", .{ dial.options.socks_target, err });
            finishSocksFailure(dial);
            return;
        };
        dial.socks_stage = .connect;
        const body = socks.connectRequest(&dial.socks_out, target) catch |err| {
            logInfo("socks connect request failed: {}", .{err});
            finishSocksFailure(dial);
            return;
        };
        dial.socks_out_len = body.len;
        socksWrite(dial);
    }

    /// Abandon this attempt: drop the negotiation's reference and let the
    /// normal backoff retry the whole dial (connect included).
    fn finishSocksFailure(dial: *DialState) void {
        dial.socks_stage = .none;
        dial.socks_recv.clearRetainingCapacity();
        dial.last_error = true;
        scheduleRedial(dial);
        dial.manager.releaseDialRef(dial);
    }

    fn scheduleRedial(dial: *DialState) void {
        if (dial.cancelled) return;
        const wait_ns = dial.backoff_ns;
        dial.backoff_ns = @min(dial.backoff_ns * 2, dial.options.max_backoff_ns);
        const wait_ms: u64 = wait_ns / std.time.ns_per_ms;
        // The queued callback holds a reference until it runs.
        refDial(dial);
        dial.timer.run(dial.manager.loop, &dial.timer_completion, wait_ms, DialState, dial, onRedialTimer);
    }

    fn onRedialTimer(ud: ?*DialState, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = r catch {};
        const dial = ud.?;
        defer dial.manager.releaseDialRef(dial);
        if (dial.cancelled) return .disarm;
        dial.manager.attemptDial(dial);
        return .disarm;
    }

    // -----------------------------------------------------------------
    // Inbound listening
    // -----------------------------------------------------------------

    /// The error set is inferred: besides `LinkError` (which is what an admin
    /// `listen` refusal would report) a listener can fail inside libxev or the
    /// resolver, and those codes are only ever logged by the caller at startup.
    /// Returns the port actually bound (resolved from `getsockname`, so a
    /// `:0` ephemeral listener reports its real port; 0 for `unix://`).
    pub fn addListener(self: *NetworkManager, uri: []const u8) !u16 {
        const parsed = try parsePeerURI(uri);

        // `wss://` listeners are not supported natively. The reference
        // (`link_wss.go`) returns
        //   "WSS listener not supported, use WS listener behind reverse proxy instead"
        // and expects TLS termination to happen in a reverse proxy in front of
        // a plain `ws://` listener. Dialing `wss://` peers still works (see
        // `addOutboundPeer`).
        // The reference has no SOCKS listener (`linkSOCKS.listen` returns
        // "SOCKS listener not supported"), so refuse it rather than bind
        // something that is not a proxy.
        if (std.mem.eql(u8, parsed.scheme, "socks") or std.mem.eql(u8, parsed.scheme, "sockstls"))
            return error.NotSupported;
        if (std.mem.eql(u8, parsed.scheme, "wss")) return error.NotSupported;

        var options = try parseLinkQuery(self.gpa, uri, .{
            .use_tls = std.mem.eql(u8, parsed.scheme, "tls"),
            .use_ws = std.mem.eql(u8, parsed.scheme, "ws"),
            .use_quic = std.mem.eql(u8, parsed.scheme, "quic"),
            .use_unix = std.mem.eql(u8, parsed.scheme, "unix"),
            .ws_path = parsed.path,
            .ws_host = parsed.host,
        });
        // Inbound links report their *remote* address as the URI (built in
        // `tryParseHandshake`), so nothing is stored in `uri` here beyond the
        // listener's own scheme/opts, which accepted connections inherit.
        options.uri = try normalizePeerUri(self.gpa, uri);
        errdefer self.gpa.free(options.uri);

        if (options.use_quic) {
            // QUIC listener: no TCP socket, no DNS. zquic's Server binds its
            // own UDP socket on 0.0.0.0:port and we drive it with a timer.
            try self.addQuicListener(options, parsed.port);
            logInfo("quic listener started on 0.0.0.0:{d}", .{parsed.port});
            return parsed.port;
        }

        if (options.use_unix) {
            if (comptime !unix_socket.supported) {
                // Same refusal as for an outbound `unix://` peer: say so once,
                // then let the caller log it and carry on without the listener.
                unix_socket.reportUnsupported("listener", options.uri);
                return error.NotSupported;
            }
            // Unix domain socket listener: no DNS, no host/port.
            const addr = unix_socket.Address.init(parsed.host) catch return error.InvalidURI;
            unix_socket.cleanupStale(addr);
            const tcp = unix_socket.listener(addr, 128) catch |err| {
                self.gpa.free(options.uri);
                logInfo("unix://{s} listen failed: {}", .{ parsed.host, err });
                return error.AddressInUse;
            };
            errdefer _ = std.posix.system.close(tcp.fd);
            const listener = try self.gpa.create(ListenerState);
            listener.* = .{
                .manager = self,
                .tcp = tcp,
                .use_tls = options.use_tls,
                .use_ws = options.use_ws,
                .scheme = try self.gpa.dupe(u8, parsed.scheme),
                .options = options,
                .unix_path = if (addr.abstract) null else try self.gpa.dupe(u8, addr.path),
            };
            try self.listeners.append(self.gpa, listener);
            listener.tcp.accept(self.loop, &listener.accept_completion, ListenerState, listener, onAccept);
            logInfo("{s} listener started on {s}", .{ parsed.scheme, parsed.host });
            return 0;
        }

        // `LinkError` is the set the admin API reports, so resolver failures are
        // folded into it rather than leaking `dns`'s own error set to callers.
        const addrs = dns.resolve(self.gpa, parsed.host, parsed.port) catch |err| {
            logInfo("resolve {s}:{d} failed: {}", .{ parsed.host, parsed.port, err });
            return error.ResolveFailed;
        };
        defer self.gpa.free(addrs);
        if (addrs.len == 0) return error.NoSuitableIPs;
        const addr = addrs[0];

        const listener = try self.gpa.create(ListenerState);
        listener.* = .{
            .manager = self,
            .tcp = try xev.TCP.init(addr),
            .use_tls = options.use_tls,
            .use_ws = options.use_ws,
            .scheme = try self.gpa.dupe(u8, parsed.scheme),
            .options = options,
        };
        try listener.tcp.bind(addr);
        try listener.tcp.listen(128);
        try self.listeners.append(self.gpa, listener);
        listener.tcp.accept(self.loop, &listener.accept_completion, ListenerState, listener, onAccept);
        logInfo("{s} listener started on {f} (tls={})", .{ parsed.scheme, addr, listener.use_tls });
        return listenerBoundPort(listener.tcp);
    }

    fn onAccept(ud: ?*ListenerState, loop: *xev.Loop, c: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
        _ = c;
        const listener = ud.?;
        const tcp = r catch |err| {
            logInfo("accept error: {}", .{err});
            listener.tcp.accept(loop, &listener.accept_completion, ListenerState, listener, onAccept);
            return .disarm;
        };
        var opts = listener.options;
        opts.persistent = false;
        listener.manager.spawnConn(tcp, opts, null) catch |err| {
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
        if (dial) |d| refDial(d);
        // Both directions funnel through here, so this is the one place that
        // guarantees every TCP/TLS/WS link is Nagle-free.
        if (!options.use_quic) setTcpNoDelay(tcp);
        const conn = try self.gpa.create(PeerConn);
        conn.* = .{
            .manager = self,
            .tcp = tcp,
            .dial = dial,
            .keepalive_timer = try xev.Timer.init(),
            .use_tls = options.use_tls,
            .use_ws = options.use_ws,
            .pending_options = options,
            .inbound = dial == null,
            // Inbound connections start with an empty `uri`; `spawnConn` fills
            // it in from the peer's actual remote address once the handshake
            // completes (see the `remoteAddrString` block below). Storing the
            // *listener's* URI here would make `getPeers` report the wildcard
            // listen address (e.g. `tls://[::]:0`) instead of the peer.
            .uri = if (dial == null) "" else (if (options.uri.len > 0) try self.gpa.dupe(u8, options.uri) else ""),
        };
        if (options.use_ws and dial != null) {
            // Outbound (client) side: we generate the Sec-WebSocket-Key and
            // precompute the expected accept. Inbound (server) side derives
            // the accept from the client's key once its upgrade arrives.
            ws.generateKey(&conn.ws_key_b64);
            ws.acceptKey(&conn.ws_key_b64, &conn.ws_accept_b64);
        }
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
        } else if (options.use_ws and dial != null) {
            // Plain-WS outbound only: send the client upgrade request.
            try self.sendWsUpgrade(conn);
        } else if (options.use_ws) {
            // Plain-WS inbound (server): nothing to send until the client's
            // upgrade request arrives (`unwrapWs` parses it and answers 101).
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
                    if (conn.use_ws and conn.dial != null) {
                        // wss:// outbound: upgrade the now-encrypted channel.
                        try self.sendWsUpgrade(conn);
                    } else if (conn.use_ws) {
                        // wss:// inbound: nothing to send; await the client's
                        // upgrade request, which arrives over the TLS channel.
                    } else {
                        const meta = Metadata.init(self.our_id.public_key, conn.pending_options.priority);
                        const msg = try meta.encode(&self.our_id, conn.pending_options.password, self.gpa);
                        queueWrite(conn, msg);
                    }
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

    /// Record why a link went down, for `getPeers`' `last_error`.
    fn noteLinkError(self: *NetworkManager, conn: *PeerConn, err: anyerror) void {
        if (conn.last_error.len > 0) self.gpa.free(conn.last_error);
        conn.last_error = std.fmt.allocPrint(self.gpa, "{s}", .{@errorName(err)}) catch "";
        conn.last_error_ns = monotonicNs();
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
        // Give back the dial reference this connection was holding before any
        // callback that may resurrect the dial runs.
        if (conn.dial) |d| {
            if (!conn.dial_ref_released) {
                conn.dial_ref_released = true;
                self.releaseDialRef(d);
            }
        }
        self.conns.remove(&conn.list_node);
        if (conn.quic) |link| {
            link.closing = true;
            conn.close_active = false;
            conn.maybeDestroy();
            return;
        }
        if (conn.quic_srv) |srv| {
            if (!srv.closed) {
                srv.closed = true;
                self.quicSrvRemove(srv);
            }
            conn.close_active = false;
            conn.maybeDestroy();
            return;
        }
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
            if (err != error.EOF) conn.manager.noteLinkError(conn, err);
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
        conn.rx_bytes += n;

        if (conn.tls) |tls| {
            conn.manager.handleTlsReadable(conn, tls, raw) catch |err| {
                logInfo("tls processing error, dropping peer: {}", .{err});
                conn.read_active = false;
                conn.manager.closeConn(conn);
                conn.maybeDestroy();
                return .disarm;
            };
        } else {
            if (conn.use_ws) {
                conn.ws_raw.appendSlice(conn.manager.gpa, raw) catch {
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
            }
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
                    if (conn.use_ws) {
                        try conn.ws_raw.appendSlice(self.gpa, scratch[0..n]);
                    } else {
                        try conn.read_buf.appendSlice(self.gpa, scratch[0..n]);
                    }
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

    fn sendWsUpgrade(self: *NetworkManager, conn: *PeerConn) !void {
        const host = if (conn.pending_options.ws_host.len > 0) conn.pending_options.ws_host else "localhost";
        const port: u16 = if (conn.dial) |d| d.port else 80;
        const path = if (conn.pending_options.ws_path.len > 0) conn.pending_options.ws_path else "/";
        const msg = try ws.buildClientUpgrade(self.gpa, host, port, path, &conn.ws_key_b64);
        queueWrite(conn, msg);
        logInfo("websocket upgrade sent to {s}:{d}{s}", .{ host, port, path });
    }

    fn startQuicDial(self: *NetworkManager, host: []u8, port: u16, options: LinkOptions) !void {
        const addrs = dns.resolve(self.gpa, host, port) catch |err| {
            logInfo("quic resolve {s}:{d} failed: {}", .{ host, port, err });
            return err;
        };
        defer self.gpa.free(addrs);
        // Prefer IPv4 (cheaper MTU/fragmentation behaviour on most paths) but
        // fall back to IPv6 instead of giving up: a large share of the public
        // peer list is IPv6-only, and the previous version of this function
        // returned `NoAddresses` for exactly those entries.
        var peer: ?std.Io.net.IpAddress = null;
        for (addrs) |a| {
            if (a == .ip4) {
                peer = a;
                break;
            }
        }
        if (peer == null) {
            for (addrs) |a| {
                if (a == .ip6) {
                    peer = a;
                    break;
                }
            }
        }
        const target = peer orelse return error.NoAddresses;

        const client = try quic_mod.createClient(self.gpa, host, target);
        errdefer quic_mod.destroyClient(self.gpa, client);
        try quic_mod.startHandshake(client);
        {
            var ip_buf: [48]u8 = undefined;
            var w = std.Io.Writer.fixed(&ip_buf);
            switch (target) {
                .ip4 => |v| w.print("{d}.{d}.{d}.{d}", .{ v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3] }) catch {},
                .ip6 => |v| {
                    w.writeByte('[') catch {};
                    node.address.formatIpv6(&v.bytes, &w) catch {};
                    w.writeByte(']') catch {};
                },
            }
            logInfo("quic://{s}:{d} Initial sent to {s}", .{ host, client.peer.getPort(), ip_buf[0..w.end] });
        }

        const conn = try self.gpa.create(PeerConn);
        errdefer self.gpa.destroy(conn);
        conn.* = .{
            .manager = self,
            .tcp = undefined,
            .keepalive_timer = try xev.Timer.init(),
            .pending_options = options,
            // QUIC outbound: set `uri` (and `inbound`) the same way `spawnConn`
            // does for TCP, so `tryParseHandshake` does not misclassify this
            // connection as inbound (which would call `getpeername` on the
            // UDP socket) and `getPeers` reports the right `remote` URI.
            // Ownership of `options.uri` transfers here: `addOutboundPeer`
            // hands it over on the success path and `conn.destroy` frees it.
            .dial = null,
            .uri = options.uri,
            .inbound = false,
        };

        const link = try self.gpa.create(QuicLink);
        errdefer self.gpa.destroy(link);
        link.* = .{
            .manager = self,
            .conn = conn,
            .client = client,
            .host = host,
            .options = options,
            .udp = xev.UDP.initFd(client.sock),
            .tick = try xev.Timer.init(),
        };
        conn.quic = link;
        self.conns.append(&conn.list_node);

        conn.keepalive_active = true;
        conn.keepalive_timer.run(self.loop, &conn.keepalive_completion, KEEPALIVE_TICK_MS, PeerConn, conn, onKeepaliveTick);

        link.tick.run(self.loop, &link.tick_c, 20, QuicLink, link, onQuicTick);
    }

    fn drainQuicUdp(self: *NetworkManager, link: *QuicLink) void {
        // Non-blocking drain. Zig 0.16 has no `std.posix.recvfrom` and no
        // `std.posix.MSG`, so the receive lives in `udp_io.zig`, which binds
        // libc's `recvfrom(3)` (Winsock's on Windows) and relies on the socket
        // being non-blocking rather than on Linux's `MSG_DONTWAIT`. A false
        // return means the kernel rejected the socket; drop the link rather
        // than spinning forever.
        if (!quic_mod.clientDrainUdp(link.client, &link.recv_scratch)) {
            logInfo("quic://{s} socket error, closing link", .{link.host});
            self.closeQuic(link);
        }
    }

    fn onQuicTick(ud: ?*QuicLink, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const link = ud.?;
        if (link.closing) return .disarm;
        link.manager.drainQuicUdp(link);
        link.manager.pumpQuic(link);
        if (link.closing) return .disarm;
        link.tick.run(loop, c, 20, QuicLink, link, onQuicTick);
        return .disarm;
    }

    fn pumpQuic(self: *NetworkManager, link: *QuicLink) void {
        if (link.closing) return;
        link.client.quic.processPendingWork(link.client.peer);
        link.client.quic.flushDeferredAck();

        if (!link.stream_opened and quic_mod.isConnected(link.client)) {
            const sid = link.client.quic.tryOpenLocalBidiStream() catch |err| {
                logInfo("quic://{s} open stream failed: {}", .{ link.host, err });
                return;
            };
            link.stream_id = sid;
            link.stream_opened = true;
            logInfo("quic://{s} handshake complete, stream {d}", .{ link.host, sid });
            const meta = Metadata.init(self.our_id.public_key, link.options.priority);
            const msg = meta.encode(&self.our_id, link.options.password, self.gpa) catch return;
            queueWrite(link.conn, msg);
        }

        if (link.stream_opened) {
            if (link.client.quic.rawAppRecvBuffer(link.stream_id)) |got| {
                if (got.len > link.recv_off) {
                    const fresh = got[link.recv_off..];
                    link.conn.read_buf.appendSlice(self.gpa, fresh) catch return;
                    link.recv_off = got.len;
                    self.processBuffered(link.conn) catch |err| {
                        logInfo("quic frame error {s}: {}", .{ link.host, err });
                        self.closeQuic(link);
                        return;
                    };
                }
            }
        }
    }

    fn closeQuic(self: *NetworkManager, link: *QuicLink) void {
        if (link.closing) return;
        link.closing = true;
        self.closeConn(link.conn);
    }

    // -----------------------------------------------------------------
    // QUIC listener (server side)
    // -----------------------------------------------------------------

    /// Start a `quic://` listener: create a zquic `Server` bound to
    /// `0.0.0.0:port` and a 20 ms drive tick that drains/feeds its UDP socket
    /// and pumps accepted connections. `options` (priority/password from the
    /// listen URI) is taken by value; on success its heap slices are owned by
    /// the listener, otherwise the caller's `errdefer` frees them.
    fn addQuicListener(self: *NetworkManager, options: LinkOptions, port: u16) !void {
        // wolfSSL must be initialised before we can mint the listener's
        // identity; `ensureTlsState` is idempotent and is what `tls://` uses.
        _ = try self.ensureTlsState();
        var key_hex_buf: [64]u8 = undefined;
        const key_hex = std.fmt.bufPrint(&key_hex_buf, "{x}", .{self.our_id.public_key}) catch unreachable;

        const server = try quic_mod.createServer(self.gpa, port, key_hex);
        errdefer quic_mod.destroyServer(self.gpa, server);

        const listener = try self.gpa.create(QuicServerListener);
        errdefer self.gpa.destroy(listener);
        listener.* = .{
            .manager = self,
            .server = server,
            .tick = try xev.Timer.init(),
            .options = options,
        };
        try self.quic_listeners.append(self.gpa, listener);
        listener.tick.run(self.loop, &listener.tick_c, 20, QuicServerListener, listener, onQuicSrvTick);
    }

    fn onQuicSrvTick(ud: ?*QuicServerListener, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const listener = ud.?;
        listener.manager.quicSrvDrive(listener);
        if (listener.manager.stop) return .disarm;
        listener.tick.run(loop, c, 20, QuicServerListener, listener, onQuicSrvTick);
        return .disarm;
    }

    /// One listener drive: reset zquic's per-drive budgets, drain/feed UDP,
    /// process pending work, promote newly handshaked conns, and pump existing
    /// conns' raw-app streams into the ironwood path.
    fn quicSrvDrive(self: *NetworkManager, listener: *QuicServerListener) void {
        quic_mod.serverDrive(listener.server, &listener.recv_scratch);
        self.quicSrvPromoteNew(listener);

        var i: usize = 0;
        while (i < listener.conns.items.len) {
            const srv = listener.conns.items[i];
            const before = listener.conns.items.len;
            self.quicSrvPump(listener, srv);
            // `quicSrvPump` may tear the conn down (removing it from the list
            // via `quicSrvRemove` + `swapRemove`); only advance when the entry
            // is still present at the same index.
            if (listener.conns.items.len == before) i += 1;
        }
    }

    /// Find freshly `.connected` zquic conns that we haven't wrapped in a
    /// `PeerConn` yet and do so.
    fn quicSrvPromoteNew(self: *NetworkManager, listener: *QuicServerListener) void {
        for (&listener.server.quic.conns) |*slot| {
            const qconn = slot.* orelse continue;
            if (qconn.phase != .connected) continue;
            // Already promoted?
            var seen = false;
            for (listener.conns.items) |srv| {
                if (srv.quic_conn == qconn) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            const conn = self.gpa.create(PeerConn) catch continue;
            conn.* = .{
                .manager = self,
                .tcp = undefined,
                .keepalive_timer = xev.Timer.init() catch {
                    self.gpa.destroy(conn);
                    continue;
                },
                .pending_options = listener.options,
                .inbound = true,
                .uri = "",
            };
            const srv = self.gpa.create(QuicSrvConn) catch {
                conn.keepalive_timer.deinit();
                self.gpa.destroy(conn);
                continue;
            };
            srv.* = .{
                .manager = self,
                .conn = conn,
                .listener = listener,
                .server = listener.server,
                .quic_conn = qconn,
            };
            conn.quic_srv = srv;
            self.conns.append(&conn.list_node);
            listener.conns.append(self.gpa, srv) catch {
                self.quicSrvRemove(srv);
                continue;
            };
            // Keepalive/timeout tick, same as TCP/outbound QUIC.
            conn.keepalive_active = true;
            conn.keepalive_timer.run(self.loop, &conn.keepalive_completion, KEEPALIVE_TICK_MS, PeerConn, conn, onKeepaliveTick);
            // Fill in the remote URI from the QUIC peer address.
            if (quicSrvPeerRemoteString(self.gpa, qconn.peer)) |ra| {
                conn.uri = std.fmt.allocPrint(self.gpa, "quic://{s}", .{ra}) catch "";
                self.gpa.free(ra);
            }
            logInfo("quic listener: accepted conn from {s}", .{if (conn.uri.len > 0) conn.uri else "?"});
        }
    }

    /// Pump one accepted conn: ensure it's still alive, locate (and answer) the
    /// client's bidirectional stream, and forward STREAM bytes into the
    /// ironwood handshake/frame parser.
    fn quicSrvPump(self: *NetworkManager, listener: *QuicServerListener, srv: *QuicSrvConn) void {
        _ = listener;
        if (srv.closed) return;

        // zquic may have reaped the ConnState (idle timeout); its slot goes
        // null and the memory is freed, so never dereference past this check.
        if (!quic_mod.serverConnAlive(srv.server, srv.quic_conn)) {
            self.closeConn(srv.conn);
            return;
        }
        const qconn = srv.quic_conn;
        if (qconn.phase != .connected) {
            self.closeConn(srv.conn);
            return;
        }

        if (!srv.stream_found) {
            const sid = self.quicSrvFindStream(srv) orelse return; // client hasn't opened yet
            srv.stream_id = sid;
            srv.stream_found = true;
            // Both sides send their ironwood metadata once the transport is
            // ready; the client opens the stream, so we answer on it.
            const meta = Metadata.init(self.our_id.public_key, srv.conn.pending_options.priority);
            const msg = meta.encode(&self.our_id, srv.conn.pending_options.password, self.gpa) catch {
                self.closeConn(srv.conn);
                return;
            };
            queueWrite(srv.conn, msg);
            return;
        }

        if (quic_mod.io.rawAppStreamResetReceived(qconn, srv.stream_id)) |code| {
            logInfo("quic listener: stream {d} reset (code {d})", .{ srv.stream_id, code });
            self.closeConn(srv.conn);
            return;
        }

        if (quic_mod.io.rawAppRecvBuffer(qconn, srv.stream_id)) |got| {
            if (got.len > srv.recv_off) {
                const fresh = got[srv.recv_off..];
                srv.conn.read_buf.appendSlice(self.gpa, fresh) catch {
                    self.closeConn(srv.conn);
                    return;
                };
                srv.recv_off = got.len;
                self.processBuffered(srv.conn) catch |err| {
                    logInfo("quic listener: frame error: {}", .{err});
                    self.closeConn(srv.conn);
                    return;
                };
            }
        }
    }

    /// Return the first active client-initiated bidirectional raw-app stream
    /// (stream_id % 4 == 0) on `srv.quic_conn`, or null if none yet.
    fn quicSrvFindStream(self: *NetworkManager, srv: *QuicSrvConn) ?u64 {
        _ = self;
        for (&srv.quic_conn.raw_app_streams) |*slot| {
            if (slot.active and slot.stream_id % 4 == 0) return slot.stream_id;
        }
        return null;
    }

    /// Release the raw-app stream, unlink and free `srv`, and clear the
    /// back-pointer on its `PeerConn` (which is still alive at this point --
    /// `maybeDestroy` defers actual free until the keepalive timer fires).
    fn quicSrvRemove(self: *NetworkManager, srv: *QuicSrvConn) void {
        if (srv.stream_found) {
            _ = quic_mod.io.releaseRawAppStream(srv.quic_conn, srv.stream_id, self.gpa);
        }
        if (srv.conn.quic_srv == srv) srv.conn.quic_srv = null;
        const listener = srv.listener;
        for (listener.conns.items, 0..) |item, i| {
            if (item == srv) {
                _ = listener.conns.swapRemove(i);
                break;
            }
        }
        self.gpa.destroy(srv);
    }

    fn unwrapWs(self: *NetworkManager, conn: *PeerConn) !void {
        if (!conn.use_ws) return;
        if (!conn.ws_handshake_done) {
            if (conn.inbound) {
                // Server side: parse the client's upgrade request and answer 101.
                const req = ws.parseClientUpgrade(conn.ws_raw.items) orelse return;
                if (!req.ok) return error.BadWsUpgrade;
                const resp = try ws.buildServerUpgrade(self.gpa, req.key);
                const prev = conn.use_ws;
                conn.use_ws = false; // queue the 101 response raw (unframed)
                queueWrite(conn, resp);
                conn.use_ws = prev;
                const remaining = conn.ws_raw.items[req.consumed..];
                std.mem.copyForwards(u8, conn.ws_raw.items[0..remaining.len], remaining);
                conn.ws_raw.shrinkRetainingCapacity(remaining.len);
                conn.ws_handshake_done = true;
                logInfo("websocket upgrade complete (server)", .{});
            } else {
                // Client side: parse the server's 101 response.
                const parsed = ws.parseServerUpgrade(conn.ws_raw.items, &conn.ws_accept_b64) orelse return;
                if (!parsed.ok) return error.BadWsUpgrade;
                const remaining = conn.ws_raw.items[parsed.consumed..];
                std.mem.copyForwards(u8, conn.ws_raw.items[0..remaining.len], remaining);
                conn.ws_raw.shrinkRetainingCapacity(remaining.len);
                conn.ws_handshake_done = true;
                logInfo("websocket upgrade complete", .{});
            }
            const meta = Metadata.init(self.our_id.public_key, conn.pending_options.priority);
            const msg = try meta.encode(&self.our_id, conn.pending_options.password, self.gpa);
            queueWrite(conn, msg);
        }

        var src = conn.ws_raw.items;
        var read_pos: usize = 0;
        while (read_pos < src.len) {
            const slice = src[read_pos..];
            const decoded = ws.decodeFrame(slice) catch |err| switch (err) {
                error.Incomplete => break,
                error.Close => return error.TlsClosed,
                else => return err,
            };
            switch (decoded.frame.opcode) {
                .binary, .text, .continuation => {
                    try conn.read_buf.appendSlice(self.gpa, decoded.frame.payload);
                },
                .ping => {
                    const pong = (if (conn.inbound)
                        ws.encodeServerFrame(self.gpa, .pong, decoded.frame.payload)
                    else
                        ws.encodeFrame(self.gpa, .pong, decoded.frame.payload)) catch break;
                    const prev = conn.use_ws;
                    conn.use_ws = false;
                    queueWrite(conn, pong);
                    conn.use_ws = prev;
                },
                .pong => {},
                .close => return error.TlsClosed,
            }
            read_pos += decoded.consumed;
        }
        const leftover = src[read_pos..];
        std.mem.copyForwards(u8, conn.ws_raw.items[0..leftover.len], leftover);
        conn.ws_raw.shrinkRetainingCapacity(leftover.len);
    }

    /// Consume as many complete units (handshake message, then wire frames)
    /// as are available in `conn.read_buf`.
    fn processBuffered(self: *NetworkManager, conn: *PeerConn) !void {
        try self.unwrapWs(conn);
        if (conn.use_ws and !conn.ws_handshake_done) return;
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

        // `?key=HEX` pinning, like the reference's `pinnedEd25519Keys`.
        {
            const pinned = if (conn.dial) |d| d.options.pinned_keys else conn.pending_options.pinned_keys;
            if (pinned.len > 0) {
                var ok = false;
                for (pinned) |k| {
                    if (std.mem.eql(u8, &k, &peer_meta.public_key)) ok = true;
                }
                if (!ok) {
                    logInfo("peer key not pinned in URI, rejecting", .{});
                    return error.PeerNotAllowed;
                }
            }
        }

        conn.peer_key = peer_meta.public_key;
        conn.up_ns = monotonicNs();
        var prio: u8 = peer_meta.priority;
        if (conn.dial) |dial| prio = @max(prio, dial.options.priority);
        if (conn.dial == null and conn.uri.len == 0) {
            // Inbound accepted connection: the reference rewrites the listener
            // URL's host to the remote address, which is what we show.
            const scheme = if (conn.use_tls) (if (conn.use_ws) "wss" else "tls") else (if (conn.use_ws) "ws" else "tcp");
            if (remoteAddrString(self.gpa, conn.tcp)) |ra| {
                conn.uri = std.fmt.allocPrint(self.gpa, "{s}://{s}", .{ scheme, ra }) catch "";
                self.gpa.free(ra);
            }
        }

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
        var payload = data;
        const packet_type: ?wire.PacketType = if (wire.decodeFrame(payload)) |decoded| decoded.packet_type else |_| null;
        // Mirror ironwood, which stamps the sigReq send time from the writer's
        // `done` callback rather than when the router queues the action; see
        // Router.markSigReqSent.
        if (packet_type) |pt| {
            if (pt == .proto_sig_req) conn.manager.core.router.markSigReqSent(conn.peer_id);
        }
        if (conn.use_ws and conn.ws_handshake_done) {
            const framed = (if (conn.inbound)
                ws.encodeServerFrame(conn.manager.gpa, .binary, payload)
            else
                ws.encodeFrame(conn.manager.gpa, .binary, payload)) catch {
                conn.manager.gpa.free(payload);
                return;
            };
            conn.manager.gpa.free(payload);
            payload = framed;
        }

        if (conn.quic) |link| {
            if (!link.stream_opened) {
                conn.manager.gpa.free(payload);
                return;
            }
            const n = link.client.quic.sendRawStreamData(link.stream_id, link.send_off, payload, false);
            if (n > 0) link.send_off += n;
            conn.manager.gpa.free(payload);
            return;
        }

        if (conn.quic_srv) |srv| {
            if (!srv.stream_found or srv.closed) {
                conn.manager.gpa.free(payload);
                return;
            }
            const n = srv.server.quic.sendRawStreamData(srv.quic_conn, srv.stream_id, srv.send_off, payload, false);
            if (n > 0) srv.send_off += n;
            conn.manager.gpa.free(payload);
            return;
        }

        if (conn.tls) |tls| {
            const result = tls.writePlaintext(payload);
            conn.manager.gpa.free(payload);
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

        queueRawWriteTyped(conn, payload, packet_type);
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
            conn.manager.noteLinkError(conn, err);
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
        conn.tx_bytes += n;
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

    /// Take a snapshot of every link for the admin socket.
    ///
    /// Mirrors `core.GetPeers()`: the reference walks its *link* table, so a
    /// peer that has connected but not finished the ironwood handshake still
    /// shows up (without key/port/cost, which the reference fills in only from
    /// the router), and joins each link with the router's peer entry for the
    /// same connection -- `peer_id` is that join key here.
    ///
    /// Recomputing the one-second byte rates as a side effect matches the
    /// reference's `_updateAverages` goroutine, whose staleness is what makes
    /// `rate_*` (with its `omitempty`) vanish on brand-new links.
    pub fn snapshotPeers(self: *NetworkManager, gpa: std.mem.Allocator) ![]PeerSnapshot {
        const router_peers = try node.core.getRouterPeers(self.core, gpa);
        defer gpa.free(router_peers);

        var list = std.ArrayListUnmanaged(PeerSnapshot).empty;
        errdefer list.deinit(gpa);

        var it = self.conns.first;
        while (it) |node_h| : (it = node_h.next) {
            const conn: *PeerConn = @fieldParentPtr("list_node", node_h);
            const now = monotonicNs();

            if (conn.rate_last_ns == 0) {
                conn.rate_last_ns = now;
                conn.rate_last_rx = conn.rx_bytes;
                conn.rate_last_tx = conn.tx_bytes;
            } else if (now > conn.rate_last_ns) {
                const dt = now - conn.rate_last_ns;
                if (dt >= std.time.ns_per_s / 2) {
                    const rx = conn.rx_bytes -| conn.rate_last_rx;
                    const tx = conn.tx_bytes -| conn.rate_last_tx;
                    conn.rx_rate = @intCast(rx * std.time.ns_per_s / dt);
                    conn.tx_rate = @intCast(tx * std.time.ns_per_s / dt);
                    conn.rate_last_rx = conn.rx_bytes;
                    conn.rate_last_tx = conn.tx_bytes;
                    conn.rate_last_ns = now;
                }
            }

            var snap = PeerSnapshot{
                // A connection spawned from a dial may not have carried the URI over
                // (the QUIC link does not); fall back to the dial's, which is what the
                // reference reports as `remote`.
                .uri = if (conn.uri.len > 0) conn.uri else if (conn.dial) |d| d.uri else "",
                .up = conn.established,
                .inbound = conn.inbound,
                .has_key = conn.established,
                .key = conn.peer_key,
                .rx_bytes = conn.rx_bytes,
                .tx_bytes = conn.tx_bytes,
                .rx_rate = conn.rx_rate,
                .tx_rate = conn.tx_rate,
                .uptime_ns = if (conn.up_ns != 0) now - conn.up_ns else 0,
                .last_error = conn.last_error,
                .last_error_age_ns = if (conn.last_error_ns != 0) now - conn.last_error_ns else 0,
            };
            if (conn.established) {
                const addr = node.addrForKey(&conn.peer_key);
                const txt = formatIpv6(&addr.bytes, &snap.address) catch "";
                snap.address_len = @min(txt.len, snap.address.len);
            }

            for (router_peers) |rp| {
                if (rp.peer_id != conn.peer_id) continue;
                snap.port = rp.port;
                snap.priority = rp.priority;
                snap.cost = rp.cost;
                snap.latency_ns = rp.latency_ns;
                break;
            }
            try list.append(gpa, snap);
        }

        // A configured peer whose dial has not produced a connection yet is still a
        // peer: the reference reports every entry of its link table, so a peer that
        // is down shows up with `up: false` and no key. (Its `last_error` text is
        // not carried on the dial in this port, so that field stays empty.)
        for (self.dials.items) |d| {
            if (d.retired) continue;
            var live = false;
            var cit = self.conns.first;
            while (cit) |cn| : (cit = cn.next) {
                const conn: *PeerConn = @fieldParentPtr("list_node", cn);
                if (conn.dial == d) {
                    live = true;
                    break;
                }
            }
            if (live) continue;
            try list.append(gpa, .{ .uri = d.uri });
        }
        return list.toOwnedSlice(gpa);
    }

    /// Snapshots borrow their strings from the live connections, so freeing is
    /// only the slice itself; the signature exists so the admin layer owns the
    /// whole lifecycle without having to know that.
    pub fn freePeerSnapshot(self: *NetworkManager, gpa: std.mem.Allocator, peers: []PeerSnapshot) void {
        _ = self;
        gpa.free(peers);
    }
};

/// One row of `getPeers`: the Zig counterpart of the reference's `core.PeerInfo`
/// joined into `admin.PeerEntry`. Fixed-size buffers for the strings that always
/// fit (an IPv6 text form is at most 45 bytes, `last_error` is short) mean
/// taking a snapshot cannot fail part-way through an admin reply.
pub const PeerSnapshot = struct {
    uri: []const u8 = "",
    up: bool = false,
    inbound: bool = false,
    /// False until the ironwood handshake identifies the remote key; the
    /// reference omits `address`/`key` in exactly that case.
    has_key: bool = false,
    key: PublicKey = [_]u8{0} ** 32,
    address: [45]u8 = undefined,
    address_len: usize = 0,
    port: u64 = 0,
    priority: u8 = 0,
    cost: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_rate: u64 = 0,
    tx_rate: u64 = 0,
    uptime_ns: u64 = 0,
    latency_ns: u64 = 0,
    last_error: []const u8 = "",
    last_error_age_ns: u64 = 0,
};

fn formatIpv6(bytes: *const [16]u8, buf: []u8) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try node.address.formatIpv6(bytes, &w);
    return buf[0..w.end];
}

/// The socket handle behind an `xev.TCP`.
///
/// libxev stores a `posix.socket_t`, which is a small integer on every
/// Unix-like target and a `HANDLE` (the `SOCKET` reinterpreted as a pointer)
/// on Windows' IOCP backend. Both are `std.posix.socket_t` as far as this file
/// is concerned -- `std.c`'s socket calls take `fd_t`, which is the same type
/// on Windows (`HANDLE`) -- so the handle is handed through unchanged.
fn tcpFd(tcp: xev.TCP) std.posix.socket_t {
    return tcp.fd;
}

/// The port a listener's socket is actually bound to (resolving `:0` /
/// ephemeral binds via `getsockname`). 0 if it can't be determined.
fn listenerBoundPort(tcp: xev.TCP) u16 {
    var storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    switch (builtin.os.tag) {
        .windows => {
            if (std.c.getsockname(tcpFd(tcp), @ptrCast(&storage), &len) != 0) return 0;
        },
        else => {
            if (std.c.getsockname(tcpFd(tcp), @ptrCast(&storage), &len) != 0) return 0;
        },
    }
    return switch (storage.family) {
        std.posix.AF.INET => blk: {
            const sa: *align(1) const std.posix.sockaddr.in = @ptrCast(&storage);
            break :blk std.mem.bigToNative(u16, sa.port);
        },
        std.posix.AF.INET6 => blk: {
            const sa: *align(1) const std.posix.sockaddr.in6 = @ptrCast(&storage);
            break :blk std.mem.bigToNative(u16, sa.port);
        },
        else => 0,
    };
}

/// `addr:port` text for the remote end of `tcp`, formatted like Go's
/// `net.TCPAddr.String()` (IPv6 bracketed). Null if the platform can't say.
fn remoteAddrString(gpa: std.mem.Allocator, tcp: xev.TCP) ?[]u8 {
    var storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    switch (builtin.os.tag) {
        .windows => {
            if (std.c.getpeername(tcpFd(tcp), @ptrCast(&storage), &len) != 0) return null;
        },
        else => std.posix.getpeername(tcpFd(tcp), @ptrCast(&storage), &len) catch return null,
    }
    var buf: [128]u8 = undefined;
    const txt = switch (storage.family) {
        std.posix.AF.INET => blk: {
            const sa: *align(1) const std.posix.sockaddr.in = @ptrCast(&storage);
            const bytes: [4]u8 = @bitCast(sa.addr);
            break :blk std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}:{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3], std.mem.bigToNative(u16, sa.port),
            }) catch return null;
        },
        std.posix.AF.INET6 => blk: {
            const sa: *align(1) const std.posix.sockaddr.in6 = @ptrCast(&storage);
            var ip: [45]u8 = undefined;
            var iw = std.Io.Writer.fixed(&ip);
            node.address.formatIpv6(&sa.addr, &iw) catch return null;
            break :blk std.fmt.bufPrint(&buf, "[{s}]:{d}", .{ ip[0..iw.end], std.mem.bigToNative(u16, sa.port) }) catch return null;
        },
        else => return null,
    };
    return gpa.dupe(u8, txt) catch null;
}

/// Format a zquic peer `compat.Address` as `host:port` (IPv4) or
/// `[host]:port` (IPv6), for the accepted conn's `remote` URI.
fn quicSrvPeerRemoteString(gpa: std.mem.Allocator, addr: quic_mod.Address) ?[]u8 {
    var buf: [128]u8 = undefined;
    const txt = switch (addr.any.family) {
        std.posix.AF.INET => blk: {
            const bytes: [4]u8 = @bitCast(addr.in.addr);
            break :blk std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}:{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3], std.mem.bigToNative(u16, addr.in.port),
            }) catch return null;
        },
        std.posix.AF.INET6 => blk: {
            var ip: [45]u8 = undefined;
            var iw = std.Io.Writer.fixed(&ip);
            node.address.formatIpv6(&addr.in6.addr, &iw) catch return null;
            break :blk std.fmt.bufPrint(&buf, "[{s}]:{d}", .{ ip[0..iw.end], std.mem.bigToNative(u16, addr.in6.port) }) catch return null;
        },
        else => return null,
    };
    return gpa.dupe(u8, txt) catch null;
}

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
    use_ws: bool = false,
    scheme: []const u8 = "tcp",
    options: LinkOptions = .{},
    /// Set for a `unix://` listener so the socket file can be unlinked on
    /// shutdown. Null for `tcp://` (and for abstract unix sockets).
    unix_path: ?[]const u8 = null,

    fn deinit(self: *ListenerState, gpa: std.mem.Allocator) void {
        if (self.scheme.len > 0) gpa.free(self.scheme);
        if (self.options.uri.len > 0) gpa.free(self.options.uri);
        if (self.unix_path) |p| {
            var buf: [108]u8 = undefined;
            if (std.fmt.bufPrintZ(&buf, "{s}", .{p})) |z| {
                _ = std.posix.system.unlink(z.ptr);
            } else |_| {}
            gpa.free(p);
        }
        gpa.destroy(self);
    }
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

test "parse websocket uri with path" {
    const parsed = try parsePeerURI("ws://example.com:1340/ygg");
    try testing.expectEqualStrings("ws", parsed.scheme);
    try testing.expectEqualStrings("example.com", parsed.host);
    try testing.expectEqual(@as(u16, 1340), parsed.port);
    try testing.expectEqualStrings("/ygg", parsed.path);
}

test "parse quic uri" {
    const parsed = try parsePeerURI("quic://ygg-msk-1.averyan.ru:8364");
    try testing.expectEqualStrings("quic", parsed.scheme);
    try testing.expectEqual(@as(u16, 8364), parsed.port);
    try testing.expectEqualStrings("/", parsed.path);
}

test "isIncompleteFrame detects short buffers" {
    try testing.expect(isIncompleteFrame(&.{}));
    try testing.expect(isIncompleteFrame(&[_]u8{0x05})); // says 5 bytes follow, none present
    const full = try wire.encodeFrame(testing.allocator, .dummy, "hi");
    defer testing.allocator.free(full);
    try testing.expect(!isIncompleteFrame(full));
    try testing.expect(isIncompleteFrame(full[0 .. full.len - 1]));
}
