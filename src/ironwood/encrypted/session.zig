//! Session state machine for encrypted communication.
//!
//! Implements Init/Ack/Traffic handshake with 3-tier key ratcheting
//! and forward secrecy using XSalsa20-Poly1305 (NaCl Box).
//! Wire-compatible with Go Ironwood.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Box = std.crypto.nacl.Box;

const ironwood_crypto = @import("../crypto.zig");
const Crypto = ironwood_crypto.Crypto;
const PublicKey = ironwood_crypto.PublicKey;
const Sig = ironwood_crypto.Sig;

const wire = @import("../wire.zig");

const enc_crypto = @import("crypto.zig");
const CurvePublicKey = enc_crypto.CurvePublicKey;
const CurvePrivateKey = enc_crypto.CurvePrivateKey;
const BOX_OVERHEAD = enc_crypto.BOX_OVERHEAD;
const GroupAuth = enc_crypto.GroupAuth;
const newBoxKeys = enc_crypto.newBoxKeys;
const makeSharedSecret = enc_crypto.makeSharedSecret;
const boxSeal = enc_crypto.boxSeal;
const boxOpen = enc_crypto.boxOpen;
const boxSealPrecomputed = enc_crypto.boxSealPrecomputed;
const boxOpenPrecomputed = enc_crypto.boxOpenPrecomputed;
const ed25519PublicToCurve25519 = enc_crypto.ed25519PublicToCurve25519;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SESSION_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
pub const SESSION_CLEANUP_INTERVAL_NS: u64 = 30 * std.time.ns_per_s;

const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + BOX_OVERHEAD + 32;
pub const SESSION_TRAFFIC_OVERHEAD: u64 = @as(u64, SESSION_TRAFFIC_OVERHEAD_MIN) + 9 + 9 + 9;
pub const SESSION_INIT_SIZE: usize = 1 + 32 + BOX_OVERHEAD + 64 + 32 + 32 + 8 + 8;

pub const SESSION_TYPE_DUMMY: u8 = 0;
pub const SESSION_TYPE_INIT: u8 = 1;
pub const SESSION_TYPE_ACK: u8 = 2;
pub const SESSION_TYPE_TRAFFIC: u8 = 3;

// ---------------------------------------------------------------------------
// SessionInit — handshake message
// ---------------------------------------------------------------------------

pub const SessionInit = struct {
    current: CurvePublicKey,
    next: CurvePublicKey,
    key_seq: u64,
    seq: u64,

    pub fn init(current: *const CurvePublicKey, next: *const CurvePublicKey, key_seq: u64) SessionInit {
        return .{ .current = current.*, .next = next.*, .key_seq = key_seq, .seq = wallClockSeconds() };
    }

    /// Encrypt an init/ack message. Caller owns the returned buffer.
    pub fn encrypt(
        self: *const SessionInit,
        our_ed_kp: *const Crypto,
        to_ed_pub: *const PublicKey,
        msg_type: u8,
        preimage: []const u8,
        gpa: Allocator,
    ) ![]u8 {
        const from = try newBoxKeys();
        const to_box = ed25519PublicToCurve25519(to_ed_pub.*) catch return error.BadKey;

        // sigBytes = [fromPub][current][next][keySeq(8)][seq(8)]
        var sig_bytes = try std.ArrayListUnmanaged(u8).initCapacity(gpa, 32 + 32 + 32 + 8 + 8);
        defer sig_bytes.deinit(gpa);
        try sig_bytes.appendSlice(gpa, &from.public_key);
        try sig_bytes.appendSlice(gpa, &self.current);
        try sig_bytes.appendSlice(gpa, &self.next);
        var ksb: [8]u8 = undefined;
        std.mem.writeInt(u64, &ksb, self.key_seq, .big);
        try sig_bytes.appendSlice(gpa, &ksb);
        var sb: [8]u8 = undefined;
        std.mem.writeInt(u64, &sb, self.seq, .big);
        try sig_bytes.appendSlice(gpa, &sb);

        const sig: Sig = if (preimage.len == 0)
            our_ed_kp.sign(sig_bytes.items)
        else blk: {
            var signed = try std.ArrayListUnmanaged(u8).initCapacity(gpa, preimage.len + sig_bytes.items.len);
            defer signed.deinit(gpa);
            try signed.appendSlice(gpa, preimage);
            try signed.appendSlice(gpa, sig_bytes.items);
            break :blk our_ed_kp.sign(signed.items);
        };

        // Payload: [sig(64)][current(32)][next(32)][keySeq(8)][seq(8)]
        var payload = try std.ArrayListUnmanaged(u8).initCapacity(gpa, 64 + 32 + 32 + 8 + 8);
        defer payload.deinit(gpa);
        try payload.appendSlice(gpa, &sig);
        try payload.appendSlice(gpa, &self.current);
        try payload.appendSlice(gpa, &self.next);
        try payload.appendSlice(gpa, &ksb);
        try payload.appendSlice(gpa, &sb);

        const ciphertext = boxSeal(payload.items, 0, &to_box, &from.secret_key, gpa) catch return error.Encode;
        errdefer gpa.free(ciphertext);

        // [type][fromPub][ciphertext]
        const data = try gpa.alloc(u8, 1 + 32 + ciphertext.len);
        data[0] = msg_type;
        @memcpy(data[1..33], &from.public_key);
        @memcpy(data[33..], ciphertext);
        gpa.free(ciphertext);
        return data;
    }

    /// Decrypt an init/ack message.
    pub fn decrypt(
        data: []const u8,
        our_curve_priv: *const CurvePrivateKey,
        from_ed_pub: *const PublicKey,
        preimage: []const u8,
        gpa: Allocator,
    ) !SessionInit {
        if (data.len != SESSION_INIT_SIZE) return error.Decode;
        var from_box: CurvePublicKey = undefined;
        @memcpy(&from_box, data[1..33]);

        const payload = boxOpen(data[33..], 0, &from_box, our_curve_priv, gpa) catch return error.Decode;
        defer gpa.free(payload);
        if (payload.len != 64 + 32 + 32 + 8 + 8) return error.Decode;

        var sig: Sig = undefined;
        @memcpy(&sig, payload[0..64]);
        var current: CurvePublicKey = undefined;
        @memcpy(&current, payload[64..96]);
        var next: CurvePublicKey = undefined;
        @memcpy(&next, payload[96..128]);
        const key_seq = std.mem.readInt(u64, payload[128..136], .big);
        const seq = std.mem.readInt(u64, payload[136..144], .big);

        // Verify: sigBytes = [fromBox][current][next][keySeq][seq]
        var sig_bytes = try std.ArrayListUnmanaged(u8).initCapacity(gpa, 32 + 32 + 32 + 8 + 8);
        defer sig_bytes.deinit(gpa);
        try sig_bytes.appendSlice(gpa, &from_box);
        try sig_bytes.appendSlice(gpa, &current);
        try sig_bytes.appendSlice(gpa, &next);
        var ksb: [8]u8 = undefined;
        std.mem.writeInt(u64, &ksb, key_seq, .big);
        try sig_bytes.appendSlice(gpa, &ksb);
        var sb: [8]u8 = undefined;
        std.mem.writeInt(u64, &sb, seq, .big);
        try sig_bytes.appendSlice(gpa, &sb);

        const verified = if (preimage.len == 0)
            Crypto.verify(from_ed_pub, sig_bytes.items, &sig)
        else blk: {
            var signed = try std.ArrayListUnmanaged(u8).initCapacity(gpa, preimage.len + sig_bytes.items.len);
            defer signed.deinit(gpa);
            try signed.appendSlice(gpa, preimage);
            try signed.appendSlice(gpa, sig_bytes.items);
            break :blk Crypto.verify(from_ed_pub, signed.items, &sig);
        };
        if (!verified) return error.BadMessage;

        return SessionInit{ .current = current, .next = next, .key_seq = key_seq, .seq = seq };
    }
};

// ---------------------------------------------------------------------------
// SessionInfo — active session with key ratcheting
// ---------------------------------------------------------------------------

pub const SessionInfo = struct {
    seq: u64,
    remote_key_seq: u64,
    current: CurvePublicKey,
    next: CurvePublicKey,
    local_key_seq: u64,
    recv_priv: CurvePrivateKey,
    recv_pub: CurvePublicKey,
    recv_shared: [Box.shared_length]u8,
    recv_nonce: u64,
    send_priv: CurvePrivateKey,
    send_pub: CurvePublicKey,
    send_shared: [Box.shared_length]u8,
    send_nonce: u64,
    next_priv: CurvePrivateKey,
    next_pub: CurvePublicKey,
    next_send_shared: [Box.shared_length]u8,
    next_send_nonce: u64,
    next_recv_shared: [Box.shared_length]u8,
    next_recv_nonce: u64,
    since_ns: u64,
    rotated_ns: ?u64,
    last_activity_ns: u64,
    rx: u64,
    tx: u64,

    pub fn init(current: CurvePublicKey, next: CurvePublicKey, seq: u64) !SessionInfo {
        const recv = try newBoxKeys();
        const send = try newBoxKeys();
        const next_kp = try newBoxKeys();

        return .{
            .seq = seq -% 1,
            .remote_key_seq = 0,
            .current = current,
            .next = next,
            .local_key_seq = 0,
            .recv_priv = recv.secret_key,
            .recv_pub = recv.public_key,
            .recv_shared = try makeSharedSecret(&current, &recv.secret_key),
            .recv_nonce = 0,
            .send_priv = send.secret_key,
            .send_pub = send.public_key,
            .send_shared = try makeSharedSecret(&current, &send.secret_key),
            .send_nonce = 0,
            .next_priv = next_kp.secret_key,
            .next_pub = next_kp.public_key,
            .next_send_shared = try makeSharedSecret(&next, &send.secret_key),
            .next_send_nonce = 0,
            .next_recv_shared = try makeSharedSecret(&next, &recv.secret_key),
            .next_recv_nonce = 0,
            .since_ns = monotonicNs(),
            .rotated_ns = null,
            .last_activity_ns = monotonicNs(),
            .rx = 0,
            .tx = 0,
        };
    }

    pub fn fixShared(self: *SessionInfo, recv_nonce: u64, send_nonce: u64) !void {
        self.recv_shared = try makeSharedSecret(&self.current, &self.recv_priv);
        self.send_shared = try makeSharedSecret(&self.current, &self.send_priv);
        self.next_send_shared = try makeSharedSecret(&self.next, &self.send_priv);
        self.next_recv_shared = try makeSharedSecret(&self.next, &self.recv_priv);
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }

    pub fn handleUpdate(self: *SessionInfo, si: *const SessionInit) !void {
        self.current = si.current;
        self.next = si.next;
        self.seq = si.seq;
        self.remote_key_seq = si.key_seq;

        // Ratchet: recv = send, send = next, new next
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv;
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv;
        const new_next = try newBoxKeys();
        self.next_pub = new_next.public_key;
        self.next_priv = new_next.secret_key;
        self.local_key_seq += 1;
        try self.fixShared(0, self.send_nonce);
        self.last_activity_ns = monotonicNs();
    }

    pub fn doSend(self: *SessionInfo, msg: []const u8, gpa: Allocator) ![]u8 {
        const snap = try self.sendSnapshot();
        const result = try encryptOutsideLock(&snap, msg, gpa);
        self.sendFinalize(@intCast(msg.len));
        return result;
    }

    pub fn sendSnapshot(self: *SessionInfo) !SendSnapshot {
        self.send_nonce += 1;
        if (self.send_nonce == 0) {
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            const new_next = try newBoxKeys();
            self.next_pub = new_next.public_key;
            self.next_priv = new_next.secret_key;
            self.local_key_seq += 1;
            try self.fixShared(0, 0);
        }
        return SendSnapshot{
            .local_key_seq = self.local_key_seq,
            .remote_key_seq = self.remote_key_seq,
            .send_nonce = self.send_nonce,
            .next_pub = self.next_pub,
            .send_shared = self.send_shared,
        };
    }

    pub fn sendFinalize(self: *SessionInfo, msg_len: u64) void {
        self.tx += msg_len;
        self.last_activity_ns = monotonicNs();
    }

    pub fn recvSnapshot(self: *const SessionInfo, msg: []const u8) RecvSnapshotResult {
        if (msg.len < SESSION_TRAFFIC_OVERHEAD_MIN or msg[0] != SESSION_TYPE_TRAFFIC)
            return .drop;

        var offset: usize = 1;
        const rks = wire.decodeUvarint(msg[offset..]) catch return .drop;
        offset += rks.len;
        const lks = wire.decodeUvarint(msg[offset..]) catch return .drop;
        offset += lks.len;
        const nonce_uv = wire.decodeUvarint(msg[offset..]) catch return .drop;
        offset += nonce_uv.len;

        const from_current = rks.value == self.remote_key_seq;
        const from_next = rks.value == self.remote_key_seq + 1;
        const to_recv = lks.value + 1 == self.local_key_seq;
        const to_send = lks.value == self.local_key_seq;

        if (from_current and to_recv) {
            if (!(self.recv_nonce < nonce_uv.value)) return .drop;
            return .{ .ok = .{
                .remote_key_seq = self.remote_key_seq,
                .nonce = nonce_uv.value,
                .encrypted_offset = offset,
                .shared = self.recv_shared,
                .case = .current_to_recv,
            } };
        } else if (from_next and to_send) {
            if (!(self.next_send_nonce < nonce_uv.value)) return .drop;
            return .{ .ok = .{
                .remote_key_seq = self.remote_key_seq,
                .nonce = nonce_uv.value,
                .encrypted_offset = offset,
                .shared = self.next_send_shared,
                .case = .next_to_send,
            } };
        } else if (from_next and to_recv) {
            if (!(self.next_recv_nonce < nonce_uv.value)) return .drop;
            return .{ .ok = .{
                .remote_key_seq = self.remote_key_seq,
                .nonce = nonce_uv.value,
                .encrypted_offset = offset,
                .shared = self.next_recv_shared,
                .case = .next_to_recv,
            } };
        } else {
            return .{ .send_init = .{
                .send_pub = self.send_pub,
                .next_pub = self.next_pub,
                .local_key_seq = self.local_key_seq,
            } };
        }
    }

    pub fn recvFinalize(self: *SessionInfo, snap: *const RecvSnapshot, inner_key: CurvePublicKey, payload_len: u64) !void {
        if (self.remote_key_seq != snap.remote_key_seq) {
            self.rx += payload_len;
            self.last_activity_ns = monotonicNs();
            return;
        }
        switch (snap.case) {
            .current_to_recv => self.recv_nonce = snap.nonce,
            .next_to_send => {
                self.next_send_nonce = snap.nonce;
                try self.maybeRatchetOnRecv(inner_key, snap.nonce);
            },
            .next_to_recv => {
                self.next_recv_nonce = snap.nonce;
                try self.maybeRatchetOnRecv(inner_key, snap.nonce);
            },
        }
        self.rx += payload_len;
        self.last_activity_ns = monotonicNs();
    }

    fn maybeRatchetOnRecv(self: *SessionInfo, inner_key: CurvePublicKey, nonce: u64) !void {
        const should_rotate = if (self.rotated_ns) |t|
            monotonicNs() - t > 60 * std.time.ns_per_s
        else
            true;
        if (should_rotate) {
            self.current = self.next;
            self.next = inner_key;
            self.remote_key_seq += 1;
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            self.local_key_seq += 1;
            const new_next = try newBoxKeys();
            self.next_pub = new_next.public_key;
            self.next_priv = new_next.secret_key;
            try self.fixShared(nonce, 0);
            self.rotated_ns = monotonicNs();
        }
    }

    pub fn isExpired(self: *const SessionInfo) bool {
        return monotonicNs() - self.last_activity_ns > SESSION_TIMEOUT_NS;
    }
};

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

pub const DecryptCase = enum { current_to_recv, next_to_send, next_to_recv };

pub const SendSnapshot = struct {
    local_key_seq: u64,
    remote_key_seq: u64,
    send_nonce: u64,
    next_pub: [32]u8,
    send_shared: [Box.shared_length]u8,
};

pub const RecvSnapshot = struct {
    remote_key_seq: u64,
    nonce: u64,
    encrypted_offset: usize,
    shared: [Box.shared_length]u8,
    case: DecryptCase,
};

pub const RecvSnapshotResult = union(enum) {
    drop,
    send_init: struct { send_pub: CurvePublicKey, next_pub: CurvePublicKey, local_key_seq: u64 },
    ok: RecvSnapshot,
};

// ---------------------------------------------------------------------------
// SessionBuffer
// ---------------------------------------------------------------------------

pub const SessionBuffer = struct {
    data: ?[]u8,
    init: SessionInit,
    current_priv: CurvePrivateKey,
    next_priv: CurvePrivateKey,
    created_ns: u64,

    pub fn deinit(self: *SessionBuffer, gpa: Allocator) void {
        if (self.data) |d| gpa.free(d);
        self.data = null;
    }
};

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn encryptOutsideLock(snap: *const SendSnapshot, msg: []const u8, gpa: Allocator) ![]u8 {
    var bs = try std.ArrayListUnmanaged(u8).initCapacity(gpa, SESSION_TRAFFIC_OVERHEAD_MIN + 9 + 9 + 9 + msg.len);
    errdefer bs.deinit(gpa);
    try bs.append(gpa, SESSION_TYPE_TRAFFIC);
    try wire.encodeUvarint(&bs, gpa, snap.local_key_seq);
    try wire.encodeUvarint(&bs, gpa, snap.remote_key_seq);
    try wire.encodeUvarint(&bs, gpa, snap.send_nonce);

    var inner = try std.ArrayListUnmanaged(u8).initCapacity(gpa, 32 + msg.len);
    defer inner.deinit(gpa);
    try inner.appendSlice(gpa, &snap.next_pub);
    try inner.appendSlice(gpa, msg);

    const ciphertext = boxSealPrecomputed(inner.items, snap.send_nonce, &snap.send_shared, gpa) catch return error.Encode;
    errdefer gpa.free(ciphertext);
    try bs.appendSlice(gpa, ciphertext);
    gpa.free(ciphertext);
    return bs.toOwnedSlice(gpa);
}

fn decryptOutsideLock(snap: *const RecvSnapshot, msg: []const u8, gpa: Allocator) !struct { data: []u8, inner_key: CurvePublicKey } {
    const encrypted = msg[snap.encrypted_offset..];
    const unboxed = boxOpenPrecomputed(encrypted, snap.nonce, &snap.shared, gpa) catch return error.SendInit;
    errdefer gpa.free(unboxed);
    if (unboxed.len < 32) { gpa.free(unboxed); return error.Drop; }
    var inner_key: CurvePublicKey = undefined;
    @memcpy(&inner_key, unboxed[0..32]);
    const data = try gpa.alloc(u8, unboxed.len - 32);
    @memcpy(data, unboxed[32..]);
    gpa.free(unboxed);
    return .{ .data = data, .inner_key = inner_key };
}

// ---------------------------------------------------------------------------
// OutAction
// ---------------------------------------------------------------------------

pub const OutAction = union(enum) {
    send_to_inner: struct { dest: PublicKey, data: []u8 },
    deliver: struct { source: PublicKey, data: []u8 },

    pub fn deinit(self: *OutAction, gpa: Allocator) void {
        switch (self.*) {
            .send_to_inner => |*a| gpa.free(a.data),
            .deliver => |*a| gpa.free(a.data),
        }
    }
};

pub fn deinitActions(gpa: Allocator, actions: []OutAction) void {
    for (actions) |*a| a.deinit(gpa);
    gpa.free(actions);
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

pub const SessionManager = struct {
    sessions: std.AutoHashMapUnmanaged(PublicKey, SessionInfo),
    buffers: std.AutoHashMapUnmanaged(PublicKey, SessionBuffer),
    group_auth: GroupAuth,
    gpa: Allocator,

    pub fn init(gpa: Allocator, group_auth: GroupAuth) SessionManager {
        return .{ .sessions = .{}, .buffers = .{}, .group_auth = group_auth, .gpa = gpa };
    }

    pub fn deinit(self: *SessionManager) void {
        self.sessions.deinit(self.gpa);
        var bit = self.buffers.iterator();
        while (bit.next()) |entry| entry.value_ptr.deinit(self.gpa);
        self.buffers.deinit(self.gpa);
    }

    pub fn handleData(
        self: *SessionManager,
        from_key: *const PublicKey,
        data: []const u8,
        our_curve_priv: *const CurvePrivateKey,
        our_ed_kp: *const Crypto,
    ) ![]OutAction {
        if (data.len == 0) return &[_]OutAction{};
        var actions = std.ArrayListUnmanaged(OutAction).empty;
        errdefer { for (actions.items) |*a| a.deinit(self.gpa); actions.deinit(self.gpa); }

        switch (data[0]) {
            SESSION_TYPE_INIT, SESSION_TYPE_ACK => {
                const hs = SessionInit.decrypt(data, our_curve_priv, from_key, self.group_auth.preimage(), self.gpa) catch return &[_]OutAction{};
                try self.handleInit(from_key, &hs, our_ed_kp, data[0], &actions);
            },
            SESSION_TYPE_TRAFFIC => try self.handleTraffic(from_key, data, our_ed_kp, &actions),
            else => {},
        }
        return actions.toOwnedSlice(self.gpa);
    }

    pub fn writeTo(
        self: *SessionManager,
        dest: *const PublicKey,
        msg: []const u8,
        our_ed_kp: *const Crypto,
    ) ![]OutAction {
        var actions = std.ArrayListUnmanaged(OutAction).empty;
        errdefer { for (actions.items) |*a| a.deinit(self.gpa); actions.deinit(self.gpa); }

        if (self.sessions.getPtr(dest.*)) |session| {
            const encrypted = session.doSend(msg, self.gpa) catch |err| {
                if (err == error.Encode) return &[_]OutAction{};
                return err;
            };
            try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = dest.*, .data = encrypted } });
        } else if (self.buffers.getPtr(dest.*)) |buf| {
            if (buf.data) |old| self.gpa.free(old);
            buf.data = try self.gpa.dupe(u8, msg);
        } else {
            const current = try newBoxKeys();
            const next = try newBoxKeys();
            const hs = SessionInit.init(&current.public_key, &next.public_key, 0);
            const buf = SessionBuffer{
                .data = try self.gpa.dupe(u8, msg),
                .init = hs,
                .current_priv = current.secret_key,
                .next_priv = next.secret_key,
                .created_ns = monotonicNs(),
            };
            try self.buffers.put(self.gpa, dest.*, buf);
            const encrypted = try hs.encrypt(our_ed_kp, dest, SESSION_TYPE_INIT, self.group_auth.preimage(), self.gpa);
            try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = dest.*, .data = encrypted } });
        }
        return actions.toOwnedSlice(self.gpa);
    }

    fn handleInit(
        self: *SessionManager,
        from_key: *const PublicKey,
        hs: *const SessionInit,
        our_ed_kp: *const Crypto,
        msg_type: u8,
        actions: *std.ArrayListUnmanaged(OutAction),
    ) !void {
        if (self.sessions.getPtr(from_key.*)) |session| {
            if (hs.seq > session.seq) {
                try session.handleUpdate(hs);
                if (self.buffers.getPtr(from_key.*)) |buf| {
                    if (buf.data) |d| {
                        const encrypted = try session.doSend(d, self.gpa);
                        try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = from_key.*, .data = encrypted } });
                        self.gpa.free(d);
                        buf.data = null;
                    }
                }
            }
            if (msg_type == SESSION_TYPE_INIT) {
                const ack_init = SessionInit.init(&session.send_pub, &session.next_pub, session.local_key_seq);
                const ack = try ack_init.encrypt(our_ed_kp, from_key, SESSION_TYPE_ACK, self.group_auth.preimage(), self.gpa);
                try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = from_key.*, .data = ack } });
            }
        } else {
            var session = try SessionInfo.init(hs.current, hs.next, hs.seq);
            // If we already sent our own Init for this peer (buffered while
            // waiting for a reply), reuse those same keys as our session's
            // send/next keys instead of freshly-generated ones -- otherwise
            // the peer never learns the keys we actually committed to, and
            // both sides loop forever re-sending Inits (see reference
            // ironwood's `_sessionForInit`).
            if (self.buffers.getPtr(from_key.*)) |buf| {
                session.send_pub = buf.init.current;
                session.send_priv = buf.current_priv;
                session.next_pub = buf.init.next;
                session.next_priv = buf.next_priv;
                try session.fixShared(0, 0);
            }
            try session.handleUpdate(hs);
            if (self.buffers.getPtr(from_key.*)) |buf| {
                if (buf.data) |d| {
                    const encrypted = try session.doSend(d, self.gpa);
                    try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = from_key.*, .data = encrypted } });
                    self.gpa.free(d);
                    buf.data = null;
                }
                if (self.buffers.fetchRemove(from_key.*)) |kv| {
                    var b = kv.value;
                    b.deinit(self.gpa);
                }
            }
            try self.sessions.put(self.gpa, from_key.*, session);
            if (msg_type == SESSION_TYPE_INIT) {
                const ack_init = SessionInit.init(&session.send_pub, &session.next_pub, session.local_key_seq);
                const ack = try ack_init.encrypt(our_ed_kp, from_key, SESSION_TYPE_ACK, self.group_auth.preimage(), self.gpa);
                try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = from_key.*, .data = ack } });
            }
        }
    }

    fn handleTraffic(
        self: *SessionManager,
        from_key: *const PublicKey,
        data: []const u8,
        our_ed_kp: *const Crypto,
        actions: *std.ArrayListUnmanaged(OutAction),
    ) !void {
        const session = self.sessions.getPtr(from_key.*) orelse return;

        switch (session.recvSnapshot(data)) {
            .drop => return,
            .send_init => |si| {
                const ri = SessionInit.init(&si.send_pub, &si.next_pub, si.local_key_seq);
                const encrypted = ri.encrypt(our_ed_kp, from_key, SESSION_TYPE_INIT, self.group_auth.preimage(), self.gpa) catch return;
                try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = from_key.*, .data = encrypted } });
            },
            .ok => |snap| {
                const decrypted = decryptOutsideLock(&snap, data, self.gpa) catch |err| {
                    if (err == error.SendInit) {
                        const si = try session.sendSnapshot();
                        const ri = SessionInit.init(&si.next_pub, &si.next_pub, si.local_key_seq);
                        const encrypted = ri.encrypt(our_ed_kp, from_key, SESSION_TYPE_INIT, self.group_auth.preimage(), self.gpa) catch return;
                        try actions.append(self.gpa, .{ .send_to_inner = .{ .dest = from_key.*, .data = encrypted } });
                    }
                    return;
                };
                defer self.gpa.free(decrypted.data);
                const payload_len: u64 = @intCast(decrypted.data.len);
                session.recvFinalize(&snap, decrypted.inner_key, payload_len) catch {};
                const owned = try self.gpa.dupe(u8, decrypted.data);
                try actions.append(self.gpa, .{ .deliver = .{ .source = from_key.*, .data = owned } });
            },
        }
    }

    pub fn cleanupExpired(self: *SessionManager) void {
        var to_remove = std.ArrayListUnmanaged(PublicKey).empty;
        defer to_remove.deinit(self.gpa);
        {
            var it = self.sessions.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.isExpired())
                    to_remove.append(self.gpa, entry.key_ptr.*) catch {};
            }
        }
        for (to_remove.items) |k| { _ = self.sessions.remove(k); }

        to_remove.clearRetainingCapacity();
        {
            var it = self.buffers.iterator();
            while (it.next()) |entry| {
                if (monotonicNs() - entry.value_ptr.created_ns > SESSION_TIMEOUT_NS)
                    to_remove.append(self.gpa, entry.key_ptr.*) catch {};
            }
        }
        for (to_remove.items) |k| {
            if (self.buffers.fetchRemove(k)) |kv| { var buf = kv.value; buf.deinit(self.gpa); }
        }
    }

    pub fn getAllSessions(self: *const SessionManager) ![]SessionSnapshot {
        var result = try std.ArrayListUnmanaged(SessionSnapshot).initCapacity(self.gpa, self.sessions.count());
        errdefer result.deinit(self.gpa);
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            try result.append(self.gpa, .{
                .key = entry.key_ptr.*,
                .tx = entry.value_ptr.tx,
                .rx = entry.value_ptr.rx,
                .since_ns = entry.value_ptr.since_ns,
            });
        }
        return result.toOwnedSlice(self.gpa);
    }
};

pub const SessionSnapshot = struct { key: PublicKey, tx: u64, rx: u64, since_ns: u64 };

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

fn wallClockSeconds() u64 {
    if (@import("builtin").os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.REALTIME, &ts) == 0 and ts.sec > 0)
            return @intCast(ts.sec);
    }
    return 0;
}

fn monotonicNs() u64 {
    if (@import("builtin").os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.MONOTONIC, &ts) == 0)
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }
    // Fallback: use a simple counter
    const static = struct {
        var counter: u64 = 0;
    };
    static.counter += 1;
    return static.counter;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeCrypto() Crypto {
    return Crypto.generate();
}

test "session init encrypt decrypt" {
    const gpa = testing.allocator;
    const a = makeCrypto();
    const b = makeCrypto();
    const curve_priv_b = enc_crypto.ed25519PrivateToCurve25519(b.key_pair) catch unreachable;

    const current = try newBoxKeys();
    const next = try newBoxKeys();
    const hs = SessionInit.init(&current.public_key, &next.public_key, 0);

    const encrypted = try hs.encrypt(&a, &b.public_key, SESSION_TYPE_INIT, &.{}, gpa);
    defer gpa.free(encrypted);
    try testing.expectEqual(SESSION_INIT_SIZE, encrypted.len);
    try testing.expectEqual(SESSION_TYPE_INIT, encrypted[0]);

    const decrypted = try SessionInit.decrypt(encrypted, &curve_priv_b, &b.public_key, &.{}, gpa);
    try testing.expectEqualSlices(u8, &current.public_key, &decrypted.current);
    try testing.expectEqualSlices(u8, &next.public_key, &decrypted.next);
    try testing.expectEqual(@as(u64, 0), decrypted.key_seq);
}

test "session ack encrypt decrypt" {
    const gpa = testing.allocator;
    const a = makeCrypto();
    const b = makeCrypto();
    const curve_priv_b = enc_crypto.ed25519PrivateToCurve25519(b.key_pair) catch unreachable;

    const current = try newBoxKeys();
    const next = try newBoxKeys();
    const hs = SessionInit.init(&current.public_key, &next.public_key, 5);

    const encrypted = try hs.encrypt(&a, &b.public_key, SESSION_TYPE_ACK, &.{}, gpa);
    defer gpa.free(encrypted);
    try testing.expectEqual(SESSION_TYPE_ACK, encrypted[0]);

    const decrypted = try SessionInit.decrypt(encrypted, &curve_priv_b, &b.public_key, &.{}, gpa);
    try testing.expectEqual(@as(u64, 5), decrypted.key_seq);
}

test "group password handshake matrix" {
    const gpa = testing.allocator;
    const cases = [_]struct { sender_pw: []const u8, receiver_pw: []const u8, want_ok: bool }{
        .{ .sender_pw = "", .receiver_pw = "", .want_ok = true },
        .{ .sender_pw = "shared", .receiver_pw = "shared", .want_ok = true },
        .{ .sender_pw = "shared", .receiver_pw = "", .want_ok = false },
        .{ .sender_pw = "", .receiver_pw = "shared", .want_ok = false },
        .{ .sender_pw = "shared", .receiver_pw = "wrong", .want_ok = false },
    };

    for (cases) |c| {
        const a = makeCrypto();
        const b = makeCrypto();
        const curve_priv_b = enc_crypto.ed25519PrivateToCurve25519(b.key_pair) catch unreachable;

        const current = try newBoxKeys();
        const next = try newBoxKeys();
        const hs = SessionInit.init(&current.public_key, &next.public_key, 9);

        const sender_auth = GroupAuth.init(c.sender_pw);
        const receiver_auth = GroupAuth.init(c.receiver_pw);

        const data = try hs.encrypt(&a, &b.public_key, SESSION_TYPE_INIT, sender_auth.preimage(), gpa);
        defer gpa.free(data);

        const result = SessionInit.decrypt(data, &curve_priv_b, &b.public_key, receiver_auth.preimage(), gpa);
        if (c.want_ok) {
            const decoded = try result;
            try testing.expectEqualSlices(u8, &current.public_key, &decoded.current);
            try testing.expectEqualSlices(u8, &next.public_key, &decoded.next);
            try testing.expectEqual(@as(u64, 9), decoded.key_seq);
        } else {
            try testing.expectError(error.BadMessage, result);
        }
    }
}

test "session send recv" {
    const gpa = testing.allocator;
    const a = makeCrypto();
    const b = makeCrypto();
    const curve_priv_a = enc_crypto.ed25519PrivateToCurve25519(a.key_pair) catch unreachable;
    const curve_priv_b = enc_crypto.ed25519PrivateToCurve25519(b.key_pair) catch unreachable;

    var mgr_a = SessionManager.init(gpa, GroupAuth.init(""));
    defer mgr_a.deinit();
    var mgr_b = SessionManager.init(gpa, GroupAuth.init(""));
    defer mgr_b.deinit();

    // A writes to B (creates buffer + init)
    const a_actions = try mgr_a.writeTo(&b.public_key, "hello from A", &a);
    defer deinitActions(gpa, a_actions);
    try testing.expectEqual(@as(usize, 1), a_actions.len); // SendToInner (init)

    // B receives init
    switch (a_actions[0]) {
        .send_to_inner => |si| {
            try testing.expectEqualSlices(u8, &b.public_key, &si.dest);
            const b_actions = try mgr_b.handleData(&a.public_key, si.data, &curve_priv_b, &b);
            defer deinitActions(gpa, b_actions);
            try testing.expect(b_actions.len > 0);

            // B's ack back to A
            for (b_actions) |ba| {
                switch (ba) {
                    .send_to_inner => |bsi| {
                        try testing.expectEqualSlices(u8, &a.public_key, &bsi.dest);
                        const a2_actions = try mgr_a.handleData(&b.public_key, bsi.data, &curve_priv_a, &a);
                        defer deinitActions(gpa, a2_actions);

                        // A should send buffered traffic
                        for (a2_actions) |a2a| {
                            switch (a2a) {
                                .send_to_inner => |a2si| {
                                    try testing.expectEqualSlices(u8, &b.public_key, &a2si.dest);
                                    const b2_actions = try mgr_b.handleData(&a.public_key, a2si.data, &curve_priv_b, &b);
                                    defer deinitActions(gpa, b2_actions);
                                    for (b2_actions) |b2a| {
                                        switch (b2a) {
                                            .deliver => |d| {
                                                try testing.expectEqualSlices(u8, &a.public_key, &d.source);
                                                try testing.expectEqualSlices(u8, "hello from A", d.data);
                                                return; // success!
                                            },
                                            else => {},
                                        }
                                    }
                                },
                                else => {},
                            }
                        }
                    },
                    else => {},
                }
            }
        },
        else => unreachable,
    }
    try testing.expect(false); // should have returned early
}

test "session bidirectional" {
    const gpa = testing.allocator;
    const a = makeCrypto();
    const b = makeCrypto();
    const curve_priv_a = enc_crypto.ed25519PrivateToCurve25519(a.key_pair) catch unreachable;
    const curve_priv_b = enc_crypto.ed25519PrivateToCurve25519(b.key_pair) catch unreachable;

    var mgr_a = SessionManager.init(gpa, GroupAuth.init(""));
    defer mgr_a.deinit();
    var mgr_b = SessionManager.init(gpa, GroupAuth.init(""));
    defer mgr_b.deinit();

    // Establish: A -> B init, B -> A ack
    const a_actions = try mgr_a.writeTo(&b.public_key, "msg1", &a);
    defer deinitActions(gpa, a_actions);

    const init_data = switch (a_actions[0]) {
        .send_to_inner => |si| si.data,
        else => unreachable,
    };
    const init_dup = try gpa.dupe(u8, init_data);
    defer gpa.free(init_dup);

    const b_actions = try mgr_b.handleData(&a.public_key, init_dup, &curve_priv_b, &b);
    defer deinitActions(gpa, b_actions);

    const ack_data = for (b_actions) |ba| {
        switch (ba) {
            .send_to_inner => |bsi| break bsi.data,
            else => {},
        }
    } else unreachable;
    const ack_dup = try gpa.dupe(u8, ack_data);
    defer gpa.free(ack_dup);

    const a2_actions = try mgr_a.handleData(&b.public_key, ack_dup, &curve_priv_a, &a);
    defer deinitActions(gpa, a2_actions);

    // Process A's buffered traffic -> B should receive "msg1"
    var delivered = false;
    for (a2_actions) |a2a| {
        switch (a2a) {
            .send_to_inner => |a2si| {
                const buf2 = try gpa.dupe(u8, a2si.data);
                defer gpa.free(buf2);
                const b2_actions = try mgr_b.handleData(&a.public_key, buf2, &curve_priv_b, &b);
                defer deinitActions(gpa, b2_actions);
                for (b2_actions) |b2a| {
                    switch (b2a) {
                        .deliver => |d| {
                            try testing.expectEqualSlices(u8, "msg1", d.data);
                            delivered = true;
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }
    try testing.expect(delivered);

    // Now B -> A (session exists)
    const b_send = try mgr_b.writeTo(&a.public_key, "msg2", &b);
    defer deinitActions(gpa, b_send);
    for (b_send) |bs| {
        switch (bs) {
            .send_to_inner => |bsi| {
                const buf3 = try gpa.dupe(u8, bsi.data);
                defer gpa.free(buf3);
                const a3_actions = try mgr_a.handleData(&b.public_key, buf3, &curve_priv_a, &a);
                defer deinitActions(gpa, a3_actions);
                for (a3_actions) |a3a| {
                    switch (a3a) {
                        .deliver => |d| {
                            try testing.expectEqualSlices(u8, "msg2", d.data);
                            return; // success
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }
    try testing.expect(false);
}
