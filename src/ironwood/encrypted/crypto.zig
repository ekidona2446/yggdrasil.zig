//! Cryptographic primitives for the encrypted layer.
//!
//! - Ed25519 <-> Curve25519 key conversion via X25519
//! - XSalsa20-Poly1305 authenticated encryption via std.crypto.nacl.Box
//! - Nonce construction from u64 counters (wire-compatible with Go)
//! - GroupAuth: closed-network shared-secret handshake gate

const std = @import("std");
const Box = std.crypto.nacl.Box;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

const ironwood_crypto = @import("../crypto.zig");

// ---------------------------------------------------------------------------
// Public type aliases
// ---------------------------------------------------------------------------

/// Curve25519 public key (32 bytes).
pub const CurvePublicKey = [X25519.public_length]u8;

/// Curve25519 private key (32 bytes).
pub const CurvePrivateKey = [X25519.secret_length]u8;

/// XSalsa20-Poly1305 overhead (Poly1305 authentication tag, 16 bytes).
pub const BOX_OVERHEAD: usize = Box.tag_length;

/// XSalsa20-Poly1305 nonce size (24 bytes).
pub const BOX_NONCE_SIZE: usize = Box.nonce_length;

// ---------------------------------------------------------------------------
// Group password (closed-network session auth)
// ---------------------------------------------------------------------------

/// Optional shared-secret gate for the session handshake.
/// Matches Go ironwood's `groupAuth`.
pub const GroupAuth = struct {
    secret: ?[32]u8,

    /// Build from a password. An empty password disables the feature.
    pub fn init(password: []const u8) GroupAuth {
        if (password.len == 0) return .{ .secret = null };
        var hasher = Sha256.init(.{});
        hasher.update("ironwood/encrypted\x00");
        hasher.update(password);
        var secret: [32]u8 = undefined;
        hasher.final(&secret);
        return .{ .secret = secret };
    }

    /// The signature preimage: 32-byte secret or empty slice if disabled.
    pub fn preimage(self: *const GroupAuth) []const u8 {
        if (self.secret) |*s| return s;
        return &.{};
    }
};

// ---------------------------------------------------------------------------
// Ed25519 -> Curve25519 conversion
// ---------------------------------------------------------------------------

/// Convert an Ed25519 public key to a Curve25519 (Montgomery) public key.
pub fn ed25519PublicToCurve25519(ed_pub: [32]u8) !CurvePublicKey {
    const pub_key = try Ed25519.PublicKey.fromBytes(ed_pub);
    return try X25519.publicKeyFromEd25519(pub_key);
}

/// Convert an Ed25519 KeyPair to a Curve25519 secret key.
pub fn ed25519PrivateToCurve25519(kp: Ed25519.KeyPair) !CurvePrivateKey {
    const xkp = try X25519.KeyPair.fromEd25519(kp);
    return xkp.secret_key;
}

// ---------------------------------------------------------------------------
// XSalsa20-Poly1305 encryption (NaCl Box)
// ---------------------------------------------------------------------------

/// A Curve25519 key pair.
pub const BoxKeyPair = struct {
    public_key: CurvePublicKey,
    secret_key: CurvePrivateKey,
};

/// Generate a new random Curve25519 keypair.
pub fn newBoxKeys() !BoxKeyPair {
    var seed: [X25519.seed_length]u8 = undefined;
    ironwood_crypto.secureRandomBytes(&seed);
    const kp = try X25519.KeyPair.generateDeterministic(seed);
    return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
}

/// Encrypt a message using XSalsa20-Poly1305. Caller owns the returned buffer.
pub fn boxSeal(
    msg: []const u8,
    nonce: u64,
    their_pub: *const CurvePublicKey,
    our_priv: *const CurvePrivateKey,
    alloc: std.mem.Allocator,
) ![]u8 {
    const nonce_bytes = nonceForU64(nonce);
    const out = try alloc.alloc(u8, msg.len + BOX_OVERHEAD);
    errdefer alloc.free(out);
    try Box.seal(out, msg, nonce_bytes, their_pub.*, our_priv.*);
    return out;
}

/// Decrypt a message using XSalsa20-Poly1305. Caller owns the returned buffer.
pub fn boxOpen(
    ciphertext: []const u8,
    nonce: u64,
    their_pub: *const CurvePublicKey,
    our_priv: *const CurvePrivateKey,
    alloc: std.mem.Allocator,
) ![]u8 {
    if (ciphertext.len < BOX_OVERHEAD) return error.AuthenticationFailed;
    const nonce_bytes = nonceForU64(nonce);
    const out = try alloc.alloc(u8, ciphertext.len - BOX_OVERHEAD);
    errdefer alloc.free(out);
    try Box.open(out, ciphertext, nonce_bytes, their_pub.*, our_priv.*);
    return out;
}

/// Encrypt with a precomputed shared key.
pub fn boxSealPrecomputed(
    msg: []const u8,
    nonce: u64,
    shared_key: *const [Box.shared_length]u8,
    alloc: std.mem.Allocator,
) ![]u8 {
    const nonce_bytes = nonceForU64(nonce);
    const out = try alloc.alloc(u8, msg.len + BOX_OVERHEAD);
    errdefer alloc.free(out);
    std.crypto.nacl.SecretBox.seal(out, msg, nonce_bytes, shared_key.*);
    return out;
}

/// Decrypt with a precomputed shared key.
pub fn boxOpenPrecomputed(
    ciphertext: []const u8,
    nonce: u64,
    shared_key: *const [Box.shared_length]u8,
    alloc: std.mem.Allocator,
) ![]u8 {
    if (ciphertext.len < BOX_OVERHEAD) return error.AuthenticationFailed;
    const nonce_bytes = nonceForU64(nonce);
    const out = try alloc.alloc(u8, ciphertext.len - BOX_OVERHEAD);
    errdefer alloc.free(out);
    try std.crypto.nacl.SecretBox.open(out, ciphertext, nonce_bytes, shared_key.*);
    return out;
}

/// Create a precomputed shared secret from keypair.
pub fn makeSharedSecret(
    their_pub: *const CurvePublicKey,
    our_priv: *const CurvePrivateKey,
) ![Box.shared_length]u8 {
    return Box.createSharedSecret(their_pub.*, our_priv.*);
}

/// Convert a u64 counter to a 24-byte XSalsa20 nonce.
/// Format: 16 zero bytes + 8 bytes big-endian u64. Matches Go's `nonceForUint64`.
pub fn nonceForU64(value: u64) [BOX_NONCE_SIZE]u8 {
    var nonce: [BOX_NONCE_SIZE]u8 = [_]u8{0} ** BOX_NONCE_SIZE;
    std.mem.writeInt(u64, nonce[16..24], value, .big);
    return nonce;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "nonce format" {
    const n0 = nonceForU64(0);
    try testing.expectEqualSlices(u8, &[_]u8{0} ** 24, &n0);

    const n1 = nonceForU64(1);
    var expected1 = [_]u8{0} ** 24;
    expected1[23] = 1;
    try testing.expectEqualSlices(u8, &expected1, &n1);

    const n256 = nonceForU64(256);
    var expected256 = [_]u8{0} ** 24;
    expected256[22] = 1;
    try testing.expectEqualSlices(u8, &expected256, &n256);
}

test "box seal and open" {
    const a = try newBoxKeys();
    const b = try newBoxKeys();
    const alloc = testing.allocator;

    const msg = "hello world";
    const ct = try boxSeal(msg, 42, &b.public_key, &a.secret_key, alloc);
    defer alloc.free(ct);
    try testing.expect(!std.mem.eql(u8, ct, msg));
    try testing.expectEqual(msg.len + BOX_OVERHEAD, ct.len);

    const pt = try boxOpen(ct, 42, &a.public_key, &b.secret_key, alloc);
    defer alloc.free(pt);
    try testing.expectEqualSlices(u8, msg, pt);
}

test "box wrong nonce fails" {
    const a = try newBoxKeys();
    const b = try newBoxKeys();
    const alloc = testing.allocator;

    const msg = "secret";
    const ct = try boxSeal(msg, 1, &b.public_key, &a.secret_key, alloc);
    defer alloc.free(ct);
    const result = boxOpen(ct, 2, &a.public_key, &b.secret_key, alloc);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "ed25519 to curve25519 roundtrip" {
    const kp_a = Ed25519.KeyPair.generate(std.testing.io);
    const kp_b = Ed25519.KeyPair.generate(std.testing.io);

    const curve_priv_a = try ed25519PrivateToCurve25519(kp_a);
    const curve_priv_b = try ed25519PrivateToCurve25519(kp_b);

    const pub_a_ed = kp_a.public_key.toBytes();
    const pub_b_ed = kp_b.public_key.toBytes();

    const curve_pub_a = try ed25519PublicToCurve25519(pub_a_ed);
    const curve_pub_b = try ed25519PublicToCurve25519(pub_b_ed);

    const alloc = testing.allocator;
    const msg = "test message for encryption";
    const ct = try boxSeal(msg, 0, &curve_pub_b, &curve_priv_a, alloc);
    defer alloc.free(ct);
    const pt = try boxOpen(ct, 0, &curve_pub_a, &curve_priv_b, alloc);
    defer alloc.free(pt);
    try testing.expectEqualSlices(u8, msg, pt);
}

test "precomputed box matches direct" {
    const a = try newBoxKeys();
    const b = try newBoxKeys();
    const alloc = testing.allocator;

    const msg = "precomputed test";

    // Direct
    const ct1 = try boxSeal(msg, 5, &b.public_key, &a.secret_key, alloc);
    defer alloc.free(ct1);

    // Precomputed
    const shared = try makeSharedSecret(&b.public_key, &a.secret_key);
    const ct2 = try boxSealPrecomputed(msg, 5, &shared, alloc);
    defer alloc.free(ct2);

    // Both should produce same ciphertext
    try testing.expectEqualSlices(u8, ct1, ct2);

    // Both should decrypt with other side
    const pt1 = try boxOpen(ct1, 5, &a.public_key, &b.secret_key, alloc);
    defer alloc.free(pt1);
    try testing.expectEqualSlices(u8, msg, pt1);

    const shared2 = try makeSharedSecret(&a.public_key, &b.secret_key);
    const pt2 = try boxOpenPrecomputed(ct2, 5, &shared2, alloc);
    defer alloc.free(pt2);
    try testing.expectEqualSlices(u8, msg, pt2);
}

test "group auth preimage matches go" {
    // sha256("ironwood/encrypted\x00" + "shared-password")
    const auth = GroupAuth.init("shared-password");
    const expected = [_]u8{
        0x16, 0xcc, 0xb8, 0x39, 0x6e, 0xd9, 0xc5, 0x3e,
        0x85, 0xc3, 0x69, 0xad, 0xb6, 0xb3, 0xbe, 0xfc,
        0xb2, 0x75, 0xa7, 0x5b, 0xc1, 0x85, 0xbc, 0xbd,
        0x5f, 0x01, 0xf4, 0xc6, 0xfa, 0x54, 0xfe, 0xe8,
    };
    try testing.expectEqualSlices(u8, &expected, auth.preimage());

    const auth2 = GroupAuth.init("");
    try testing.expectEqual(@as(usize, 0), auth2.preimage().len);
}
