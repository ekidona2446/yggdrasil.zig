//! Signed PacketConn support.
//!
//! Provides Ed25519 signature authentication (no encryption) for restricted
//! networks (e.g. amateur radio) where encryption is prohibited but
//! authentication is desired. Each packet is prefixed with a 64-byte signature
//! on send and verified on read.
//!
//! This module currently implements the *pure* signing/verification logic
//! (`sign` / `unpack`), which is deterministic and fully testable. The async
//! `SignedPacketConn` wrapper (background reader loop, mpsc channels, and the
//! underlying `PacketConnImpl`) is deferred until `core.zig` and the libxev
//! async layer are ported — see `Pending` below.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cryptomod = @import("crypto.zig");
const Crypto = cryptomod.Crypto;
const PublicKey = cryptomod.PublicKey;
const Sig = cryptomod.Sig;
const SIGNATURE_SIZE = cryptomod.SIGNATURE_SIZE;
const PUBLIC_KEY_SIZE = cryptomod.PUBLIC_KEY_SIZE;

/// Channel capacity for delivering verified traffic to readers (used by the
/// async wrapper once ported).
pub const RECV_CHANNEL_SIZE: usize = 64;

/// Sign `msg` for a specific recipient `to_key`.
///
/// Signs the concatenation `[to_key || msg]` with our identity and returns a
/// freshly-allocated buffer `[signature(64) || msg]`. Caller owns the result.
pub fn sign(gpa: Allocator, id: *const Crypto, to_key: *const PublicKey, msg: []const u8) Allocator.Error![]u8 {
    // Build the signing input: to_key || msg.
    var sig_input = try gpa.alloc(u8, PUBLIC_KEY_SIZE + msg.len);
    defer gpa.free(sig_input);
    @memcpy(sig_input[0..PUBLIC_KEY_SIZE], to_key);
    @memcpy(sig_input[PUBLIC_KEY_SIZE..], msg);

    const signature: Sig = id.sign(sig_input);

    // Output: signature || msg.
    const out = try gpa.alloc(u8, SIGNATURE_SIZE + msg.len);
    errdefer gpa.free(out);
    @memcpy(out[0..SIGNATURE_SIZE], &signature);
    @memcpy(out[SIGNATURE_SIZE..], msg);
    return out;
}

/// Verify and unpack a signed message.
///
/// Verifies the signature over `[our_pub || msg]` against the sender's key
/// `from_key`. On success returns a freshly-allocated copy of `msg` (caller
/// owns it); on failure (too short or bad signature) returns `null`.
pub fn unpack(
    gpa: Allocator,
    our_pub: *const PublicKey,
    bs: []const u8,
    from_key: *const PublicKey,
) Allocator.Error!?[]u8 {
    if (bs.len < SIGNATURE_SIZE) return null;

    var signature: Sig = undefined;
    @memcpy(&signature, bs[0..SIGNATURE_SIZE]);
    const msg = bs[SIGNATURE_SIZE..];

    // Verification input: our_pub || msg.
    var sig_input = try gpa.alloc(u8, PUBLIC_KEY_SIZE + msg.len);
    defer gpa.free(sig_input);
    @memcpy(sig_input[0..PUBLIC_KEY_SIZE], our_pub);
    @memcpy(sig_input[PUBLIC_KEY_SIZE..], msg);

    if (Crypto.verify(from_key, sig_input, &signature)) {
        return try gpa.dupe(u8, msg);
    }
    return null;
}

/// MTU overhead added by the signed wrapper (the prepended signature).
pub const SIGNED_OVERHEAD: u64 = SIGNATURE_SIZE;

// ---------------------------------------------------------------------------
// Pending: async SignedPacketConn wrapper.
//
// The full `SignedPacketConn` wraps `core::PacketConnImpl`
// with a background reader loop that verifies signatures and forwards verified
// traffic over a channel. It implements the `PacketConn` trait:
//   read_from / write_to / handle_conn / is_closed / private_key / mtu /
//   send_lookup / close / local_addr
// Porting it requires:
//   1. `core.zig` (PacketConnImpl) — not yet ported.
//   2. The libxev async layer + an mpsc-style channel + cancellation.
// `mtu()` will be `inner.mtu() -| SIGNED_OVERHEAD`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "sign produces signature||msg of expected length" {
    const gpa = testing.allocator;
    const id = Crypto.generate();
    const to_key = [_]u8{0xBB} ** 32;
    const msg = "hello world";

    const signed = try sign(gpa, &id, &to_key, msg);
    defer gpa.free(signed);
    try testing.expectEqual(SIGNATURE_SIZE + msg.len, signed.len);
    try testing.expectEqualSlices(u8, msg, signed[SIGNATURE_SIZE..]);
}

test "sign and unpack roundtrip" {
    const gpa = testing.allocator;
    const a = Crypto.generate(); // sender
    const b = Crypto.generate(); // recipient
    const msg = "hello world";

    // A signs a message destined for B (signs over B's pub key || msg).
    const signed = try sign(gpa, &a, &b.public_key, msg);
    defer gpa.free(signed);

    // B unpacks it, verifying against its own pub key and A's key.
    const unpacked = try unpack(gpa, &b.public_key, signed, &a.public_key);
    try testing.expect(unpacked != null);
    defer gpa.free(unpacked.?);
    try testing.expectEqualSlices(u8, msg, unpacked.?);
}

test "unpack with wrong recipient key fails" {
    const gpa = testing.allocator;
    const a = Crypto.generate();
    const b = Crypto.generate();
    const msg = "secret";

    const signed = try sign(gpa, &a, &b.public_key, msg);
    defer gpa.free(signed);

    // Verifying against A's pub key (wrong recipient) must fail.
    const wrong = try unpack(gpa, &a.public_key, signed, &a.public_key);
    try testing.expect(wrong == null);
}

test "unpack with wrong sender key fails" {
    const gpa = testing.allocator;
    const a = Crypto.generate();
    const b = Crypto.generate();
    const c = Crypto.generate(); // impostor
    const msg = "secret";

    const signed = try sign(gpa, &a, &b.public_key, msg);
    defer gpa.free(signed);

    // Correct recipient B, but claim the sender was C -> verification fails.
    const wrong = try unpack(gpa, &b.public_key, signed, &c.public_key);
    try testing.expect(wrong == null);
}

test "unpack rejects too-short input" {
    const gpa = testing.allocator;
    const our = [_]u8{0x01} ** 32;
    const from = [_]u8{0x02} ** 32;
    const short = [_]u8{0} ** (SIGNATURE_SIZE - 1);
    const r = try unpack(gpa, &our, &short, &from);
    try testing.expect(r == null);
}

test "tampered payload fails verification" {
    const gpa = testing.allocator;
    const a = Crypto.generate();
    const b = Crypto.generate();
    const msg = "important";

    const signed = try sign(gpa, &a, &b.public_key, msg);
    defer gpa.free(signed);

    // Flip a byte in the payload portion.
    var tampered = try gpa.dupe(u8, signed);
    defer gpa.free(tampered);
    tampered[SIGNATURE_SIZE] ^= 0xFF;

    const r = try unpack(gpa, &b.public_key, tampered, &a.public_key);
    try testing.expect(r == null);
}
