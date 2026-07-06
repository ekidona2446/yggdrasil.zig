//! Cryptographic identity for ironwood.
//!
//! Uses Ed25519 (std.crypto.sign.Ed25519), wire-compatible with the
//! ed25519-dalek based reference implementation.

const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const Ed25519 = std.crypto.sign.Ed25519;
const timemod = @import("util").time;

/// Fill `buf` with cryptographically secure random bytes.
///
/// Zig 0.16 moved randomness behind the new `std.Io` interface, so there is
/// no ambient `std.crypto.random` anymore. We use the platform's native CSPRNG
/// entry point directly:
///   - Linux: `getrandom(2)` syscall (works on any glibc/musl version, no
///     libc feature-detection needed).
///   - macOS/*BSD/other libc targets that provide it: `arc4random_buf`,
///     which never fails and needs no error handling.
///   - Windows: `BCryptGenRandom` against the default RNG provider.
///   - Anything else: fall back to a CSPRNG seeded from a best-effort
///     entropy source (monotonic clock + ASLR pointer address).
pub fn secureRandomBytes(buf: []u8) void {
    switch (native_os) {
		.linux => {
			var off: usize = 0;
			while (off < buf.len) {
				const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
				const signed: isize = @bitCast(rc);
				if (signed < 0) {
					// EINTR or transient failure: retry.
					continue;
				}
				off += rc;
			}
            return;
		},
		.macos, .ios, .tvos, .watchos, .visionos, .freebsd, .openbsd, .netbsd, .dragonfly => {
			if (@hasDecl(std.c, "arc4random_buf") and @TypeOf(std.c.arc4random_buf) != void) {
				std.c.arc4random_buf(buf.ptr, buf.len);
				return;
			}
		},
		.windows => {
			if (windowsSecureRandomBytes(buf)) return;
		},
		else => {},
    }
	fallbackRandomBytes(buf);
}

fn fallbackRandomBytes(buf: []u8) void {
    // Fallback: seed a CSPRNG from a best-effort entropy source.
    var seed: u64 = timemod.monotonicNanos() ^ @as(u64, @truncate(@intFromPtr(buf.ptr)));
    var prng = std.Random.DefaultCsprng.init(blk: {
        var s: [32]u8 = undefined;
        std.mem.writeInt(u64, s[0..8], seed, .little);
        std.mem.writeInt(u64, s[8..16], seed *% 0x9E3779B97F4A7C15, .little);
        std.mem.writeInt(u64, s[16..24], seed ^ 0xD1B54A32D192ED03, .little);
        std.mem.writeInt(u64, s[24..32], seed +% 0xCA9C9D5B7E1F8A3D, .little);
        break :blk s;
    });
    seed = 0;
    prng.random().bytes(buf);
}

// ---------------------------------------------------------------------------
// Windows: BCryptGenRandom (bcrypt.dll)
// ---------------------------------------------------------------------------

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

extern "bcrypt" fn BCryptGenRandom(
    hAlgorithm: ?*anyopaque,
	pbBuffer: [*]u8,
	cbBuffer: u32,
	dwFlags: u32,
) callconv(.winapi) i32; // NTSTATUS; 0 == STATUS_SUCCESS

fn windowsSecureRandomBytes(buf: []u8) bool {
	if (buf.len == 0) return true;
	var off: usize = 0;
	while (off < buf.len) {
		const chunk_len: u32 = @intCast(@min(buf.len - off, std.math.maxInt(u32)));
		const status = BCryptGenRandom(null, buf.ptr + off, chunk_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (status != 0) return false;
		off += chunk_len;
	}
	return true;
}

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const SECRET_SEED_SIZE: usize = 32;

/// Fixed-size public key (raw ed25519 verifying key bytes).
pub const PublicKey = [PUBLIC_KEY_SIZE]u8;

/// Fixed-size detached signature.
pub const Sig = [SIGNATURE_SIZE]u8;

/// Cryptographic identity: holds the ed25519 key pair and its public bytes.
pub const Crypto = struct {
    key_pair: Ed25519.KeyPair,
    public_key: PublicKey,

    /// Build a Crypto from an existing key pair.
    pub fn init(key_pair: Ed25519.KeyPair) Crypto {
        return .{
            .key_pair = key_pair,
            .public_key = key_pair.public_key.toBytes(),
        };
    }

    /// Generate a fresh random identity.
    pub fn generate() Crypto {
        var seed: [SECRET_SEED_SIZE]u8 = undefined;
        secureRandomBytes(&seed);
        // A random 32-byte seed yields a valid key with overwhelming probability;
        // retry on the astronomically unlikely identity-element error.
        const kp = Ed25519.KeyPair.generateDeterministic(seed) catch blk: {
            secureRandomBytes(&seed);
            break :blk Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
        };
        return init(kp);
    }

    /// Build a Crypto from a 32-byte secret seed (deterministic).
    pub fn fromSeed(seed: [SECRET_SEED_SIZE]u8) !Crypto {
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        return init(kp);
    }

    /// Sign a message with our private key. Returns a detached 64-byte signature.
    pub fn sign(self: *const Crypto, message: []const u8) Sig {
        const signature = self.key_pair.sign(message, null) catch unreachable;
        return signature.toBytes();
    }

    /// Verify a detached signature produced by `key` over `message`.
    pub fn verify(key: *const PublicKey, message: []const u8, sig: *const Sig) bool {
        const pub_key = Ed25519.PublicKey.fromBytes(key.*) catch return false;
        const signature = Ed25519.Signature.fromBytes(sig.*);
        signature.verify(message, pub_key) catch return false;
        return true;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "sign and verify" {
    const crypto = Crypto.generate();
    const message = "hello ironwood";
    const sig = crypto.sign(message);
    try std.testing.expect(Crypto.verify(&crypto.public_key, message, &sig));
}

test "verify wrong message fails" {
    const crypto = Crypto.generate();
    const sig = crypto.sign("correct");
    try std.testing.expect(!Crypto.verify(&crypto.public_key, "wrong", &sig));
}

test "verify wrong key fails" {
    const c1 = Crypto.generate();
    const c2 = Crypto.generate();
    const sig = c1.sign("test");
    try std.testing.expect(!Crypto.verify(&c2.public_key, "test", &sig));
}

test "deterministic from seed" {
    const seed = [_]u8{7} ** 32;
    const a = try Crypto.fromSeed(seed);
    const b = try Crypto.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &a.public_key, &b.public_key);
}
