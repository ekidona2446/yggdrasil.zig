//! Version handshake metadata exchanged between peers.
//!
//! Wire format: "meta" (4 bytes) + length (u16 BE) + TLV fields + ed25519 signature (64).
//! Signature is over BLAKE2b-512(public_key, key=password).
//! Wire-compatible with the reference implementation.

const std = @import("std");
const ironwood = @import("ironwood");
const crypto = ironwood.crypto;
const PublicKey = crypto.PublicKey;
const Sig = crypto.Sig;

pub const PROTOCOL_VERSION_MAJOR: u16 = 0;
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

const PREAMBLE: [4]u8 = .{ 'm', 'e', 't', 'a' };
const SIGNATURE_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

pub const Metadata = struct {
    major_ver: u16 = PROTOCOL_VERSION_MAJOR,
    minor_ver: u16 = PROTOCOL_VERSION_MINOR,
    public_key: PublicKey = [_]u8{0} ** 32,
    priority: u8 = 0,

    pub fn init(public_key: PublicKey, priority: u8) Metadata {
        return .{
            .major_ver = PROTOCOL_VERSION_MAJOR,
            .minor_ver = PROTOCOL_VERSION_MINOR,
            .public_key = public_key,
            .priority = priority,
        };
    }

    /// Compatible if same major and remote minor >= our minor.
    pub fn check(self: *const Metadata) bool {
        return self.major_ver == PROTOCOL_VERSION_MAJOR and
            self.minor_ver >= PROTOCOL_VERSION_MINOR and
            self.public_key.len == 32;
    }

    pub fn isExactMatch(self: *const Metadata) bool {
        return self.major_ver == PROTOCOL_VERSION_MAJOR and
            self.minor_ver == PROTOCOL_VERSION_MINOR;
    }

    /// Encode to wire format, signed with the given key pair.
    /// Caller owns the returned buffer.
    pub fn encode(self: *const Metadata, kp: *const crypto.Crypto, password: []const u8, gpa: std.mem.Allocator) ![]u8 {
        var bs = try std.ArrayListUnmanaged(u8).initCapacity(gpa, 128);
        errdefer bs.deinit(gpa);

        try bs.appendSlice(gpa, &PREAMBLE);
        try bs.appendNTimes(gpa, 0, 2); // length placeholder

        // Major version: type(2) + len(2) + value(2)
        try writeU16BE(&bs, gpa, META_VERSION_MAJOR);
        try writeU16BE(&bs, gpa, 2);
        try writeU16BE(&bs, gpa, self.major_ver);

        // Minor version
        try writeU16BE(&bs, gpa, META_VERSION_MINOR);
        try writeU16BE(&bs, gpa, 2);
        try writeU16BE(&bs, gpa, self.minor_ver);

        // Public key
        try writeU16BE(&bs, gpa, META_PUBLIC_KEY);
        try writeU16BE(&bs, gpa, 32);
        try bs.appendSlice(gpa, &self.public_key);

        // Priority
        try writeU16BE(&bs, gpa, META_PRIORITY);
        try writeU16BE(&bs, gpa, 1);
        try bs.append(gpa, self.priority);

        // BLAKE2b-512 of public key (keyed with password if non-empty)
        const hash = try blake2bHash(&self.public_key, password, gpa);
        defer gpa.free(hash);
        const sig = kp.sign(hash);
        try bs.appendSlice(gpa, &sig);

        // Fill in length (excludes 6-byte header) — big-endian
        const length: u16 = @intCast(bs.items.len - 6);
        std.mem.writeInt(u16, bs.items[4..6][0..2], length, .big);

        return bs.toOwnedSlice(gpa);
    }

    /// Decode metadata from a byte slice. Verifies the signature.
    pub fn decode(data: []const u8, password: []const u8, gpa: std.mem.Allocator) !Metadata {
        if (data.len < 6) return error.InvalidPreamble;
        if (!std.mem.eql(u8, data[0..4], &PREAMBLE)) return error.InvalidPreamble;

        const length = std.mem.readInt(u16, data[4..6], .big);
        if (length < SIGNATURE_SIZE) return error.TooShort;
        const total = @as(usize, 6) + @as(usize, length);
        if (data.len < total) return error.TooShort;

        const body = data[6..total];
        const sig_bytes = body[body.len - SIGNATURE_SIZE ..];
        const fields = body[0 .. body.len - SIGNATURE_SIZE];

        var meta = Metadata{};
        var pos: usize = 0;
        while (pos + 4 <= fields.len) {
            const field_id = std.mem.readInt(u16, fields[pos..][0..2], .big);
            const field_len = std.mem.readInt(u16, fields[pos + 2 ..][0..2], .big);
            pos += 4;
            if (pos + field_len > fields.len) return error.InvalidLength;
            const field = fields[pos .. pos + field_len];
            switch (field_id) {
                META_VERSION_MAJOR => {
                    if (field_len != 2) return error.InvalidLength;
                    meta.major_ver = std.mem.readInt(u16, field[0..2], .big);
                },
                META_VERSION_MINOR => {
                    if (field_len != 2) return error.InvalidLength;
                    meta.minor_ver = std.mem.readInt(u16, field[0..2], .big);
                },
                META_PUBLIC_KEY => {
                    if (field_len != 32) return error.InvalidLength;
                    @memcpy(&meta.public_key, field[0..32]);
                },
                META_PRIORITY => {
                    if (field_len != 1) return error.InvalidLength;
                    meta.priority = field[0];
                },
                else => {}, // skip unknown
            }
            pos += field_len;
        }
        if (pos != fields.len) return error.InvalidLength;

        // Verify signature
        const hash = try blake2bHash(&meta.public_key, password, gpa);
        defer gpa.free(hash);
        var sig: Sig = undefined;
        @memcpy(&sig, sig_bytes[0..64]);
        if (!crypto.Crypto.verify(&meta.public_key, hash, &sig)) return error.BadSignature;

        return meta;
    }
};

// ---------------------------------------------------------------------------
// BLAKE2b-512 (keyed or unkeyed)
// ---------------------------------------------------------------------------

fn blake2bHash(data: []const u8, password: []const u8, gpa: std.mem.Allocator) ![]u8 {
    const out = try gpa.alloc(u8, 64);
    errdefer gpa.free(out);
    if (password.len == 0) {
        std.crypto.hash.blake2.Blake2b512.hash(data, out[0..64], .{});
    } else {
        std.crypto.hash.blake2.Blake2b512.hash(data, out[0..64], .{ .key = password });
    }
    return out;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn writeU16BE(bs: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try bs.appendSlice(gpa, &buf);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encode decode no password" {
    const gpa = testing.allocator;
    const id = crypto.Crypto.generate();
    const meta = Metadata.init(id.public_key, 0);

    const encoded = try meta.encode(&id, &.{}, gpa);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &PREAMBLE, encoded[0..4]);

    const decoded = try Metadata.decode(encoded, &.{}, gpa);
    try testing.expectEqual(PROTOCOL_VERSION_MAJOR, decoded.major_ver);
    try testing.expectEqual(PROTOCOL_VERSION_MINOR, decoded.minor_ver);
    try testing.expectEqualSlices(u8, &id.public_key, &decoded.public_key);
    try testing.expectEqual(@as(u8, 0), decoded.priority);
    try testing.expect(decoded.check());
}

test "encode decode with password" {
    const gpa = testing.allocator;
    const id = crypto.Crypto.generate();
    const meta = Metadata.init(id.public_key, 5);
    const pw = "test-password";

    const encoded = try meta.encode(&id, pw, gpa);
    defer gpa.free(encoded);
    const decoded = try Metadata.decode(encoded, pw, gpa);
    try testing.expectEqual(@as(u8, 5), decoded.priority);
    try testing.expectEqualSlices(u8, &id.public_key, &decoded.public_key);
}

test "wrong password fails" {
    const gpa = testing.allocator;
    const id = crypto.Crypto.generate();
    const meta = Metadata.init(id.public_key, 0);

    const encoded = try meta.encode(&id, "correct", gpa);
    defer gpa.free(encoded);
    try testing.expectError(error.BadSignature, Metadata.decode(encoded, "wrong", gpa));
}

test "check valid and invalid" {
    var meta = Metadata.init([_]u8{1} ** 32, 0);
    try testing.expect(meta.check());

    meta.major_ver = 1;
    try testing.expect(!meta.check());
}
