//! LAN multicast peer discovery.
//!
//! Sends and receives BLAKE2b-authenticated advertisements on
//! ff02::114:9001 to discover Yggdrasil peers on the local network.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const PublicKey = ironwood.PublicKey;
const Metadata = node.version.Metadata;

pub const MULTICAST_GROUP: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x14 };
pub const MULTICAST_PORT: u16 = 9001;
pub const BEACON_MAX_INTERVAL_NS: u64 = 15 * std.time.ns_per_s;
const RECV_BUF_SIZE: usize = 2048;

/// A received advertisement.
pub const Advertisement = struct {
    major_version: u16,
    minor_version: u16,
    public_key: PublicKey,
    port: u16,
    hash: []u8, // caller-owned

    pub fn encode(self: *const Advertisement, gpa: std.mem.Allocator) ![]u8 {
        const total = 40 + self.hash.len;
        const buf = try gpa.alloc(u8, total);
        std.mem.writeInt(u16, buf[0..2], self.major_version, .big);
        std.mem.writeInt(u16, buf[2..4], self.minor_version, .big);
        @memcpy(buf[4..36], &self.public_key);
        std.mem.writeInt(u16, buf[36..38], self.port, .big);
        std.mem.writeInt(u16, buf[38..40], @intCast(self.hash.len), .big);
        if (self.hash.len > 0)
            @memcpy(buf[40..], self.hash);
        return buf;
    }

    pub fn decode(data: []const u8, gpa: std.mem.Allocator) !Advertisement {
        if (data.len < 40) return error.Decode;
        const hash_len: usize = std.mem.readInt(u16, data[38..40], .big);
        if (data.len < 40 + hash_len) return error.Decode;
        const hash = try gpa.dupe(u8, data[40 .. 40 + hash_len]);
        return .{
            .major_version = std.mem.readInt(u16, data[0..2], .big),
            .minor_version = std.mem.readInt(u16, data[2..4], .big),
            .public_key = data[4..36].*,
            .port = std.mem.readInt(u16, data[36..38], .big),
            .hash = hash,
        };
    }
};

/// Compute BLAKE2b-512 auth hash.
pub fn computeAuthHash(public_key: *const PublicKey, password: []const u8, gpa: std.mem.Allocator) ![]u8 {
    const out = try gpa.alloc(u8, 64);
    if (password.len == 0) {
        std.crypto.hash.blake2.Blake2b512.hash(public_key, out[0..64], .{});
    } else {
        std.crypto.hash.blake2.Blake2b512.hash(public_key, out[0..64], .{ .key = password });
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "advertisement encode decode" {
    const gpa = testing.allocator;
    const key = [_]u8{0x42} ** 32;
    const hash = try computeAuthHash(&key, "", gpa);
    defer gpa.free(hash);

    const ad = Advertisement{
        .major_version = 0,
        .minor_version = 5,
        .public_key = key,
        .port = 9001,
        .hash = hash,
    };

    const encoded = try ad.encode(gpa);
    defer gpa.free(encoded);
    try testing.expectEqual(@as(usize, 40 + 64), encoded.len);

    const decoded = try Advertisement.decode(encoded, gpa);
    defer gpa.free(decoded.hash);
    try testing.expectEqualSlices(u8, &key, &decoded.public_key);
    try testing.expectEqual(@as(u16, 9001), decoded.port);
}
