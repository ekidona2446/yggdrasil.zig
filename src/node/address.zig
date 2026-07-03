//! Yggdrasil IPv6 addressing from ed25519 public keys.
//!
//! Wire-compatible with the reference implementation.  An ed25519 key is
//! bitwise-inverted, then the leading 1-bits are counted (clamped to 255)
//! and the remaining bits after the first 0-bit are packed into the address.

const std = @import("std");
const testing = std.testing;

/// 16-byte Yggdrasil IPv6 address prefix (0x02).
const ADDRESS_PREFIX: u8 = 0x02;
/// 8-byte Yggdrasil /64 subnet prefix (0x03).
const SUBNET_PREFIX: u8 = 0x03;

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// Yggdrasil IPv6 address (16 bytes).
pub const Address = struct {
    bytes: [16]u8,

    pub fn isValid(self: *const Address) bool {
        return self.bytes[0] == ADDRESS_PREFIX;
    }

    /// Reconstruct a partial ed25519 public key from this address.
    /// Used for DHT/bloom-filter lookups.
    pub fn getKey(self: *const Address) [32]u8 {
        const ones = self.bytes[1];
        var key = [_]u8{0} ** 32;
        const ones_usize: usize = ones;
        var idx: usize = 0;
        while (idx < ones_usize) : (idx += 1) {
            if (idx / 8 >= 32) break;
            key[idx / 8] |= @as(u8, 0x80) >> @intCast(idx % 8);
        }
        const key_offset = ones_usize + 1;
        var idx2: usize = 0;
        while (idx2 < 8 * 14) : (idx2 += 1) {
            const addr_byte = 2 + idx2 / 8;
            if (addr_byte >= 16) break;
            const bit = (self.bytes[addr_byte] >> @intCast(7 - (idx2 % 8))) & 1;
            const kbp = key_offset + idx2;
            if (kbp / 8 >= 32) break;
            key[kbp / 8] |= bit << @intCast(7 - (kbp % 8));
        }
        for (&key) |*b| b.* = ~b.*;
        return key;
    }

    /// Format as IPv6 address string (e.g. "200:abcd::1").
    pub fn format(self: Address, writer: anytype) !void {
        // Manual IPv6 formatting: 8 groups of 2 bytes in hex
        var started: bool = false;
        const delim = ":";
        for (0..8) |i| {
            const hi = self.bytes[i * 2];
            const lo = self.bytes[i * 2 + 1];
            if (started) try writer.writeAll(delim);
            try writer.print("{x:0>2}{x:0>2}", .{ hi, lo });
            started = true;
        }
    }
};

// ---------------------------------------------------------------------------
// Subnet
// ---------------------------------------------------------------------------

/// Yggdrasil /64 subnet (first 8 bytes of address with bit 0 set).
pub const Subnet = struct {
    bytes: [8]u8,

    pub fn isValid(self: *const Subnet) bool {
        return self.bytes[0] == SUBNET_PREFIX;
    }

    /// Format as IPv6 subnet prefix string (e.g. "300:abcd:0:0").
    pub fn format(self: Subnet, writer: anytype) !void {
        var started: bool = false;
        for (0..4) |i| {
            const hi = self.bytes[i * 2];
            const lo = self.bytes[i * 2 + 1];
            if (started) try writer.writeAll(":");
            try writer.print("{x:0>2}{x:0>2}", .{ hi, lo });
            started = true;
        }
    }

    /// Reconstruct a partial ed25519 public key from this subnet.
    pub fn getKey(self: *const Subnet) [32]u8 {
        var addr_bytes: [16]u8 = [_]u8{0} ** 16;
        @memcpy(addr_bytes[0..8], &self.bytes);
        addr_bytes[0] &= ~@as(u8, 0x01); // clear subnet marker bit
        const addr = Address{ .bytes = addr_bytes };
        return addr.getKey();
    }
};

// ---------------------------------------------------------------------------
// Key -> Address / Subnet
// ---------------------------------------------------------------------------

/// Derive a Yggdrasil IPv6 address from an ed25519 public key.
pub fn addrForKey(public_key: *const [32]u8) Address {
    // Bitwise invert
    var buf = public_key.*;
    for (&buf) |*b| b.* = ~b.*;

    // Count leading 1-bits
    var ones: usize = 0;
    var done = false;
    var temp: [14]u8 = [_]u8{0} ** 14;
    var bits: u8 = 0;
    var n_bits: u8 = 0;
    var temp_idx: usize = 0;

    for (0..256) |idx| {
        const bit = (buf[idx / 8] & (@as(u8, 0x80) >> @intCast(idx % 8))) >> @intCast(7 - (idx % 8));
        if (!done and bit != 0) {
            ones += 1;
            continue;
        }
        if (!done and bit == 0) {
            done = true;
            continue;
        }
        bits = (bits << 1) | bit;
        n_bits += 1;
        if (n_bits == 8) {
            if (temp_idx < 14) {
                temp[temp_idx] = bits;
            }
            temp_idx += 1;
            bits = 0;
            n_bits = 0;
        }
    }

    var addr = [_]u8{0} ** 16;
    addr[0] = ADDRESS_PREFIX;
    addr[1] = @min(ones, 255);
    const n = @min(temp_idx, 14);
    for (0..n) |i| {
        addr[2 + i] = temp[i];
    }
    return .{ .bytes = addr };
}

/// Derive a Yggdrasil /64 subnet from an ed25519 public key.
pub fn subnetForKey(public_key: *const [32]u8) Subnet {
    const addr = addrForKey(public_key);
    var subnet: [8]u8 = undefined;
    @memcpy(&subnet, addr.bytes[0..8]);
    subnet[0] |= 0x01;
    return .{ .bytes = subnet };
}

/// Bloom-filter key transform used by the reference implementation:
/// `SubnetForKey(key).GetKey()`. Nodes that share the same /64 subnet (i.e.
/// the same first `ones` leading-1-bits + one 0-bit prefix in the inverted
/// key) collapse to the same bloom-filter entry, so a lookup for *any* key
/// in that subnet reaches a node that owns it. This function signature
/// matches `ironwood.config.BloomTransformFn` and MUST be installed via
/// `ironwood.Config.bloom_transform` for path lookups to work at all --
/// leaving it as the default identity transform means our bloom filters
/// never match lookups originated by real Yggdrasil peers (which always use
/// this transform), so `path_lookup` messages are silently dropped as
/// "no matching multicast target" and no `path_notify` is ever produced.
pub fn bloomKeyTransform(key: [32]u8) [32]u8 {
    const subnet = subnetForKey(&key);
    return subnet.getKey();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "zero key address" {
    const key = [_]u8{0} ** 32;
    const addr = addrForKey(&key);
    try testing.expect(addr.isValid());
    try testing.expectEqual(@as(u8, ADDRESS_PREFIX), addr.bytes[0]);
    // All-zeros inverts to all-ones -> 256 leading ones -> clamped to 255
    try testing.expectEqual(@as(u8, 255), addr.bytes[1]);
}

test "all ones key address" {
    const key = [_]u8{0xFF} ** 32;
    const addr = addrForKey(&key);
    try testing.expect(addr.isValid());
    try testing.expectEqual(@as(u8, 0), addr.bytes[1]);
}

test "known ones count" {
    var key = [_]u8{0} ** 32;
    key[1] = 0x01; // first 15 bits are 0, bit 16 is 1 -> inverted: 15 leading ones
    const addr = addrForKey(&key);
    try testing.expectEqual(@as(u8, 15), addr.bytes[1]);
}

test "subnet key" {
    const key = [_]u8{0} ** 32;
    const subnet = subnetForKey(&key);
    try testing.expect(subnet.isValid());
    try testing.expectEqual(@as(u8, 1), subnet.bytes[0] & 0x01);
}

test "roundtrip addr -> getKey -> addr" {
    for (0..20) |seed| {
        var key = [_]u8{0} ** 32;
        key[0] = @truncate(seed);
        key[31] = @truncate(seed *% 7);
        const addr = addrForKey(&key);
        const recovered = addr.getKey();
        const addr2 = addrForKey(&recovered);
        try testing.expectEqualSlices(u8, &addr.bytes, &addr2.bytes);
    }
}

test "bloom transform equivalence" {
    for (0..50) |seed| {
        var key = [_]u8{0} ** 32;
        key[0] = @truncate(seed);
        key[15] = @truncate(seed *% 3);
        key[31] = @truncate(seed *% 7);

        const addr = addrForKey(&key);
        const partial = addr.getKey();

        const bloom_full = subnetForKey(&key).getKey();
        const bloom_partial = subnetForKey(&partial).getKey();

        try testing.expectEqualSlices(u8, &bloom_full, &bloom_partial);
    }
}
