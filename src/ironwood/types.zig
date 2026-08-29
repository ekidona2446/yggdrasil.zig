//! Core public types for ironwood.

const std = @import("std");
const crypto = @import("crypto.zig");

/// Ed25519 public key used as a network address.
pub const Addr = struct {
    bytes: [32]u8,

    pub fn network(_: *const Addr) []const u8 {
        return "ed25519";
    }

    pub fn fromBytes(bytes: [32]u8) Addr {
        return .{ .bytes = bytes };
    }

    pub fn fromPublicKey(pk: crypto.PublicKey) Addr {
        return .{ .bytes = pk };
    }

    pub fn eql(self: *const Addr, other: *const Addr) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Total ordering.
    pub fn order(self: *const Addr, other: *const Addr) std.math.Order {
        return std.mem.order(u8, &self.bytes, &other.bytes);
    }

    /// Lowercase hex formatting.
    pub fn format(self: Addr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
    }
};

/// Errors returned by ironwood operations.
pub const Error = error{
    Encode,
    Decode,
    Closed,
    Timeout,
    BadMessage,
    EmptyMessage,
    OversizedMessage,
    UnrecognizedMessage,
    PeerNotFound,
    BadAddress,
    BadKey,
    Io,
    OutOfMemory,
};

test "addr hex display" {
    var bytes: [32]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @intCast(i);
    const addr = Addr.fromBytes(bytes);
    var buf: [64]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f}", .{addr});
    try std.testing.expect(std.mem.startsWith(u8, s, "000102030405"));
    try std.testing.expectEqual(@as(usize, 64), s.len);
}

test "addr ordering and equality" {
    const a = Addr.fromBytes([_]u8{0} ** 32);
    var bb = [_]u8{0} ** 32;
    bb[31] = 1;
    const b = Addr.fromBytes(bb);
    try std.testing.expect(a.order(&b) == .lt);
    try std.testing.expect(a.eql(&a));
    try std.testing.expect(!a.eql(&b));
}
