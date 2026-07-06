//! Configuration for an ironwood PacketConn.
//!
//! Durations are expressed in nanoseconds (Zig has no Duration type;
//! `std.time.ns_per_s` etc. are used for readability).

const std = @import("std");
const ns_per_s = std.time.ns_per_s;
const cryptomod = @import("crypto.zig");
const PublicKey = cryptomod.PublicKey;

/// Callback applied to keys before bloom-filter insertion.
pub const BloomTransformFn = *const fn (PublicKey) PublicKey;
/// Callback invoked when a new path is discovered.
pub const PathNotifyFn = *const fn (PublicKey) void;

pub const Config = struct {
    /// How often to refresh our own tree announcement. Default: 4 minutes.
    router_refresh_ns: u64 = 4 * 60 * ns_per_s,
    /// Timeout before expiring a peer's tree info. Default: 5 minutes.
    router_timeout_ns: u64 = 5 * 60 * ns_per_s,
    /// Delay before sending a keepalive to an idle peer. Default: 1 second.
    peer_keepalive_delay_ns: u64 = 1 * ns_per_s,
    /// Timeout before considering a peer dead. Default: 5 seconds.
    peer_timeout_ns: u64 = 5 * ns_per_s,
    /// Maximum size of a single peer message. Default: 1 MiB.
    peer_max_message_size: u64 = 1024 * 1024,
    /// Optional transform applied to keys before bloom-filter insertion.
    bloom_transform: ?BloomTransformFn = null,
    /// Callback invoked when a new path is discovered.
    path_notify: ?PathNotifyFn = null,
    /// Timeout before expiring a cached path. Default: 1 minute.
    path_timeout_ns: u64 = 60 * ns_per_s,
    /// Minimum interval between path lookups to the same destination. Default: 1 second.
    path_throttle_ns: u64 = 1 * ns_per_s,
    /// Optional closed-network group password. null/empty = open network.
    group_password: ?[]const u8 = null,

    pub fn default() Config {
        return .{};
    }
};

test "config defaults match reference" {
    const c = Config.default();
    try std.testing.expectEqual(@as(u64, 4 * 60 * ns_per_s), c.router_refresh_ns);
    try std.testing.expectEqual(@as(u64, 5 * 60 * ns_per_s), c.router_timeout_ns);
    try std.testing.expectEqual(@as(u64, 1024 * 1024), c.peer_max_message_size);
    try std.testing.expect(c.group_password == null);
}
