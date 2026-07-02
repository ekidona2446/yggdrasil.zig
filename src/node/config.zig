//! Yggdrasil node configuration.
//!
//! Supports TOML config files with the same schema as the reference
//! implementation.  Provides defaults, key parsing, and node-info helpers.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const ironwood = @import("ironwood");
const crypto = ironwood.crypto;

/// Per-interface multicast discovery configuration.
pub const MulticastInterfaceConfig = struct {
    filter: []const u8 = "*",
    beacon: bool = true,
    listen: bool = true,
    port: u16 = 0,
    priority: u8 = 0,
    password: []const u8 = &.{},
};

/// Built-in stateful firewall configuration.
pub const FirewallConfig = struct {
    enable: bool = false,
    open_tcp: []const u16 = &.{},
    open_udp: []const u16 = &.{},
    open_all_for: [][]const u8 = &.{},
    allow_icmp_echo: bool = true,
};

/// Yggdrasil node configuration.
pub const Config = struct {
    /// Ed25519 private key as 128-char hex string (64 bytes).
    private_key: []const u8 = &.{},
    /// Peer URIs: ["tcp://host:port", ...].
    peers: []const []const u8 = &.{},
    /// Listen addresses: ["tcp://[::]:0", ...].
    listen: []const []const u8 = &.{},
    /// Admin socket: "tcp://localhost:9001".
    admin_listen: []const u8 = "tcp://localhost:9001",
    /// TUN interface name ("auto" | "none" | custom).
    if_name: []const u8 = "auto",
    /// TUN MTU.
    if_mtu: u64 = 65535,
    /// Custom node info (JSON string or empty).
    node_info: []const u8 = "{}",
    /// Hide build info from peers.
    node_info_privacy: bool = false,
    /// Allowed peer keys (hex strings).
    allowed_public_keys: []const []const u8 = &.{},
    /// Multicast interfaces.
    multicast_interfaces: []const MulticastInterfaceConfig = &.{},
    /// Firewall.
    firewall: FirewallConfig = .{},
    /// Closed-network group password.
    group_password: []const u8 = &.{},
    /// Ironwood config (delegated).
    ironwood: *const IronwoodConfig = &.{},

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Parse the private key from hex, returning a Crypto identity.
    /// Returns null if no key is configured (caller should generate one).
    pub fn signingKey(self: *const Config) !?crypto.Crypto {
        if (self.private_key.len == 0) return null;
        // 64 ed25519 keypair bytes -> 128 hex chars
        if (self.private_key.len != 128) return error.BadKey;

        var kp_bytes: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&kp_bytes, self.private_key);

        const secret_key = try Ed25519.SecretKey.fromBytes(kp_bytes);
        const kp = try Ed25519.KeyPair.fromSecretKey(secret_key);
        return crypto.Crypto.init(kp);
    }

    /// Default listen addresses when none are configured.
    pub fn defaultListen() []const []const u8 {
        return &.{"tcp://[::]:0"};
    }
};

/// Ironwood-level configuration (re-exported from ironwood/config).
pub const IronwoodConfig = ironwood.config.Config;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "default config" {
    const cfg = Config{};
    try testing.expectEqualStrings("tcp://localhost:9001", cfg.admin_listen);
    try testing.expectEqual(@as(u64, 65535), cfg.if_mtu);
    try testing.expect((try cfg.signingKey()) == null);
}

test "signing key parse" {
    const id = crypto.Crypto.generate();
    var hex_buf: [128]u8 = undefined;
    const kp_bytes = id.key_pair.secret_key.toBytes();
    const hex_chars = "0123456789abcdef";
    for (kp_bytes, 0..) |b, i| {
        hex_buf[i * 2] = hex_chars[(b >> 4) & 0xF];
        hex_buf[i * 2 + 1] = hex_chars[b & 0xF];
    }

    var cfg = Config{ .private_key = &hex_buf };
    const parsed = try cfg.signingKey();
    try testing.expect(parsed != null);
    try testing.expectEqualSlices(u8, &id.public_key, &parsed.?.public_key);
}
