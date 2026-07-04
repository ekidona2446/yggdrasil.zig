//! Yggdrasil node configuration.
//!
//! Supports a TOML configuration file with the same schema as the
//! reference (Rust) implementation's `config_template.toml`. Since none of
//! the available third-party Zig TOML libraries (`tomlz` forks) build
//! under Zig 0.16 -- they rely on pre-0.15 `std.Build` APIs
//! (`.root_source_file` directly on `addExecutable`) and/or removed
//! language features (`pub usingnamespace`) -- this module implements a
//! small hand-rolled reader/writer covering exactly the subset of TOML our
//! own `--genconf` output uses: string/bool/integer scalars, string and
//! integer arrays, `[section]` tables, and `[[array_of_tables]]` entries.
//! It is *not* a general-purpose TOML parser (no dotted keys, inline
//! tables, multi-line strings, etc.), but it round-trips our own generated
//! config files losslessly, which is what actually matters in practice.

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

    /// Set when this Config was produced by `parseToml`/`generateDefault`
    /// and owns all of its string/slice memory; `deinit` is then
    /// meaningful. Configs built as Zig struct literals (e.g. in tests, or
    /// from CLI-only flags) should leave this `false` and skip `deinit`.
    owns_memory: bool = false,

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

    /// Build a fresh default configuration with a newly generated Ed25519
    /// identity, suitable for `--genconf`. All memory is owned by `gpa`.
    pub fn generateDefault(gpa: std.mem.Allocator) !Config {
        const id = crypto.Crypto.generate();
        var hex_buf = try gpa.alloc(u8, 128);
        const hex_chars = "0123456789abcdef";
        const kp_bytes = id.key_pair.secret_key.toBytes();
        for (kp_bytes, 0..) |b, i| {
            hex_buf[i * 2] = hex_chars[(b >> 4) & 0xF];
            hex_buf[i * 2 + 1] = hex_chars[b & 0xF];
        }

        const listen = try gpa.alloc([]const u8, 1);
        listen[0] = try gpa.dupe(u8, "tcp://0.0.0.0:0");

        const mc = try gpa.alloc(MulticastInterfaceConfig, 1);
        mc[0] = .{ .filter = try gpa.dupe(u8, "*") };

        return .{
            .private_key = hex_buf,
            .peers = &.{},
            .listen = listen,
            .admin_listen = try gpa.dupe(u8, "tcp://localhost:9001"),
            .if_name = try gpa.dupe(u8, "auto"),
            .if_mtu = 65535,
            .node_info = try gpa.dupe(u8, "{}"),
            .allowed_public_keys = &.{},
            .multicast_interfaces = mc,
            .firewall = .{
                .open_tcp = try gpa.dupe(u16, &.{ 22, 80, 443 }),
                .open_udp = try gpa.dupe(u16, &.{53}),
            },
            .owns_memory = true,
        };
    }

    pub fn deinit(self: *Config, gpa: std.mem.Allocator) void {
        if (!self.owns_memory) return;
        gpa.free(self.private_key);
        for (self.peers) |p| gpa.free(p);
        gpa.free(self.peers);
        for (self.listen) |l| gpa.free(l);
        gpa.free(self.listen);
        gpa.free(self.admin_listen);
        gpa.free(self.if_name);
        gpa.free(self.node_info);
        for (self.allowed_public_keys) |k| gpa.free(k);
        gpa.free(self.allowed_public_keys);
        for (self.multicast_interfaces) |m| {
            gpa.free(m.filter);
            gpa.free(m.password);
        }
        gpa.free(self.multicast_interfaces);
        gpa.free(self.firewall.open_tcp);
        gpa.free(self.firewall.open_udp);
        for (self.firewall.open_all_for) |s| gpa.free(s);
        gpa.free(self.firewall.open_all_for);
        gpa.free(self.group_password);
    }

    /// Serialize to our TOML subset (matches the reference config's shape
    /// closely enough to be a drop-in replacement, minus the descriptive
    /// comment blocks).
    pub fn writeToml(self: *const Config, writer: *std.Io.Writer) !void {
        try writer.print("private_key = \"{s}\"\n\n", .{self.private_key});

        try writeStringArray(writer, "peers", self.peers);
        try writer.writeAll("\n");
        try writeStringArray(writer, "listen", self.listen);
        try writer.writeAll("\n");

        try writer.print("admin_listen = \"{s}\"\n\n", .{self.admin_listen});
        try writer.print("if_name = \"{s}\"\n", .{self.if_name});
        try writer.print("if_mtu = {d}\n\n", .{self.if_mtu});

        try writer.print("node_info_privacy = {}\n\n", .{self.node_info_privacy});

        try writeStringArray(writer, "allowed_public_keys", self.allowed_public_keys);
        try writer.writeAll("\n");

        if (self.group_password.len > 0) {
            try writer.print("group_password = \"{s}\"\n\n", .{self.group_password});
        }

        try writer.writeAll("[node_info]\n\n");

        for (self.multicast_interfaces) |m| {
            try writer.writeAll("[[multicast_interfaces]]\n");
            try writer.print("filter = \"{s}\"\n", .{m.filter});
            try writer.print("beacon = {}\n", .{m.beacon});
            try writer.print("listen = {}\n", .{m.listen});
            try writer.print("port = {d}\n", .{m.port});
            try writer.print("priority = {d}\n", .{m.priority});
            try writer.print("password = \"{s}\"\n\n", .{m.password});
        }

        try writer.writeAll("[firewall]\n");
        try writer.print("enable = {}\n", .{self.firewall.enable});
        try writeIntArray(writer, "open_tcp", self.firewall.open_tcp);
        try writeIntArray(writer, "open_udp", self.firewall.open_udp);
        try writeStringArray(writer, "open_all_for", self.firewall.open_all_for);
        try writer.print("allow_icmp_echo = {}\n", .{self.firewall.allow_icmp_echo});
    }

    fn writeStringArray(writer: *std.Io.Writer, name: []const u8, items: []const []const u8) !void {
        if (items.len == 0) {
            try writer.print("{s} = []\n", .{name});
            return;
        }
        try writer.print("{s} = [", .{name});
        for (items, 0..) |it, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("\"{s}\"", .{it});
        }
        try writer.writeAll("]\n");
    }

    fn writeIntArray(writer: *std.Io.Writer, name: []const u8, items: []const u16) !void {
        try writer.print("{s} = [", .{name});
        for (items, 0..) |it, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.print("{d}", .{it});
        }
        try writer.writeAll("]\n");
    }

    /// Parse a Config from our TOML subset. All returned string/slice
    /// memory is owned by `gpa`; call `deinit` when done.
    pub fn parseToml(gpa: std.mem.Allocator, text: []const u8) !Config {
        // NOTE: Config's struct defaults for admin_listen/if_name/node_info
        // are non-empty string *literals* (not heap allocations), used so
        // that plain Zig-literal Configs (tests, CLI-only construction)
        // "just work" without a dupe. Since this function unconditionally
        // frees every field it touches via `deinit`, we must not let those
        // literal defaults leak through un-duped -- so we start from
        // explicit empty slices here and dupe the real defaults back in
        // afterwards if the file didn't set them.
        var cfg = Config{ .owns_memory = true, .admin_listen = &.{}, .if_name = &.{}, .node_info = &.{} };
        // Track growable lists we build up during parsing, converted to
        // owned slices at the end.
        var peers = std.ArrayListUnmanaged([]const u8).empty;
        defer peers.deinit(gpa);
        var listen = std.ArrayListUnmanaged([]const u8).empty;
        defer listen.deinit(gpa);
        var allowed_keys = std.ArrayListUnmanaged([]const u8).empty;
        defer allowed_keys.deinit(gpa);
        var mc_list = std.ArrayListUnmanaged(MulticastInterfaceConfig).empty;
        defer mc_list.deinit(gpa);
        var open_tcp = std.ArrayListUnmanaged(u16).empty;
        defer open_tcp.deinit(gpa);
        var open_udp = std.ArrayListUnmanaged(u16).empty;
        defer open_udp.deinit(gpa);
        var open_all_for = std.ArrayListUnmanaged([]const u8).empty;
        defer open_all_for.deinit(gpa);

        var section: Section = .root;
        var cur_mc: MulticastInterfaceConfig = .{};
        var have_cur_mc = false;

        var lines = std.mem.splitScalar(u8, text, '\n');
        var pending_key: ?[]const u8 = null;
        var pending_array_items = std.ArrayListUnmanaged(u8).empty;
        defer pending_array_items.deinit(gpa);
        var in_multiline_array = false;

        while (lines.next()) |raw_line| {
            var line = stripComment(raw_line);
            line = std.mem.trim(u8, line, " \t\r");

            if (in_multiline_array) {
                try pending_array_items.appendSlice(gpa, line);
                try pending_array_items.append(gpa, ' ');
                if (std.mem.indexOfScalar(u8, line, ']') != null) {
                    in_multiline_array = false;
                    try applyArrayValue(gpa, pending_key.?, pending_array_items.items, section, &cfg, &peers, &listen, &allowed_keys, &open_tcp, &open_udp, &open_all_for, &cur_mc);
                    pending_array_items.clearRetainingCapacity();
                    pending_key = null;
                }
                continue;
            }

            if (line.len == 0) continue;

            if (line.len >= 2 and std.mem.startsWith(u8, line, "[[") and std.mem.endsWith(u8, line, "]]")) {
                if (have_cur_mc) try mc_list.append(gpa, try cloneMulticast(gpa, cur_mc));
                const name = std.mem.trim(u8, line[2 .. line.len - 2], " \t");
                if (std.mem.eql(u8, name, "multicast_interfaces")) {
                    section = .multicast_interfaces;
                    cur_mc = .{};
                    have_cur_mc = true;
                } else {
                    section = .unknown;
                }
                continue;
            }
            if (line.len >= 1 and line[0] == '[' and line[line.len - 1] == ']') {
                if (have_cur_mc) {
                    try mc_list.append(gpa, try cloneMulticast(gpa, cur_mc));
                    have_cur_mc = false;
                }
                const name = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
                if (std.mem.eql(u8, name, "firewall")) {
                    section = .firewall;
                } else if (std.mem.eql(u8, name, "node_info")) {
                    section = .node_info;
                } else {
                    section = .unknown;
                }
                continue;
            }

            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = std.mem.trim(u8, line[0..eq], " \t");
            var value = std.mem.trim(u8, line[eq + 1 ..], " \t");

            if (value.len > 0 and value[0] == '[' and std.mem.indexOfScalar(u8, value, ']') == null) {
                // Multi-line array: buffer until we see the closing ']'.
                in_multiline_array = true;
                pending_key = key;
                pending_array_items.clearRetainingCapacity();
                try pending_array_items.appendSlice(gpa, value);
                try pending_array_items.append(gpa, ' ');
                continue;
            }

            if (value.len > 0 and value[0] == '[') {
                try applyArrayValue(gpa, key, value, section, &cfg, &peers, &listen, &allowed_keys, &open_tcp, &open_udp, &open_all_for, &cur_mc);
                continue;
            }

            // Scalar value.
            value = unquote(value);
            try applyScalarValue(gpa, key, value, section, &cfg, &cur_mc);
        }
        if (have_cur_mc) try mc_list.append(gpa, try cloneMulticast(gpa, cur_mc));

        cfg.peers = try peers.toOwnedSlice(gpa);
        cfg.listen = try listen.toOwnedSlice(gpa);
        cfg.allowed_public_keys = try allowed_keys.toOwnedSlice(gpa);
        cfg.multicast_interfaces = try mc_list.toOwnedSlice(gpa);
        cfg.firewall.open_tcp = try open_tcp.toOwnedSlice(gpa);
        cfg.firewall.open_udp = try open_udp.toOwnedSlice(gpa);
        cfg.firewall.open_all_for = try open_all_for.toOwnedSlice(gpa);
        if (cfg.admin_listen.len == 0) cfg.admin_listen = try gpa.dupe(u8, "tcp://localhost:9001");
        if (cfg.if_name.len == 0) cfg.if_name = try gpa.dupe(u8, "auto");
        if (cfg.node_info.len == 0) cfg.node_info = try gpa.dupe(u8, "{}");
        if (cfg.if_mtu == 0) cfg.if_mtu = 65535;
        return cfg;
    }

    const Section = enum { root, firewall, node_info, multicast_interfaces, unknown };

    fn cloneMulticast(gpa: std.mem.Allocator, m: MulticastInterfaceConfig) !MulticastInterfaceConfig {
        return .{
            .filter = try gpa.dupe(u8, if (m.filter.len > 0) m.filter else "*"),
            .beacon = m.beacon,
            .listen = m.listen,
            .port = m.port,
            .priority = m.priority,
            .password = try gpa.dupe(u8, m.password),
        };
    }

    fn stripComment(line: []const u8) []const u8 {
        var in_quotes = false;
        for (line, 0..) |c, i| {
            if (c == '"') in_quotes = !in_quotes;
            if (c == '#' and !in_quotes) return line[0..i];
        }
        return line;
    }

    fn unquote(v: []const u8) []const u8 {
        if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') return v[1 .. v.len - 1];
        return v;
    }

    fn applyScalarValue(
        gpa: std.mem.Allocator,
        key: []const u8,
        value: []const u8,
        section: Section,
        cfg: *Config,
        cur_mc: *MulticastInterfaceConfig,
    ) !void {
        switch (section) {
            .root => {
                if (std.mem.eql(u8, key, "private_key")) {
                    cfg.private_key = try gpa.dupe(u8, value);
                } else if (std.mem.eql(u8, key, "admin_listen")) {
                    cfg.admin_listen = try gpa.dupe(u8, value);
                } else if (std.mem.eql(u8, key, "if_name")) {
                    cfg.if_name = try gpa.dupe(u8, value);
                } else if (std.mem.eql(u8, key, "if_mtu")) {
                    cfg.if_mtu = std.fmt.parseInt(u64, value, 10) catch cfg.if_mtu;
                } else if (std.mem.eql(u8, key, "node_info_privacy")) {
                    cfg.node_info_privacy = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "group_password")) {
                    cfg.group_password = try gpa.dupe(u8, value);
                }
            },
            .firewall => {
                if (std.mem.eql(u8, key, "enable")) {
                    cfg.firewall.enable = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "allow_icmp_echo")) {
                    cfg.firewall.allow_icmp_echo = std.mem.eql(u8, value, "true");
                }
            },
            .multicast_interfaces => {
                // NOTE: stores raw slices into the (caller-owned, longer-
                // lived-than-this-function) `text` buffer, not heap dupes --
                // `cloneMulticast` (called once per `[[multicast_interfaces]]`
                // entry, on seeing the next section or EOF) performs the
                // single owned-copy dupe. Duping here too would leak: the
                // un-cloned `cur_mc` itself is discarded once its clone is
                // appended to `mc_list`.
                if (std.mem.eql(u8, key, "filter")) {
                    cur_mc.filter = value;
                } else if (std.mem.eql(u8, key, "beacon")) {
                    cur_mc.beacon = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "listen")) {
                    cur_mc.listen = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "port")) {
                    cur_mc.port = std.fmt.parseInt(u16, value, 10) catch 0;
                } else if (std.mem.eql(u8, key, "priority")) {
                    cur_mc.priority = std.fmt.parseInt(u8, value, 10) catch 0;
                } else if (std.mem.eql(u8, key, "password")) {
                    cur_mc.password = value;
                }
            },
            .node_info, .unknown => {},
        }
    }

    fn applyArrayValue(
        gpa: std.mem.Allocator,
        key: []const u8,
        raw_value: []const u8,
        section: Section,
        cfg: *Config,
        peers: *std.ArrayListUnmanaged([]const u8),
        listen: *std.ArrayListUnmanaged([]const u8),
        allowed_keys: *std.ArrayListUnmanaged([]const u8),
        open_tcp: *std.ArrayListUnmanaged(u16),
        open_udp: *std.ArrayListUnmanaged(u16),
        open_all_for: *std.ArrayListUnmanaged([]const u8),
        cur_mc: *MulticastInterfaceConfig,
    ) !void {
        _ = cur_mc;
        const inner_start = std.mem.indexOfScalar(u8, raw_value, '[') orelse return;
        const inner_end = std.mem.lastIndexOfScalar(u8, raw_value, ']') orelse return;
        if (inner_end <= inner_start) return;
        const inner = raw_value[inner_start + 1 .. inner_end];

        if (section == .root and std.mem.eql(u8, key, "peers")) {
            try appendStringItems(gpa, inner, peers);
        } else if (section == .root and std.mem.eql(u8, key, "listen")) {
            try appendStringItems(gpa, inner, listen);
        } else if (section == .root and std.mem.eql(u8, key, "allowed_public_keys")) {
            try appendStringItems(gpa, inner, allowed_keys);
        } else if (section == .firewall and std.mem.eql(u8, key, "open_tcp")) {
            try appendIntItems(gpa, inner, open_tcp);
        } else if (section == .firewall and std.mem.eql(u8, key, "open_udp")) {
            try appendIntItems(gpa, inner, open_udp);
        } else if (section == .firewall and std.mem.eql(u8, key, "open_all_for")) {
            try appendStringItems(gpa, inner, open_all_for);
        } else {
            _ = cfg;
        }
    }

    fn appendStringItems(gpa: std.mem.Allocator, inner: []const u8, out: *std.ArrayListUnmanaged([]const u8)) !void {
        var it = std.mem.splitScalar(u8, inner, ',');
        while (it.next()) |raw_item| {
            const trimmed = std.mem.trim(u8, raw_item, " \t\r\n");
            if (trimmed.len == 0) continue;
            const val = unquote(trimmed);
            if (val.len == 0) continue;
            try out.append(gpa, try gpa.dupe(u8, val));
        }
    }

    fn appendIntItems(gpa: std.mem.Allocator, inner: []const u8, out: *std.ArrayListUnmanaged(u16)) !void {
        var it = std.mem.splitScalar(u8, inner, ',');
        while (it.next()) |raw_item| {
            const trimmed = std.mem.trim(u8, raw_item, " \t\r\n");
            if (trimmed.len == 0) continue;
            const n = std.fmt.parseInt(u16, trimmed, 10) catch continue;
            try out.append(gpa, n);
        }
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

test "generateDefault produces a usable config" {
    var cfg = try Config.generateDefault(testing.allocator);
    defer cfg.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 128), cfg.private_key.len);
    try testing.expect((try cfg.signingKey()) != null);
    try testing.expectEqualStrings("auto", cfg.if_name);
    try testing.expectEqual(@as(usize, 1), cfg.listen.len);
    try testing.expectEqual(@as(usize, 1), cfg.multicast_interfaces.len);
    try testing.expectEqual(@as(usize, 3), cfg.firewall.open_tcp.len);
}

test "writeToml + parseToml round-trip" {
    var original = try Config.generateDefault(testing.allocator);
    defer original.deinit(testing.allocator);

    var owned_peers = try testing.allocator.alloc([]const u8, 2);
    owned_peers[0] = try testing.allocator.dupe(u8, "tcp://example.com:1234");
    owned_peers[1] = try testing.allocator.dupe(u8, "tls://peer.example:443?key=abcd");
    testing.allocator.free(original.peers);
    original.peers = owned_peers;
    original.firewall.enable = true;

    var w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer w.deinit();
    try original.writeToml(&w.writer);

    var parsed = try Config.parseToml(testing.allocator, w.written());
    defer parsed.deinit(testing.allocator);

    try testing.expectEqualStrings(original.private_key, parsed.private_key);
    try testing.expectEqual(@as(usize, 2), parsed.peers.len);
    try testing.expectEqualStrings("tcp://example.com:1234", parsed.peers[0]);
    try testing.expectEqualStrings("tls://peer.example:443?key=abcd", parsed.peers[1]);
    try testing.expectEqualStrings(original.if_name, parsed.if_name);
    try testing.expectEqual(original.if_mtu, parsed.if_mtu);
    try testing.expectEqual(@as(usize, 1), parsed.multicast_interfaces.len);
    try testing.expectEqualStrings("*", parsed.multicast_interfaces[0].filter);
    try testing.expect(parsed.firewall.enable);
    try testing.expectEqual(@as(usize, 3), parsed.firewall.open_tcp.len);
    try testing.expectEqual(@as(u16, 22), parsed.firewall.open_tcp[0]);
    try testing.expectEqual(@as(usize, 1), parsed.firewall.open_udp.len);
    try testing.expectEqual(@as(u16, 53), parsed.firewall.open_udp[0]);
}

test "parseToml handles empty arrays and comments" {
    const text =
        \\# a comment
        \\private_key = "aabbcc"
        \\peers = []
        \\listen = ["tcp://[::]:12345"] # inline comment
        \\if_name = "none"
        \\if_mtu = 1500
        \\
        \\[firewall]
        \\enable = true
        \\open_tcp = [22, 80, 443]
        \\open_udp = []
    ;
    var cfg = try Config.parseToml(testing.allocator, text);
    defer cfg.deinit(testing.allocator);

    try testing.expectEqualStrings("aabbcc", cfg.private_key);
    try testing.expectEqual(@as(usize, 0), cfg.peers.len);
    try testing.expectEqual(@as(usize, 1), cfg.listen.len);
    try testing.expectEqualStrings("tcp://[::]:12345", cfg.listen[0]);
    try testing.expectEqualStrings("none", cfg.if_name);
    try testing.expectEqual(@as(u64, 1500), cfg.if_mtu);
    try testing.expect(cfg.firewall.enable);
    try testing.expectEqual(@as(usize, 3), cfg.firewall.open_tcp.len);
    try testing.expectEqual(@as(usize, 0), cfg.firewall.open_udp.len);
}
