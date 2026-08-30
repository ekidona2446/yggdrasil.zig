//! Crypto-Key Routing (CKR) — tunnel arbitrary IPv4/IPv6 subnets through the
//! mesh by mapping IP prefixes to node public keys.
//!
//! Mirrors the Rust reference (`crates/yggdrasil/src/ckr.rs`): a
//! longest-prefix-match table per address family, built from
//! `[tunnel_routing.remote_subnets]`. Supports the reference's CIDR syntax:
//! bare addresses (`/32` or `/128`), `~`-prefixed entries (tunnel without a
//! system route), `!` exclusions, and the `inetv4`/`inetv6` expansions.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const PublicKey = ironwood.PublicKey;

/// A CIDR prefix in one address family. `addr` is the masked network address
/// right-aligned in a `u128` (IPv4 uses the low 32 bits, IPv6 the full 128).
pub const Prefix = struct {
    v6: bool,
    addr: u128,
    len: u8,

    /// Longest-prefix-match test: does `addr` fall within this prefix?
    fn contains(self: Prefix, addr: u128) bool {
        if (self.len == 0) return true;
        const bits: u32 = if (self.v6) 128 else 32;
        const shift = bits - @as(u32, self.len);
        return (addr >> @intCast(shift)) == (self.addr >> @intCast(shift));
    }
};

/// One route: a prefix plus the destination key.
const Route = struct {
    prefix: Prefix,
    key: PublicKey,
};

/// Longest-prefix-match routing table. Small enough that a linear scan over
/// routes (longest prefix first) is plenty fast.
pub const CkrTable = struct {
    yggdrasil_routing: bool,
    routes: []Route, // owned
    gpa: std.mem.Allocator,

    /// Build the table from config. Routes whose destination equals `self_key`
    /// are dropped (so a shared config can be distributed to every node).
    pub fn init(gpa: std.mem.Allocator, cfg: *const node.config.TunnelRoutingConfig, self_key: PublicKey) !CkrTable {
        var routes = std.ArrayListUnmanaged(Route).empty;
        errdefer routes.deinit(gpa);

        if (cfg.enable) {
            for (cfg.remote_subnets) |rs| {
                const dest = parsePubkey(rs.key_hex) orelse continue;
                if (std.mem.eql(u8, &dest, &self_key)) continue;
                var prefixes = try expandCidrs(gpa, rs.cidrs);
                defer prefixes.deinit(gpa);
                for (prefixes.items) |p| {
                    try routes.append(gpa, .{ .prefix = p, .key = dest });
                }
            }
        }

        // Sort by prefix length descending so the first match is the longest.
        std.mem.sort(Route, routes.items, {}, struct {
            fn lessThan(_: void, a: Route, b: Route) bool {
                return a.prefix.len > b.prefix.len;
            }
        }.lessThan);

        return .{ .yggdrasil_routing = cfg.yggdrasil_routing, .routes = try routes.toOwnedSlice(gpa), .gpa = gpa };
    }

    pub fn deinit(self: *CkrTable) void {
        self.gpa.free(self.routes);
        self.routes = &.{};
    }

    pub fn isEnabled(self: *const CkrTable) bool {
        return self.routes.len > 0 or self.yggdrasil_routing;
    }

    /// Longest-prefix-match lookup for an IP address. Returns the destination
    /// key, or null if no CKR route matches.
    pub fn getKeyForAddress(self: *const CkrTable, v6: bool, addr: u128) ?PublicKey {
        for (self.routes) |r| {
            if (r.prefix.v6 != v6) continue;
            if (r.prefix.contains(addr)) return r.key;
        }
        return null;
    }
};

/// Is this IPv6 address a native Yggdrasil address or subnet (`02xx::` /
/// `03xx::`)?
pub fn isYggdrasilDestination(bytes: *const [16]u8) bool {
    const addr = node.Address{ .bytes = bytes.* };
    if (addr.isValid()) return true;
    const subnet = node.Subnet{ .bytes = bytes[0..8].* };
    return subnet.isValid();
}

/// Parse a 64-hex-char public key.
fn parsePubkey(hex: []const u8) ?PublicKey {
    if (hex.len != 64) return null;
    var key: PublicKey = undefined;
    _ = std.fmt.hexToBytes(&key, hex) catch return null;
    return key;
}

// ---------------------------------------------------------------------------
// CIDR parsing + expansion
// ---------------------------------------------------------------------------

const INETV4_PREFIXES = [_][]const u8{
    "0.0.0.0/5",    "8.0.0.0/7",    "11.0.0.0/8",   "12.0.0.0/6",
    "16.0.0.0/4",   "32.0.0.0/3",   "64.0.0.0/2",   "128.0.0.0/3",
    "160.0.0.0/5",  "168.0.0.0/6",  "172.0.0.0/12", "172.32.0.0/11",
    "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
    "176.0.0.0/4",  "192.0.0.0/9",  "192.128.0.0/11", "192.160.0.0/13",
    "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12",
    "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6",
    "200.0.0.0/5",  "208.0.0.0/4", "240.0.0.0/4",
};
const INETV6_PREFIXES = [_][]const u8{"2000::/3"};

/// Parse a single CIDR string ("10.0.0.0/8", "2001:db8::/32", bare "1.2.3.4").
/// Returns null on parse failure.
fn parsePrefix(text: []const u8) ?Prefix {
    // Split optional "/len".
    var addr_text: []const u8 = text;
    var len: u8 = 0;
    var has_len = false;
    if (std.mem.indexOfScalar(u8, text, '/')) |slash| {
        addr_text = text[0..slash];
        len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
        has_len = true;
    }

    // IPv6 if it contains a colon.
    if (std.mem.indexOfScalar(u8, addr_text, ':') != null) {
        const parsed = std.Io.net.Ip6Address.parse(addr_text, 0) catch return null;
        const bytes = parsed.bytes;
        if (!has_len) len = 128;
        if (len > 128) return null;
        var v: u128 = 0;
        for (bytes) |b| v = (v << 8) | b;
        return .{ .v6 = true, .addr = mask(v, len, 128), .len = len };
    }

    // IPv4.
    const parsed = std.Io.net.Ip4Address.parse(addr_text, 0) catch return null;
    const bytes = parsed.bytes;
    if (!has_len) len = 32;
    if (len > 32) return null;
    var v: u32 = 0;
    for (bytes) |b| v = (v << 8) | b;
    return .{ .v6 = false, .addr = mask(v, len, 32), .len = len };
}

fn mask(addr: u128, len: u8, bits: u32) u128 {
    if (len == 0) return 0;
    const shift = bits - @as(u32, len);
    return (addr >> @intCast(shift)) << @intCast(shift);
}

/// Expand a list of CIDR entries (with `~`, `!`, `inetv4`, `inetv6`) into the
/// minimal set of prefixes covering (includes) \ (excludes). The caller owns
/// the returned list.
pub fn expandCidrs(gpa: std.mem.Allocator, entries: []const []const u8) !std.ArrayListUnmanaged(Prefix) {
    var v4_inc = std.ArrayListUnmanaged(Prefix).empty;
    defer v4_inc.deinit(gpa);
    var v6_inc = std.ArrayListUnmanaged(Prefix).empty;
    defer v6_inc.deinit(gpa);
    var v4_exc = std.ArrayListUnmanaged(Prefix).empty;
    defer v4_exc.deinit(gpa);
    var v6_exc = std.ArrayListUnmanaged(Prefix).empty;
    defer v6_exc.deinit(gpa);

    for (entries) |raw_entry| {
        var raw = std.mem.trim(u8, raw_entry, " \t");
        // `~` prefix = tunnel-only (no system route) — still a CKR include.
        if (raw.len > 0 and raw[0] == '~') raw = std.mem.trim(u8, raw[1..], " \t");

        // `inetv4` / `inetv6` special expansions.
        if (std.ascii.eqlIgnoreCase(raw, "inetv4")) {
            for (INETV4_PREFIXES) |p| try v4_inc.append(gpa, parsePrefix(p).?);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(raw, "inetv6")) {
            for (INETV6_PREFIXES) |p| try v6_inc.append(gpa, parsePrefix(p).?);
            continue;
        }

        var is_exclude = false;
        if (raw.len > 0 and raw[0] == '!') {
            is_exclude = true;
            raw = std.mem.trim(u8, raw[1..], " \t");
        }
        const prefix = parsePrefix(raw) orelse continue;
        if (is_exclude) {
            if (prefix.v6) try v6_exc.append(gpa, prefix) else try v4_exc.append(gpa, prefix);
        } else {
            if (prefix.v6) try v6_inc.append(gpa, prefix) else try v4_inc.append(gpa, prefix);
        }
    }

    var out = std.ArrayListUnmanaged(Prefix).empty;
    errdefer out.deinit(gpa);

    try subtract(gpa, &out, v4_inc.items, v4_exc.items);
    try subtract(gpa, &out, v6_inc.items, v6_exc.items);
    return out;
}

/// Append the result of subtracting every exclude from every include.
fn subtract(
    gpa: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(Prefix),
    incs: []const Prefix,
    excs: []const Prefix,
) !void {
    for (incs) |inc| {
        // Fast path: no excludes overlap this include.
        var overlapping = false;
        for (excs) |exc| {
            if (exc.v6 != inc.v6) continue;
            if (prefixOverlaps(inc, exc)) {
                overlapping = true;
                break;
            }
        }
        if (!overlapping) {
            try out.append(gpa, inc);
            continue;
        }
        try subtractOne(gpa, out, inc, excs);
    }
}

fn prefixOverlaps(a: Prefix, b: Prefix) bool {
    if (a.v6 != b.v6) return false;
    // a contains b's network, or b contains a's network.
    return a.contains(b.addr) or b.contains(a.addr);
}

/// Subtract a set of excludes from a single include, emitting the gaps as
/// prefixes. Recursive half-splitting (like the reference's historical
/// approach): split the include in two and recurse on halves that still
/// overlap an exclude.
fn subtractOne(gpa: std.mem.Allocator, out: *std.ArrayListUnmanaged(Prefix), inc: Prefix, excs: []const Prefix) !void {
    var covered = false;
    for (excs) |exc| {
        if (exc.v6 != inc.v6) continue;
        // If an exclude fully covers the include, nothing to emit.
        if (exc.len <= inc.len and exc.contains(inc.addr)) {
            covered = true;
            break;
        }
    }
    if (covered) return;

    // Does any exclude actually overlap this include?
    var any_overlap = false;
    for (excs) |exc| {
        if (exc.v6 == inc.v6 and prefixOverlaps(inc, exc)) {
            any_overlap = true;
            break;
        }
    }
    if (!any_overlap) {
        try out.append(gpa, inc);
        return;
    }

    const bits: u32 = if (inc.v6) 128 else 32;
    if (inc.len >= bits) return; // /32 or /128 leaf: partially covered, emit anyway
    // Split into two halves.
    const half_len = inc.len + 1;
    const half_bits = bits - @as(u32, half_len);
    const step: u128 = @as(u128, 1) << @intCast(half_bits);
    const lo = Prefix{ .v6 = inc.v6, .addr = inc.addr, .len = half_len };
    const hi = Prefix{ .v6 = inc.v6, .addr = inc.addr + step, .len = half_len };
    try subtractOne(gpa, out, lo, excs);
    try subtractOne(gpa, out, hi, excs);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parsePrefix ipv4 and ipv6" {
    const p4 = parsePrefix("10.0.0.0/8").?;
    try testing.expect(!p4.v6);
    try testing.expectEqual(@as(u8, 8), p4.len);
    try testing.expectEqual(@as(u128, 10 << 24), p4.addr);

    const p4bare = parsePrefix("1.2.3.4").?;
    try testing.expectEqual(@as(u8, 32), p4bare.len);

    const p6 = parsePrefix("2001:db8::/32").?;
    try testing.expect(p6.v6);
    try testing.expectEqual(@as(u8, 32), p6.len);

    const p6bare = parsePrefix("2001:db8::1").?;
    try testing.expectEqual(@as(u8, 128), p6bare.len);
}

test "prefix contains" {
    const p = parsePrefix("10.0.0.0/8").?;
    try testing.expect(p.contains(0x0a_01_02_03));
    try testing.expect(!p.contains(0x0b_01_02_03));
}

test "expand cidrs excludes" {
    const gpa = testing.allocator;
    var list = try expandCidrs(gpa, &.{ "10.0.0.0/8", "!10.1.0.0/16" });
    defer list.deinit(gpa);
    // 10.0.0.0/8 minus 10.1.0.0/16 yields a handful of prefixes.
    try testing.expect(list.items.len > 1);
    // None of them should contain 10.1.x.x.
    for (list.items) |p| {
        try testing.expect(!p.contains(0x0a_01_00_00));
    }
    // But 10.2.0.0 should still be covered.
    var covered = false;
    for (list.items) |p| {
        if (p.contains(0x0a_02_00_00)) covered = true;
    }
    try testing.expect(covered);
}

test "ckr table lookup" {
    const gpa = testing.allocator;
    const self = [_]u8{0x11} ** 32;
    var cfg = node.config.TunnelRoutingConfig{
        .enable = true,
        .remote_subnets = &.{
            .{
                .key_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                .cidrs = &.{ "10.0.0.0/8" },
            },
        },
    };
    var table = try CkrTable.init(gpa, &cfg, self);
    defer table.deinit();

    const key = table.getKeyForAddress(false, 0x0a_01_02_03);
    try testing.expect(key != null);
    try testing.expectEqual(@as(u8, 0xaa), key.?[0]);
    try testing.expect(table.getKeyForAddress(false, 0x0b_00_00_00) == null);
}

test "yggdrasil destination detection" {
    const ygg = [_]u8{ 0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const not = [_]u8{ 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expect(isYggdrasilDestination(&ygg));
    try testing.expect(!isYggdrasilDestination(&not));
}
