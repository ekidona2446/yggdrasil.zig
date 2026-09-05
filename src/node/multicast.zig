//! LAN multicast peer discovery.
//!
//! Sends and receives BLAKE2b-authenticated advertisements on
//! ff02::114:9001 to discover Yggdrasil peers on the local network, mirroring
//! yggdrasil-go's `src/multicast`. The beacon announces our TLS listener on
//! each configured interface; the listener receives beacons, verifies their
//! auth hash, and auto-peers with the sender.
//!
//! The wire format is:
//!   major_version u16be | minor_version u16be | public_key [32] | port u16be
//!   | hash_len u16be | hash [hash_len]
//! where `hash = BLAKE2b-512(public_key, key=password)`.

const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");
const udp_io = @import("udp_io.zig");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const c = std.c;
const PublicKey = ironwood.PublicKey;
const Metadata = node.version.Metadata;
const NetworkManager = node.network.NetworkManager;

pub const MULTICAST_GROUP: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x14 };
pub const MULTICAST_PORT: u16 = 9001;
pub const BEACON_MAX_INTERVAL_NS: u64 = 15 * std.time.ns_per_s;
const RECV_BUF_SIZE: usize = 2048;
/// How often the driver wakes to drain beacons / decide whether to announce.
const TICK_MS: u64 = 250;

const timemod = @import("util").time;

// ---------------------------------------------------------------------------
// Platform primitives (IPv6 multicast sockets + interface enumeration).
// These are POSIX concepts (`getifaddrs`, `ipv6_mreq`, `IPV6_JOIN_GROUP`);
// the constants differ per OS, so they're dispatched on `builtin.os.tag`.
// ---------------------------------------------------------------------------

const IFF_UP: c_uint = 0x1;
/// Defined for completeness but deliberately not used as a filter:
/// yggdrasil-go's `_updateInterfaces` checks only Up/Running/Multicast and
/// not-PointToPoint, so it multicasts on loopback too. Matching that keeps two
/// nodes on one host discoverable in both implementations.
const IFF_LOOPBACK: c_uint = 0x8;
const IFF_POINTOPOINT: c_uint = 0x10;
const IFF_RUNNING: c_uint = 0x40;
const IFF_MULTICAST: c_uint = switch (builtin.os.tag) {
    .linux, .windows => 0x1000,
    // macOS / BSD use a different bit for IFF_MULTICAST.
    .macos, .ios, .maccatalyst, .tvos, .visionos, .watchos,
    .freebsd, .netbsd, .openbsd, .dragonfly, .illumos,
    => 0x8000,
    else => 0x1000,
};

/// `struct ipv6_mreq { struct in6_addr ipv6mr_multiaddr; unsigned int ipv6mr_interface; }`.
const ipv6_mreq = extern struct {
    multiaddr: [16]u8,
    interface: c_uint,
};

/// `IPV6_JOIN_GROUP` (Linux; a.k.a. `IPV6_ADD_MEMBERSHIP` on BSD/macOS/Windows).
const IPV6_JOIN_GROUP: u32 = switch (builtin.os.tag) {
    .linux => 20,
    .windows, .macos, .ios, .maccatalyst, .tvos, .visionos, .watchos,
    .freebsd, .netbsd, .openbsd, .dragonfly, .illumos,
    => 12,
    else => 20,
};

/// `IPV6_LEAVE_GROUP` / `IPV6_DROP_MEMBERSHIP`.
const IPV6_LEAVE_GROUP: u32 = switch (builtin.os.tag) {
    .linux => 21,
    .windows, .macos, .ios, .maccatalyst, .tvos, .visionos, .watchos,
    .freebsd, .netbsd, .openbsd, .dragonfly, .illumos,
    => 13,
    else => 21,
};

/// `struct sockaddr_in6` in the Linux/BSD/Windows layout (`sin6_family` first).
/// macOS's native struct leads with a `sin6_len` byte; that variant is not
/// handled here (the multicast driver is exercised on Linux).
const SockaddrIn6 = extern struct {
    family: u16,
    port: u16, // network byte order
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

const AF_INET6: u16 = 10;

/// One candidate interface, as enumerated by the platform backends below.
/// `name` is borrowed from the platform's own buffer on POSIX and owned by the
/// caller on Windows (see `win_if.adapterName`), which is why results are
/// released through `freeEnumerated` rather than freed directly.
const RawIf = struct {
    name: []const u8,
    index: u32,
    addr: [16]u8,
    up: bool,
    running: bool,
    multicast: bool,
    pointopoint: bool,
};

const posix_if = struct {
    const IfAddrs = extern struct {
        ifa_next: ?*IfAddrs,
        ifa_name: [*:0]u8,
        ifa_flags: c_uint,
        ifa_addr: ?*c.sockaddr,
        ifa_netmask: ?*c.sockaddr,
        ifa_ifu: ?*c.sockaddr,
        ifa_data: ?*anyopaque,
    };
    extern "c" fn getifaddrs(ifap: *?*IfAddrs) c_int;
    extern "c" fn freeifaddrs(ifa: *IfAddrs) void;

    fn enumerate(gpa: std.mem.Allocator) ![]RawIf {
        var out: std.ArrayListUnmanaged(RawIf) = .empty;
        errdefer out.deinit(gpa);

        var head: ?*IfAddrs = null;
        if (getifaddrs(&head) != 0) return error.EnumerationFailed;
        defer if (head) |h| freeifaddrs(h);

        var cur = head;
        while (cur) |ifa| : (cur = ifa.ifa_next) {
            const sa = ifa.ifa_addr orelse continue;
            if (sa.family != AF_INET6) continue;
            const sin6: *align(1) const SockaddrIn6 = @ptrCast(sa);
            if (!isLinkLocal(&sin6.addr)) continue;

            const name = std.mem.span(ifa.ifa_name);
            const raw_idx = c.if_nametoindex(ifa.ifa_name);
            if (raw_idx <= 0) continue;

            try out.append(gpa, .{
                .name = name,
                .index = @intCast(raw_idx),
                .addr = sin6.addr,
                .up = ifa.ifa_flags & IFF_UP != 0,
                .running = ifa.ifa_flags & IFF_RUNNING != 0,
                .multicast = ifa.ifa_flags & IFF_MULTICAST != 0,
                .pointopoint = ifa.ifa_flags & IFF_POINTOPOINT != 0,
            });
        }
        return out.toOwnedSlice(gpa);
    }
};

/// Windows has no `getifaddrs`; the equivalent is `GetAdaptersAddresses`
/// (iphlpapi), which Zig 0.16's std does not bind, so the pieces this needs
/// are declared here. Only the fields up to `ipv6_if_index` are spelled out --
/// iteration follows each entry's `next` pointer, so the trailing half of the
/// struct (prefixes, gateways, WINS, ...) is never read and can stay undefined.
const win_if = struct {
    const ADAPTER_UNICAST = extern struct {
        alignment: u64,
        next: ?*ADAPTER_UNICAST,
        sockaddr: ?*anyopaque,
        sockaddr_len: i32,
    };

    const ADAPTER_ADDRESSES = extern struct {
        alignment: u64,
        next: ?*ADAPTER_ADDRESSES,
        adapter_name: [*:0]u8,
        first_unicast: ?*ADAPTER_UNICAST,
        first_anycast: ?*anyopaque,
        first_multicast: ?*anyopaque,
        first_dns_server: ?*anyopaque,
        dns_suffix: [*:0]u16,
        description: [*:0]u16,
        friendly_name: [*:0]u16,
        physical_address: [16]u8,
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: u32,
        ipv6_if_index: u32,
        zone_indices: [16]u32,
    };

    extern "iphlpapi" fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: ?*anyopaque,
        addresses: ?*anyopaque,
        size: *u32,
    ) callconv(.winapi) u32;

    const AF_INET6_WIN: u32 = 23;
    const GAA_SKIP: u32 = 0x2 | 0x4 | 0x8; // anycast | multicast | dns server
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_OPER_STATUS_UP: u32 = 1;
    const IF_TYPE_PPP: u32 = 23;
    /// Windows exposes no `IFF_MULTICAST`; PPP, loopback and tunnel adapters
    /// are the ones that cannot carry a link-local multicast group.
    const NO_MULTICAST_TYPES = [_]u32{ 23, 24, 131 }; // PPP, software loopback, tunnel

    fn enumerate(gpa: std.mem.Allocator) ![]RawIf {
        var out: std.ArrayListUnmanaged(RawIf) = .empty;
        errdefer out.deinit(gpa);

        var size: u32 = 16 * 1024;
        var buf: []u8 = try gpa.alloc(u8, size);
        errdefer gpa.free(buf);
        var rc: u32 = 0;
        while (true) {
            rc = GetAdaptersAddresses(AF_INET6_WIN, GAA_SKIP, null, buf.ptr, &size);
            if (rc != ERROR_BUFFER_OVERFLOW) break;
            buf = gpa.realloc(buf, size) catch return error.EnumerationFailed;
        }
        if (rc != 0) return error.EnumerationFailed;
        defer gpa.free(buf);

        var adapter: ?*ADAPTER_ADDRESSES = @ptrCast(@alignCast(buf.ptr));
        while (adapter) |a| : (adapter = a.next) {
            const up = a.oper_status == IF_OPER_STATUS_UP;
            const type_is_multicast = blk: {
                for (NO_MULTICAST_TYPES) |t| if (a.if_type == t) break :blk false;
                break :blk true;
            };

            var uc = a.first_unicast;
            while (uc) |u| : (uc = u.next) {
                const sa: *align(1) const SockaddrIn6 = @ptrCast(u.sockaddr orelse continue);
                if (sa.family != AF_INET6) continue;
                if (!isLinkLocal(&sa.addr)) continue;

                try out.append(gpa, .{
                    .name = adapterName(gpa, a),
                    .index = a.ipv6_if_index,
                    .addr = sa.addr,
                    .up = up,
                    .running = up,
                    .multicast = type_is_multicast,
                    .pointopoint = a.if_type == IF_TYPE_PPP,
                });
                break; // one link-local address per adapter is enough
            }
        }
        return out.toOwnedSlice(gpa);
    }

    /// Prefer the friendly name ("Ethernet 2") -- that is what a Windows user
    /// would write in `MulticastInterfaces` -- falling back to the adapter
    /// GUID when the system has no friendly name for it.
    fn adapterName(gpa: std.mem.Allocator, a: *const ADAPTER_ADDRESSES) []const u8 {
        const friendly = std.mem.span(a.friendly_name);
        if (friendly.len > 0) {
            return std.unicode.utf16LeToUtf8Alloc(gpa, friendly) catch
                std.mem.span(a.adapter_name);
        }
        return std.mem.span(a.adapter_name);
    }
};

fn enumerateInterfaces(gpa: std.mem.Allocator) ![]RawIf {
    if (comptime builtin.os.tag == .windows) return win_if.enumerate(gpa);
    return posix_if.enumerate(gpa);
}

fn freeEnumerated(gpa: std.mem.Allocator, raw: []RawIf) void {
    // Windows names are UTF-8 conversions we own; POSIX ones are borrowed
    // from `getifaddrs`' own buffer.
    for (raw) |r| if (comptime builtin.os.tag == .windows) gpa.free(r.name);
    gpa.free(raw);
}

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

/// Simple glob match (`*` wildcards only) — the reference uses a full regexp,
/// but the overwhelmingly common filters are `"*"`, `"eth0"`, `"eth.*"`.
fn globMatch(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == name[n])) {
            p += 1;
            n += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            star_n = n;
        } else if (star) |sp| {
            p = sp + 1;
            star_n += 1;
            n = star_n;
        } else {
            return false;
        }
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn isLinkLocal(addr: *const [16]u8) bool {
    return addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80;
}

// ---------------------------------------------------------------------------
// The multicast driver
// ---------------------------------------------------------------------------

pub const Multicast = struct {
    gpa: std.mem.Allocator,
    loop: *xev.Loop,
    net: *NetworkManager,
    our_key: PublicKey,
    /// Config entries (slices borrow the config object; never freed here).
    config: []const node.config.MulticastInterfaceConfig,

    /// `posix.socket_t`: an `i32` fd on POSIX, a `HANDLE` on Windows. A
    /// separate `sock_open` flag records validity, because a Windows handle
    /// has no "invalid" integer value to compare against.
    sock: std.posix.socket_t = undefined,
    sock_open: bool = false,
    running: bool = false,
    timer: xev.Timer,
    timer_c: xev.Completion = undefined,
    next_announce_ns: u64 = 0,

    /// Discovered/selected interfaces (owned).
    interfaces: std.ArrayListUnmanaged(IfInfo) = .empty,
    /// Interface indexes whose group membership we currently hold, so we join
    /// each one once instead of on every tick.
    joined: std.AutoHashMapUnmanaged(u32, void) = .empty,
    /// The beacon listener's actual bound port (0 = no beacon listener yet).
    beacon_port: u16 = 0,
    /// URI of the beacon listener we created (owned; null until created).
    beacon_uri: ?[]u8 = null,

    const IfInfo = struct {
        name: []u8, // owned
        index: u32,
        addr: [16]u8, // link-local IPv6
        beacon: bool,
        listen: bool,
        port: u16,
        priority: u8,
        password: []u8, // owned copy
        hash: [64]u8,

        fn deinit(self: *IfInfo, gpa: std.mem.Allocator) void {
            gpa.free(self.name);
            gpa.free(self.password);
        }
    };

    pub fn init(gpa: std.mem.Allocator, loop: *xev.Loop, net: *NetworkManager, our_key: PublicKey, config: []const node.config.MulticastInterfaceConfig) !Multicast {
        return .{ .gpa = gpa, .loop = loop, .net = net, .our_key = our_key, .config = config, .timer = try xev.Timer.init() };
    }

    pub fn deinit(self: *Multicast) void {
        self.stop();
        for (self.interfaces.items) |*i| i.deinit(self.gpa);
        self.interfaces.deinit(self.gpa);
        if (self.beacon_uri) |u| self.gpa.free(u);
        self.beacon_uri = null;
        self.timer.deinit();
    }

    /// `SOCK_CLOEXEC` is a Linux/BSD extension: winsock's `SOCK` has no such
    /// bit, so it is taken only where the platform libc defines it.
    const SOCK_CLOEXEC: c_int = if (@hasDecl(c.SOCK, "CLOEXEC")) c.SOCK.CLOEXEC else 0;

    /// `MSG_DONTWAIT` does not exist in winsock, so on Windows the socket
    /// itself is switched to non-blocking mode (see `start`) and `recvfrom`
    /// is called with no flags -- which is why the drain loop cannot block.
    const MSG_DONTWAIT: c_int = if (builtin.os.tag == .windows) 0 else std.posix.MSG.DONTWAIT;

    /// `IPPROTO_IPV6` is 41 on every platform, but std's winsock `IPPROTO`
    /// struct does not spell it out.
    const IPPROTO_IPV6: c_int = if (builtin.os.tag == .windows) 41 else c.IPPROTO.IPV6;

    /// Open the socket, join the multicast groups, and start the driver timer.
    pub fn start(self: *Multicast) !void {
        if (self.running) return;
        const rc = c.socket(AF_INET6, c.SOCK.DGRAM | SOCK_CLOEXEC, 0);
        if (rc < 0) return error.SocketFailed;
        const fd = udp_io.socketFromRc(rc);
        self.sock = fd;
        self.sock_open = true;
        if (comptime builtin.os.tag == .windows) {
            // No MSG_DONTWAIT there, so non-blocking has to be a property of
            // the socket instead of a per-call flag (see MSG_DONTWAIT above).
            udp_io.setNonblocking(fd) catch {};
        }

        // SO_REUSEADDR (+ SO_REUSEPORT where available) so several nodes can
        // share the well-known group address on the same host.
        var one: c_int = 1;
        _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.REUSEADDR, &one, @sizeOf(c_int));
        if (@hasDecl(c.SO, "REUSEPORT")) {
            _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.REUSEPORT, &one, @sizeOf(c_int));
        }

        var bind_addr = SockaddrIn6{
            .family = AF_INET6,
            .port = std.mem.nativeToBig(u16, MULTICAST_PORT),
            .flowinfo = 0,
            .addr = [_]u8{0} ** 16,
            .scope_id = 0,
        };
        if (c.bind(fd, @ptrCast(&bind_addr), @sizeOf(SockaddrIn6)) != 0) {
            udp_io.closeSocketFd(fd);
            self.sock_open = false;
            return error.BindFailed;
        }

        self.running = true;
        self.refreshInterfaces();
        self.timer.run(self.loop, &self.timer_c, TICK_MS, Multicast, self, onTick);
        self.next_announce_ns = 0; // announce immediately on first tick
    }

    pub fn stop(self: *Multicast) void {
        if (!self.running) return;
        self.running = false;
        // Closing the socket drops every membership; just forget the record so
        // a later start() joins again.
        self.joined.clearRetainingCapacity();
        if (self.sock_open) {
            udp_io.closeSocketFd(self.sock);
            self.sock_open = false;
        }
    }

    fn onTick(ud: ?*Multicast, loop: *xev.Loop, cc: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        if (!self.running) return .disarm;
        self.drain();
        self.maybeAnnounce();
        self.timer.run(loop, cc, TICK_MS, Multicast, self, onTick);
        return .disarm;
    }

    /// Non-blocking drain of received beacons.
    fn drain(self: *Multicast) void {
        var buf: [RECV_BUF_SIZE]u8 = undefined;
        while (true) {
            var from = SockaddrIn6{ .family = 0, .port = 0, .flowinfo = 0, .addr = undefined, .scope_id = 0 };
            var from_len: c.socklen_t = @sizeOf(SockaddrIn6);
            const n: isize = std.posix.system.recvfrom(
                self.sock,
                buf[0..].ptr,
                buf.len,
                MSG_DONTWAIT,
                @ptrCast(&from),
                &from_len,
            );
            if (n <= 0) break;
            self.handleBeacon(buf[0..@intCast(n)], &from);
        }
    }

    fn handleBeacon(self: *Multicast, data: []const u8, from: *const SockaddrIn6) void {
        const adv = Advertisement.decode(data, self.gpa) catch return;
        defer self.gpa.free(adv.hash);
        if (adv.major_version != node.version.PROTOCOL_VERSION_MAJOR) return;
        if (adv.minor_version != node.version.PROTOCOL_VERSION_MINOR) return;
        if (std.mem.eql(u8, &adv.public_key, &self.our_key)) return;

        // Which interface did this arrive on? The scope id of the source
        // address is the receiving interface index on Linux/macOS/BSD.
        const info = self.findInterface(from.scope_id, adv.public_key, adv.hash) orelse return;

        var addr_buf: [48]u8 = undefined;
        var w = std.Io.Writer.fixed(&addr_buf);
        node.address.formatIpv6(&from.addr, &w) catch return;
        const addr_text = addr_buf[0..w.end];

        var key_hex: [64]u8 = undefined;
        const hx = "0123456789abcdef";
        for (adv.public_key, 0..) |b, i| {
            key_hex[i * 2] = hx[(b >> 4) & 0xF];
            key_hex[i * 2 + 1] = hx[b & 0xF];
        }
        // Numeric scope id so the link-local dial is routed on the interface
        // the beacon arrived on.
        var uri_buf: [256]u8 = undefined;
        const uri = std.fmt.bufPrint(&uri_buf, "tls://[{s}%{d}]:{d}?key={s}&priority={d}&password={s}", .{
            addr_text, from.scope_id, adv.port, key_hex, info.priority, info.password,
        }) catch return;
        std.debug.print("[ygg] multicast discovered peer {s}\n", .{uri});
        self.net.addOutboundPeer(uri, .{}) catch |err| {
            std.debug.print("[ygg] multicast peer dial failed: {}\n", .{err});
        };
    }

    /// Find the interface entry matching the receiving index and verify the
    /// auth hash against that entry's password.
    fn findInterface(self: *Multicast, idx: u32, key: PublicKey, hash: []const u8) ?*IfInfo {
        for (self.interfaces.items) |*info| {
            if (info.index != idx or !info.listen) continue;
            var computed: [64]u8 = undefined;
            if (info.password.len == 0) {
                std.crypto.hash.blake2.Blake2b512.hash(&key, &computed, .{});
            } else {
                std.crypto.hash.blake2.Blake2b512.hash(&key, &computed, .{ .key = info.password });
            }
            if (std.mem.eql(u8, &computed, hash)) return info;
        }
        return null;
    }

    fn maybeAnnounce(self: *Multicast) void {
        const now = timemod.monotonicNanos();
        if (now < self.next_announce_ns) return;
        // Re-scan interfaces each announce (interfaces come and go).
        self.refreshInterfaces();
        self.announce() catch |err| {
            std.debug.print("[ygg] multicast announce error: {}\n", .{err});
        };
        // ~1s + up to ~1s of jitter, like the reference.
        self.next_announce_ns = now + std.time.ns_per_s + (now % std.time.ns_per_s);
    }

    /// (Re)enumerate the set of interfaces we multicast on, joining the group
    /// on every `listen` interface.
    fn refreshInterfaces(self: *Multicast) void {
        for (self.interfaces.items) |*i| i.deinit(self.gpa);
        self.interfaces.clearRetainingCapacity();

        const raw = enumerateInterfaces(self.gpa) catch return;
        defer freeEnumerated(self.gpa, raw);

        for (raw) |ifa| {
            const name = ifa.name;

            // Interface must be up, running, multicast-capable, non-P2P.
            if (!ifa.up) continue;
            if (!ifa.running) continue;
            if (!ifa.multicast) continue;
            if (ifa.pointopoint) continue;

            // Match against config (first matching entry wins, like the ref).
            var cfg: ?*const node.config.MulticastInterfaceConfig = null;
            for (self.config) |*mc| {
                if (!mc.beacon and !mc.listen) continue;
                if (globMatch(mc.filter, name)) {
                    cfg = mc;
                    break;
                }
            }
            const mc = cfg orelse continue;

            const idx = ifa.index;
            var hash: [64]u8 = undefined;
            if (mc.password.len == 0) {
                std.crypto.hash.blake2.Blake2b512.hash(&self.our_key, &hash, .{});
            } else {
                std.crypto.hash.blake2.Blake2b512.hash(&self.our_key, &hash, .{ .key = mc.password });
            }

            const name_dup = self.gpa.dupe(u8, name) catch continue;
            const pw_dup = self.gpa.dupe(u8, mc.password) catch {
                self.gpa.free(name_dup);
                continue;
            };
            self.interfaces.append(self.gpa, .{
                .name = name_dup,
                .index = idx,
                .addr = ifa.addr,
                .beacon = mc.beacon,
                .listen = mc.listen,
                .port = mc.port,
                .priority = mc.priority,
                .password = pw_dup,
                .hash = hash,
            }) catch {
                self.gpa.free(name_dup);
                self.gpa.free(pw_dup);
                continue;
            };
        }
        self.reconcileMemberships();
    }

    /// Bring group membership in line with the interfaces we just enumerated.
    ///
    /// yggdrasil-go calls `JoinGroup` for every listen interface on every tick
    /// and discards the resulting `EADDRINUSE`, so it issues one pointless
    /// setsockopt per interface per second forever and never gives a membership
    /// back when an interface disappears. Joining only what is new and dropping
    /// what is gone is the same observable behaviour -- we end up a member of
    /// ff02::114 on exactly the listen interfaces -- without the churn.
    fn reconcileMemberships(self: *Multicast) void {
        var wanted: std.AutoHashMapUnmanaged(u32, void) = .empty;
        defer wanted.deinit(self.gpa);
        for (self.interfaces.items) |i| {
            if (!i.listen) continue;
            wanted.put(self.gpa, i.index, {}) catch {};
            if (self.joined.contains(i.index)) continue;
            if (self.setMembership(i.index, IPV6_JOIN_GROUP)) {
                self.joined.put(self.gpa, i.index, {}) catch {};
            }
        }
        var stale = std.ArrayList(u32).empty;
        defer stale.deinit(self.gpa);
        var it = self.joined.keyIterator();
        while (it.next()) |kp| {
            if (!wanted.contains(kp.*)) stale.append(self.gpa, kp.*) catch {};
        }
        for (stale.items) |idx| {
            _ = self.setMembership(idx, IPV6_LEAVE_GROUP);
            _ = self.joined.remove(idx);
        }
    }

    /// Returns true when we hold the membership afterwards. `EADDRINUSE` on a
    /// join means we were already a member, which is the wanted outcome; every
    /// other failure is reported, unlike the reference which discards them all.
    fn setMembership(self: *Multicast, idx: u32, opt: u32) bool {
        var mreq = ipv6_mreq{ .multiaddr = MULTICAST_GROUP, .interface = idx };
        if (c.setsockopt(self.sock, IPPROTO_IPV6, opt, &mreq, @sizeOf(ipv6_mreq)) == 0) return true;
        const err = std.c._errno().*;
        if (opt == IPV6_JOIN_GROUP and err == @intFromEnum(std.c.E.ADDRINUSE)) return true;
        std.debug.print("[ygg] multicast: setsockopt({s}) on ifindex {d} failed: {d}\n", .{
            if (opt == IPV6_JOIN_GROUP) "IPV6_JOIN_GROUP" else "IPV6_LEAVE_GROUP",
            idx,
            err,
        });
        return false;
    }

    /// Ensure a beacon listener exists and send our advertisement on every
    /// beacon interface.
    fn announce(self: *Multicast) !void {
        var any_beacon = false;
        for (self.interfaces.items) |*info| {
            if (info.beacon) {
                any_beacon = true;
                break;
            }
        }
        if (!any_beacon) return;

        // Create the beacon listener once. Bound to [::] (all interfaces); the
        // reference binds per-interface link-local addresses, but a wildcard
        // listener accepts the dials peers make to our link-local address too.
        if (self.beacon_uri == null) {
            const first = for (self.interfaces.items) |*info| {
                if (info.beacon) break info;
            } else return;
            var uri_buf: [128]u8 = undefined;
            const uri = try std.fmt.bufPrint(&uri_buf, "tls://[::]:{d}?priority={d}&password={s}", .{
                first.port, first.priority, first.password,
            });
            const bound = self.net.addListener(uri) catch |err| {
                std.debug.print("[ygg] multicast beacon listener failed: {}\n", .{err});
                return;
            };
            self.beacon_port = if (bound != 0) bound else first.port;
            self.beacon_uri = try self.gpa.dupe(u8, uri);
        }

        const port = self.beacon_port;
        for (self.interfaces.items) |*info| {
            if (!info.beacon) continue;
            const adv = Advertisement{
                .major_version = node.version.PROTOCOL_VERSION_MAJOR,
                .minor_version = node.version.PROTOCOL_VERSION_MINOR,
                .public_key = self.our_key,
                .port = port,
                .hash = &info.hash,
            };
            const msg = try adv.encode(self.gpa);
            defer self.gpa.free(msg);
            var dest = SockaddrIn6{
                .family = AF_INET6,
                .port = std.mem.nativeToBig(u16, MULTICAST_PORT),
                .flowinfo = 0,
                .addr = MULTICAST_GROUP,
                .scope_id = info.index,
            };
            _ = std.posix.system.sendto(self.sock, msg.ptr, msg.len, 0, @ptrCast(&dest), @sizeOf(SockaddrIn6));
        }
    }

    /// Write the admin `getMulticastInterfaces` JSON body directly, mirroring
    /// Go's `GetMulticastInterfacesResponse` (interfaces sorted stably by name).
    pub fn writeAdminJson(self: *Multicast, w: *std.Io.Writer) !void {
        // Collect interface pointers and sort them by name.
        const gpa = self.gpa;
        const ptrs = try gpa.alloc(*const IfInfo, self.interfaces.items.len);
        defer gpa.free(ptrs);
        for (self.interfaces.items, 0..) |*info, i| ptrs[i] = info;
        std.mem.sort(*const IfInfo, ptrs, {}, struct {
            fn lessThan(_: void, a: *const IfInfo, b: *const IfInfo) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lessThan);

        try w.writeAll("{\"multicast_interfaces\":[");
        for (ptrs, 0..) |info, i| {
            if (i != 0) try w.writeAll(",");
            // address: the per-interface TLS listener is bound to
            // `[fe80::...%ifname]:port` (Go's `listener.Addr().String()`), or "-".
            try w.writeAll("{\"name\":");
            try node.admin.writeJsonString(w, info.name);
            try w.writeAll(",\"address\":");
            if (self.beacon_port != 0 and info.beacon) {
                var ipbuf: [48]u8 = undefined;
                var iw = std.Io.Writer.fixed(&ipbuf);
                if (node.address.formatIpv6(&info.addr, &iw)) |_| {
                    var buf: [96]u8 = undefined;
                    if (std.fmt.bufPrint(&buf, "[{s}%{s}]:{d}", .{ ipbuf[0..iw.end], info.name, self.beacon_port })) |s| {
                        try node.admin.writeJsonString(w, s);
                    } else |_| {
                        try node.admin.writeJsonString(w, "-");
                    }
                } else |_| {
                    try node.admin.writeJsonString(w, "-");
                }
            } else {
                try node.admin.writeJsonString(w, "-");
            }
            try w.print(",\"beacon\":{},\"listen\":{},\"password\":{}}}", .{
                info.beacon, info.listen, info.password.len > 0,
            });
        }
        try w.writeAll("]}");
    }
};

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

test "glob match" {
    try testing.expect(globMatch("*", "eth0"));
    try testing.expect(globMatch("eth0", "eth0"));
    try testing.expect(!globMatch("eth0", "eth1"));
    try testing.expect(globMatch("eth*", "eth0"));
    try testing.expect(globMatch("e?h0", "eth0"));
    try testing.expect(globMatch("*.0", "eth1.0"));
    try testing.expect(!globMatch("*.0", "eth0"));
    try testing.expect(!globMatch("wlan*", "eth0"));
}

test "link local detection" {
    const fe80 = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const global = [_]u8{ 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expect(isLinkLocal(&fe80));
    try testing.expect(!isLinkLocal(&global));
}
