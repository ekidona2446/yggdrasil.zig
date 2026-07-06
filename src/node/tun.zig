//! TUN adapter — creates and manages a TUN network interface.
//!
//! Platform-specific: uses /dev/net/tun on Linux. Provides both a blocking
//! read/write API (used by `initFd`-wrapping code) and helpers to drive the
//! fd through libxev's `xev.File` watcher for async I/O in the main loop.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

pub const TunAdapter = struct {
    fd: std.posix.fd_t,
    name: [16:0]u8,
    mtu: u16,
    enabled: bool,

    pub fn init(name: []const u8, addr_str: []const u8, mtu: u16) !TunAdapter {
        if (std.mem.eql(u8, name, "none")) return .{
            .fd = -1,
            .name = .{0} ** 16,
            .mtu = mtu,
            .enabled = false,
        };

        const ifname = if (std.mem.eql(u8, name, "auto")) "ygg0" else name;
        const trunc_len = @min(ifname.len, 15);

        // Open /dev/net/tun
        const fd = try std.posix.openat(
            std.posix.AT.FDCWD,
            "/dev/net/tun",
            .{ .ACCMODE = .RDWR },
            0,
        );
        errdefer _ = std.os.linux.close(fd);

        // Configure TUN interface
        var ifr: [40]u8 = [_]u8{0} ** 40;
        @memcpy(ifr[0..trunc_len], ifname[0..trunc_len]);
        // IFF_TUN | IFF_NO_PI
        std.mem.writeInt(i16, ifr[16..18], 1 | 0x1000, .native);

        const TUNSETIFF: u64 = 0x400454CA;
        const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        if (rc != 0) {
            _ = std.os.linux.close(fd);
            return error.TunSetupFailed;
        }

        // Bring the interface up and set its MTU via a UDP socket + SIOCSIF*
        // ioctls (the tun fd itself doesn't support these).
        const sock = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
        if (@as(isize, @bitCast(sock)) >= 0) {
            defer _ = std.os.linux.close(@intCast(sock));

            var ifr_mtu: [40]u8 = [_]u8{0} ** 40;
            @memcpy(ifr_mtu[0..trunc_len], ifname[0..trunc_len]);
            std.mem.writeInt(i32, ifr_mtu[16..20], @as(i32, mtu), .native);
            const SIOCSIFMTU: u64 = 0x8922;
            _ = std.os.linux.ioctl(@intCast(sock), SIOCSIFMTU, @intFromPtr(&ifr_mtu));

            var ifr_flags: [40]u8 = [_]u8{0} ** 40;
            @memcpy(ifr_flags[0..trunc_len], ifname[0..trunc_len]);
            const SIOCGIFFLAGS: u64 = 0x8913;
            const SIOCSIFFLAGS: u64 = 0x8914;
            _ = std.os.linux.ioctl(@intCast(sock), SIOCGIFFLAGS, @intFromPtr(&ifr_flags));
            const IFF_UP: i16 = 0x1;
            const IFF_RUNNING: i16 = 0x40;
            var flags = std.mem.readInt(i16, ifr_flags[16..18], .native);
            flags |= IFF_UP | IFF_RUNNING;
            std.mem.writeInt(i16, ifr_flags[16..18], flags, .native);
            _ = std.os.linux.ioctl(@intCast(sock), SIOCSIFFLAGS, @intFromPtr(&ifr_flags));
        }

        _ = addr_str; // IPv6 address assignment left to `assignAddress`.

        var name_buf: [16:0]u8 = .{0} ** 16;
        @memcpy(name_buf[0..trunc_len], ifname[0..trunc_len]);

        return .{
            .fd = fd,
            .name = name_buf,
            .mtu = mtu,
            .enabled = true,
        };
    }

    pub fn deinit(self: *TunAdapter) void {
        if (self.enabled) {
            _ = std.os.linux.close(self.fd);
            self.enabled = false;
        }
    }

    pub fn read(self: *TunAdapter, buf: []u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        return try std.posix.read(self.fd, buf);
    }

    pub fn write(self: *TunAdapter, buf: []const u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        const n = std.os.linux.write(self.fd, buf.ptr, buf.len);
        const signed: isize = @bitCast(n);
        if (signed < 0) return error.WriteFailed;
        return n;
    }
};

// ---------------------------------------------------------------------------
// Address assignment via direct ioctls (no external process dependency).
// ---------------------------------------------------------------------------

/// In6_ifreq, as used by SIOCSIFADDR/SIOCDIFADDR on an AF_INET6 socket.
/// See linux/ipv6.h.
const in6_ifreq = extern struct {
    addr: [16]u8,
    prefixlen: u32,
    ifindex: i32,
};

/// Assign the Yggdrasil IPv6 address (with /7 "network" visibility, matching
/// the reference implementation's use of a broad on-link prefix) to the given
/// interface, and bring it up. Uses raw ioctls (SIOCGIFINDEX + SIOCSIFADDR on
/// an AF_INET6 socket, then SIOCSIFFLAGS to bring the link up) so no external
/// `ip`/`ifconfig` binary is required. Requires CAP_NET_ADMIN / root.
pub fn assignAddress(gpa: std.mem.Allocator, ifname: []const u8, addr: node.Address, mtu: u16) !void {
    _ = gpa;
    const trunc_len = @min(ifname.len, 15);

    const sock6: usize = std.os.linux.socket(std.os.linux.AF.INET6, std.os.linux.SOCK.DGRAM, 0);
    if (@as(isize, @bitCast(sock6)) < 0) return error.SocketFailed;
    const fd6: i32 = @intCast(sock6);
    defer _ = std.os.linux.close(fd6);

    // Look up the interface index.
    var ifr: [40]u8 = [_]u8{0} ** 40;
    @memcpy(ifr[0..trunc_len], ifname[0..trunc_len]);
    const SIOCGIFINDEX: u64 = 0x8933;
    if (std.os.linux.ioctl(fd6, SIOCGIFINDEX, @intFromPtr(&ifr)) != 0) return error.IfIndexFailed;
    const ifindex = std.mem.readInt(i32, ifr[16..20], .native);

    // Assign the address with a /7 prefix (matches the reference
    // implementation's broad on-link visibility for the whole 0x02-0x03 range).
    var ifr6 = in6_ifreq{ .addr = addr.bytes, .prefixlen = 7, .ifindex = ifindex };
    const SIOCSIFADDR: u64 = 0x8916;
    if (std.os.linux.ioctl(fd6, SIOCSIFADDR, @intFromPtr(&ifr6)) != 0) return error.SetAddrFailed;

    // Set MTU and bring the link up via an AF_INET socket (IFF_* flags are
    // address-family agnostic, and SIOCSIFMTU only needs the ifreq name).
    const sock4: usize = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
    if (@as(isize, @bitCast(sock4)) >= 0) {
        const fd4: i32 = @intCast(sock4);
        defer _ = std.os.linux.close(fd4);

        var ifr_mtu: [40]u8 = [_]u8{0} ** 40;
        @memcpy(ifr_mtu[0..trunc_len], ifname[0..trunc_len]);
        std.mem.writeInt(i32, ifr_mtu[16..20], @as(i32, mtu), .native);
        const SIOCSIFMTU: u64 = 0x8922;
        _ = std.os.linux.ioctl(fd4, SIOCSIFMTU, @intFromPtr(&ifr_mtu));

        var ifr_flags: [40]u8 = [_]u8{0} ** 40;
        @memcpy(ifr_flags[0..trunc_len], ifname[0..trunc_len]);
        const SIOCGIFFLAGS: u64 = 0x8913;
        const SIOCSIFFLAGS: u64 = 0x8914;
        _ = std.os.linux.ioctl(fd4, SIOCGIFFLAGS, @intFromPtr(&ifr_flags));
        const IFF_UP: i16 = 0x1;
        const IFF_RUNNING: i16 = 0x40;
        var flags = std.mem.readInt(i16, ifr_flags[16..18], .native);
        flags |= IFF_UP | IFF_RUNNING;
        std.mem.writeInt(i16, ifr_flags[16..18], flags, .native);
        _ = std.os.linux.ioctl(fd4, SIOCSIFFLAGS, @intFromPtr(&ifr_flags));
    }
}

fn formatAddress(buf: []u8, bytes: *const [16]u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    for (0..8) |i| {
        if (i > 0) try w.writeAll(":");
        try w.print("{x}", .{std.mem.readInt(u16, bytes[i * 2 ..][0..2], .big)});
    }
    return w.buffered();
}



test "formatAddress produces colon-separated hex groups" {
    const bytes: [16]u8 = .{ 0x02, 0x01, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var buf: [64]u8 = undefined;
    const s = try formatAddress(&buf, &bytes);
    try std.testing.expectEqualStrings("201:abcd:0:0:0:0:0:1", s);
}
