//! Linux TUN backend: uses /dev/net/tun + TUNSETIFF, and raw AF_INET/AF_INET6
//! socket ioctls (SIOCSIFMTU/SIOCSIFFLAGS/SIOCSIFADDR) to configure the
//! resulting interface without shelling out to `ip`/`ifconfig`.

const std = @import("std");
const node = @import("node.zig");

pub const NativeTun = struct {
    fd: std.posix.fd_t,
    name: [16:0]u8,
    mtu: u16,
    enabled: bool,

    pub fn init(name: []const u8, mtu: u16) !NativeTun {
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

        var name_buf: [16:0]u8 = .{0} ** 16;
        @memcpy(name_buf[0..trunc_len], ifname[0..trunc_len]);

        return .{
            .fd = fd,
            .name = name_buf,
            .mtu = mtu,
            .enabled = true,
        };
    }

    pub fn deinit(self: *NativeTun) void {
        if (self.enabled) {
            _ = std.os.linux.close(self.fd);
            self.enabled = false;
        }
    }

    pub fn read(self: *NativeTun, buf: []u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        return try std.posix.read(self.fd, buf);
    }

    pub fn write(self: *NativeTun, buf: []const u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        const n = std.os.linux.write(self.fd, buf.ptr, buf.len);
        const signed: isize = @bitCast(n);
        if (signed < 0) return error.WriteFailed;
        return n;
    }

    /// The raw fd, usable with `xev.File.initFd` for async I/O.
    pub fn pollHandle(self: *const NativeTun) std.posix.fd_t {
        return self.fd;
    }
};

/// In6_ifreq, as used by SIOCSIFADDR/SIOCDIFADDR on an AF_INET6 socket.
/// See linux/ipv6.h.
const in6_ifreq = extern struct {
    addr: [16]u8,
    prefixlen: u32,
    ifindex: i32,
};

/// Assign an arbitrary IPv4/IPv6 address in CIDR notation (e.g. "10.99.0.1/24"
/// or "2005:8a:9:11::3/64") to the interface, via raw ioctls. Used for CKR
/// tunnel addresses. Requires CAP_NET_ADMIN / root.
pub fn assignCidrAddress(ifname: []const u8, cidr: []const u8) !void {
    const trunc_len = @min(ifname.len, 15);

    // Parse "addr/prefix" (prefix optional; /32 and /128 defaults).
    var addr_text = cidr;
    var prefix: u32 = 0;
    var has_prefix = false;
    if (std.mem.indexOfScalar(u8, cidr, '/')) |slash| {
        addr_text = cidr[0..slash];
        prefix = std.fmt.parseInt(u32, cidr[slash + 1 ..], 10) catch return error.BadCidr;
        has_prefix = true;
    }

    if (std.mem.indexOfScalar(u8, addr_text, ':') != null) {
        const ip6 = std.Io.net.Ip6Address.parse(addr_text, 0) catch return error.BadCidr;
        if (!has_prefix) prefix = 128;
        if (prefix > 128) return error.BadCidr;

        const sock6: usize = std.os.linux.socket(std.os.linux.AF.INET6, std.os.linux.SOCK.DGRAM, 0);
        if (@as(isize, @bitCast(sock6)) < 0) return error.SocketFailed;
        const fd6: i32 = @intCast(sock6);
        defer _ = std.os.linux.close(fd6);

        var ifr: [40]u8 = [_]u8{0} ** 40;
        @memcpy(ifr[0..trunc_len], ifname[0..trunc_len]);
        const SIOCGIFINDEX: u64 = 0x8933;
        if (std.os.linux.ioctl(fd6, SIOCGIFINDEX, @intFromPtr(&ifr)) != 0) return error.IfIndexFailed;
        const ifindex = std.mem.readInt(i32, ifr[16..20], .native);

        var ifr6 = in6_ifreq{ .addr = ip6.bytes, .prefixlen = prefix, .ifindex = ifindex };
        const SIOCSIFADDR: u64 = 0x8916;
        if (std.os.linux.ioctl(fd6, SIOCSIFADDR, @intFromPtr(&ifr6)) != 0) return error.SetAddrFailed;
        return;
    }

    const ip4 = std.Io.net.Ip4Address.parse(addr_text, 0) catch return error.BadCidr;
    if (!has_prefix) prefix = 32;
    if (prefix > 32) return error.BadCidr;

    const sock4: usize = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
    if (@as(isize, @bitCast(sock4)) < 0) return error.SocketFailed;
    const fd4: i32 = @intCast(sock4);
    defer _ = std.os.linux.close(fd4);

    var ifr: [40]u8 = [_]u8{0} ** 40;
    @memcpy(ifr[0..trunc_len], ifname[0..trunc_len]);
    // `ifr_addr` is a `sockaddr_in`: family (u16), port (u16), addr (u32 BE).
    std.mem.writeInt(u16, ifr[16..18], @intCast(std.os.linux.AF.INET), .native);
    std.mem.writeInt(u16, ifr[18..20], 0, .native);
    @memcpy(ifr[20..24], &ip4.bytes);
    const SIOCSIFADDR: u64 = 0x8916;
    if (std.os.linux.ioctl(fd4, SIOCSIFADDR, @intFromPtr(&ifr)) != 0) return error.SetAddrFailed;

    // Set the netmask so the address carries the requested /prefix length.
    const mask: u32 = if (prefix == 0) 0 else ~((@as(u32, 1) << @intCast(32 - prefix)) - 1);
    var ifr_mask: [40]u8 = [_]u8{0} ** 40;
    @memcpy(ifr_mask[0..trunc_len], ifname[0..trunc_len]);
    std.mem.writeInt(u16, ifr_mask[16..18], @intCast(std.os.linux.AF.INET), .native);
    std.mem.writeInt(u16, ifr_mask[18..20], 0, .native);
    std.mem.writeInt(u32, ifr_mask[20..24], mask, .big);
    const SIOCSIFNETMASK: u64 = 0x891c;
    _ = std.os.linux.ioctl(fd4, SIOCSIFNETMASK, @intFromPtr(&ifr_mask));
}

/// Assign the Yggdrasil IPv6 address (with /7 "network" visibility, matching
/// the reference implementation's use of a broad on-link prefix) to the given
/// interface, and bring it up. Uses raw ioctls (SIOCGIFINDEX + SIOCSIFADDR on
/// an AF_INET6 socket, then SIOCSIFFLAGS to bring the link up) so no external
/// `ip`/`ifconfig` binary is required. Requires CAP_NET_ADMIN / root.
pub fn assignAddress(ifname: []const u8, addr: node.Address, mtu: u16) !void {
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
