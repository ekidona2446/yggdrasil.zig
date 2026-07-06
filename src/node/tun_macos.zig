//! macOS TUN backend: uses the `utun` kernel control interface
//! (PF_SYSTEM/SYSPROTO_CONTROL socket connected to "com.apple.net.utun_control"),
//! the same mechanism used by wireguard-go, tailscale, and the reference
//! Yggdrasil Go implementation. No /dev/tun character devices or third-party
//! kernel extensions are involved -- utun has been a stock part of the
//! macOS/iOS kernel since OS X 10.7.
//!
//! Packets read from / written to a utun socket are prefixed with a 4-byte
//! big-endian address-family header (2 for AF_INET, 30 for AF_INET6) that
//! is not part of the IP packet itself; this backend strips/adds that header
//! so callers only ever see raw IPv6 packets, matching the Linux backend's
//! IFF_NO_PI framing.

const std = @import("std");
const node = @import("node.zig");

// ---------------------------------------------------------------------------
// PF_SYSTEM / kernel control socket constants
// (bsd/sys/sys_domain.h, bsd/sys/kern_control.h in XNU -- not present in
// Zig's minimal Darwin libc headers, so declared here from Apple's public,
// stable ABI documentation.)
// ---------------------------------------------------------------------------

const AF_SYSTEM: c_int = 32;
const PF_SYSTEM: c_int = AF_SYSTEM;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: c_int = 2;
const MAX_KCTL_NAME = 96;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";
const UTUN_OPT_IFNAME: c_int = 2;

/// See bsd/sys/kern_control.h: struct ctl_info.
const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [MAX_KCTL_NAME]u8,
};

/// See bsd/sys/kern_control.h: struct sockaddr_ctl.
const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

/// `_IOWR('N', 3, struct ctl_info)`, computed the same way <sys/ioccom.h>
/// does: `IOC_INOUT | (len << 16) | (group << 8) | num`.
const CTLIOCGINFO: c_ulong = ioc(IOC_INOUT, 'N', 3, @sizeOf(ctl_info));

const IOC_OUT: u32 = 0x40000000;
const IOC_IN: u32 = 0x80000000;
const IOC_INOUT: u32 = IOC_IN | IOC_OUT;

fn ioc(inout: u32, group: u8, num: u8, len: usize) c_ulong {
    return @as(c_ulong, inout) | (@as(c_ulong, @intCast(len & 0x1fff)) << 16) | (@as(c_ulong, group) << 8) | num;
}

extern "c" fn socket(domain: c_int, socktype: c_int, protocol: c_int) c_int;
extern "c" fn connect(sockfd: c_int, addr: *const anyopaque, addrlen: u32) c_int;
extern "c" fn getsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: ?*anyopaque, optlen: *u32) c_int;
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const SOCK_DGRAM: c_int = 2;

// ---------------------------------------------------------------------------
// NativeTun
// ---------------------------------------------------------------------------

pub const NativeTun = struct {
    fd: c_int,
    name: [16:0]u8,
    mtu: u16,
    enabled: bool,

    /// `name` is honored on a best-effort basis: utun interface names are
    /// always `utunN` and chosen by the kernel (or requested via
    /// `sc_unit = N + 1`). If `name` matches `utun<N>`, that specific unit
    /// is requested; otherwise ("auto" or an arbitrary name), unit 0 lets
    /// the kernel pick the first free `utunN`.
    pub fn init(name: []const u8, mtu: u16) !NativeTun {
        if (std.mem.eql(u8, name, "none")) return .{
            .fd = -1,
            .name = .{0} ** 16,
            .mtu = mtu,
            .enabled = false,
        };

        var requested_unit: u32 = 0; // 0 == kernel picks the first free unit
        if (std.mem.startsWith(u8, name, "utun")) {
            requested_unit = (std.fmt.parseInt(u32, name[4..], 10) catch 0) + 1;
        }

        const fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) return error.TunSetupFailed;
        errdefer _ = close(fd);

        var info = std.mem.zeroes(ctl_info);
        @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);
        if (ioctl(fd, CTLIOCGINFO, &info) != 0) return error.TunSetupFailed;

        var addr = std.mem.zeroes(sockaddr_ctl);
        addr.sc_len = @sizeOf(sockaddr_ctl);
        addr.sc_family = @intCast(AF_SYSTEM);
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = requested_unit;

        if (connect(fd, &addr, @sizeOf(sockaddr_ctl)) != 0) return error.TunSetupFailed;

        var name_buf: [16:0]u8 = .{0} ** 16;
        var name_len: u32 = name_buf.len;
        _ = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &name_buf, &name_len);

        var tun = NativeTun{
            .fd = fd,
            .name = name_buf,
            .mtu = mtu,
            .enabled = true,
        };
        // Best-effort MTU + up; failures here aren't fatal (assignAddress
        // will retry the same ioctls once the address is known).
        setMtuAndUp(std.mem.sliceTo(&tun.name, 0), mtu) catch {};
        return tun;
    }

    pub fn deinit(self: *NativeTun) void {
        if (self.enabled) {
            _ = close(self.fd);
            self.enabled = false;
        }
    }

    /// Reads one packet, stripping utun's 4-byte address-family header.
    pub fn read(self: *NativeTun, buf: []u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        var hdr_buf: [4]u8 = undefined;
        var iov = [_]Iovec{
            .{ .base = &hdr_buf, .len = hdr_buf.len },
            .{ .base = buf.ptr, .len = buf.len },
        };
        const n = readv(self.fd, &iov, iov.len);
        if (n < 0) return error.ReadFailed;
        const total: usize = @intCast(n);
        if (total <= hdr_buf.len) return 0;
        return total - hdr_buf.len;
    }

    /// Writes one packet, prefixing utun's 4-byte address-family header
    /// (inferred from the IP version nibble).
    pub fn write(self: *NativeTun, buf: []const u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        if (buf.len == 0) return 0;
        const version = buf[0] >> 4;
        const af: u32 = if (version == 6) 30 else 2; // AF_INET6 : AF_INET on Darwin
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, af, .big);
        var iov = [_]Iovec{
            .{ .base = &hdr, .len = hdr.len },
            .{ .base = @constCast(buf.ptr), .len = buf.len },
        };
        const n = writev(self.fd, &iov, iov.len);
        if (n < 0) return error.WriteFailed;
        const total: usize = @intCast(n);
        return if (total > hdr.len) total - hdr.len else 0;
    }

    /// The raw fd, usable with `xev.File.initFd` for async I/O (kqueue
    /// backends poll arbitrary fds/sockets, so this works the same way as
    /// on Linux).
    pub fn pollHandle(self: *const NativeTun) c_int {
        return self.fd;
    }
};

const Iovec = extern struct {
    base: [*]u8,
    len: usize,
};
extern "c" fn readv(fd: c_int, iov: [*]const Iovec, iovcnt: c_int) isize;
extern "c" fn writev(fd: c_int, iov: [*]const Iovec, iovcnt: c_int) isize;

// ---------------------------------------------------------------------------
// Address assignment via ioctls on an AF_INET6 socket (SIOCAIFADDR_IN6),
// mirroring what `ifconfig utunN inet6 <addr> prefixlen <n>` does.
// ---------------------------------------------------------------------------

const AF_INET: c_int = 2;
const AF_INET6: c_int = 30;
const IFNAMSIZ = 16;

const sockaddr_in6 = extern struct {
    sin6_len: u8 = @sizeOf(sockaddr_in6),
    sin6_family: u8 = @intCast(AF_INET6),
    sin6_port: u16 = 0,
    sin6_flowinfo: u32 = 0,
    sin6_addr: [16]u8 = [_]u8{0} ** 16,
    sin6_scope_id: u32 = 0,
};

/// See bsd/netinet6/in6_var.h: struct in6_addrlifetime.
const in6_addrlifetime = extern struct {
    ia6t_expire: i64 = 0,
    ia6t_preferred: i64 = 0,
    ia6t_vltime: u32 = ND6_INFINITE_LIFETIME,
    ia6t_pltime: u32 = ND6_INFINITE_LIFETIME,
};

const ND6_INFINITE_LIFETIME: u32 = 0xffffffff;

/// See bsd/netinet6/in6_var.h: struct in6_aliasreq. Fixed-width fields only
/// (no kernel/userland pointer-size ambiguity like the `_32`/`_64` kernel
/// variants -- those only matter for ioctls issued *from* the kernel).
const in6_aliasreq = extern struct {
    ifra_name: [IFNAMSIZ]u8 = [_]u8{0} ** IFNAMSIZ,
    ifra_addr: sockaddr_in6 = .{},
    ifra_dstaddr: sockaddr_in6 = .{},
    ifra_prefixmask: sockaddr_in6 = .{},
    ifra_flags: c_int = 0,
    ifra_lifetime: in6_addrlifetime = .{},
};

/// `_IOW('i', 26, struct in6_aliasreq)` (bsd/netinet6/in6_var.h). Despite the
/// name symmetry with other SIOC*_IN6 ioctls, this one is write-only from
/// the kernel's perspective (`_IOW`, i.e. `IOC_IN` only) -- verified against
/// XNU's public header and the well-known numeric value 0x8080691a.
const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, 'i', 26, @sizeOf(in6_aliasreq));

const ifreq = extern struct {
    ifr_name: [IFNAMSIZ]u8 = [_]u8{0} ** IFNAMSIZ,
    // Union of {sockaddr, short, int, ...}; sockaddr is 16 bytes on Darwin,
    // matching (and exceeding) every scalar field we actually use below.
    ifr_ifru: extern union {
        addr: [16]u8,
        flags: i16,
        mtu: i32,
    } = .{ .mtu = 0 },
};

const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, 'i', 16, @sizeOf(ifreq));
const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, 'i', 17, @sizeOf(ifreq));
const SIOCSIFMTU: c_ulong = ioc(IOC_IN, 'i', 52, @sizeOf(ifreq));
const IFF_UP: i16 = 0x1;
const IFF_RUNNING: i16 = 0x40;

fn setMtuAndUp(ifname: []const u8, mtu: u16) !void {
    const sock4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock4 < 0) return error.SocketFailed;
    defer _ = close(sock4);

    const trunc_len = @min(ifname.len, IFNAMSIZ - 1);

    var ifr_mtu = ifreq{};
    @memcpy(ifr_mtu.ifr_name[0..trunc_len], ifname[0..trunc_len]);
    ifr_mtu.ifr_ifru = .{ .mtu = mtu };
    _ = ioctl(sock4, SIOCSIFMTU, &ifr_mtu);

    var ifr_flags = ifreq{};
    @memcpy(ifr_flags.ifr_name[0..trunc_len], ifname[0..trunc_len]);
    _ = ioctl(sock4, SIOCGIFFLAGS, &ifr_flags);
    var flags = ifr_flags.ifr_ifru.flags;
    flags |= IFF_UP | IFF_RUNNING;
    ifr_flags.ifr_ifru = .{ .flags = flags };
    _ = ioctl(sock4, SIOCSIFFLAGS, &ifr_flags);
}

/// Assign the Yggdrasil IPv6 address (with /7 "network" visibility, matching
/// the reference implementation's use of a broad on-link prefix) to the given
/// utun interface, and bring it up. Requires root (kernel control sockets
/// and SIOCAIFADDR_IN6 both do).
pub fn assignAddress(ifname: []const u8, addr: node.Address, mtu: u16) !void {
    const trunc_len = @min(ifname.len, IFNAMSIZ - 1);

    const sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock6 < 0) return error.SocketFailed;
    defer _ = close(sock6);

    var req = in6_aliasreq{};
    @memcpy(req.ifra_name[0..trunc_len], ifname[0..trunc_len]);
    req.ifra_addr = .{ .sin6_addr = addr.bytes };
    // /7 prefix mask: first 7 bits set, rest zero.
    var mask_bytes: [16]u8 = [_]u8{0} ** 16;
    mask_bytes[0] = 0xfe; // 0b11111110 -> top 7 bits set
    req.ifra_prefixmask = .{ .sin6_addr = mask_bytes };
    req.ifra_lifetime = .{};

    if (ioctl(sock6, SIOCAIFADDR_IN6, &req) != 0) return error.SetAddrFailed;

    setMtuAndUp(ifname, mtu) catch {};
}
