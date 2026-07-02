//! TUN adapter — creates and manages a TUN network interface.
//!
//! Platform-specific: uses /dev/net/tun on Linux.

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

        // Open /dev/net/tun
        const fd = try std.posix.openat(
            std.posix.AT.FDCWD,
            "/dev/net/tun",
            .{ .ACCMODE = .RDWR },
            0,
        );
        errdefer std.posix.close(fd);

        // Configure TUN interface
        var ifr: [40]u8 = [_]u8{0} ** 40;
        @memcpy(ifr[0..std.math.min(ifname.len, 15)], ifname); // truncated to 15
        ifr[16] = 0; // name
        // IFF_TUN | IFF_NO_PI
        std.mem.writeInt(i16, ifr[16..18], 1 | 0x1000, .native);

        const TUNSETIFF: u64 = 0x400454CA;
        const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        if (rc < 0) {
            std.posix.close(fd);
            return error.TunSetupFailed;
        }

        // Set MTU
        const SIOCSIFMTU: u64 = 0x8922;
        var ifr_mtu: [40]u8 = [_]u8{0} ** 40;
        @memcpy(ifr_mtu[0..std.math.min(ifname.len, 15)], ifname);
        std.mem.writeInt(i32, ifr_mtu[16..20], @as(i32, mtu), .native);
        _ = std.os.linux.ioctl(fd, SIOCSIFMTU, @intFromPtr(&ifr_mtu));

        _ = addr_str; // Full address assignment deferred

        return .{
            .fd = fd,
            .name = ifname[0..std.math.min(ifname.len, 15)].* ++ .{0} ** (16 - @min(ifname.len, 15)),
            .mtu = mtu,
            .enabled = true,
        };
    }

    pub fn deinit(self: *TunAdapter) void {
        if (self.enabled) {
            std.posix.close(self.fd);
            self.enabled = false;
        }
    }

    pub fn read(self: *TunAdapter, buf: []u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        return try std.posix.read(self.fd, buf);
    }

    pub fn write(self: *TunAdapter, buf: []const u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        return try std.posix.write(self.fd, buf);
    }
};
