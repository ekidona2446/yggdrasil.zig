//! Fallback TUN backend for platforms without a dedicated implementation
//! (e.g. WASI, other exotic targets). Compiles cleanly everywhere so the
//! rest of the daemon (mesh routing, peer links, session crypto) still
//! builds and runs -- only local TUN I/O is unavailable, exactly as if the
//! user had passed `--tun none`.

const std = @import("std");
const node = @import("node.zig");

pub const NativeTun = struct {
    name: [16:0]u8 = .{0} ** 16,
    enabled: bool = false,

    pub fn init(name: []const u8, mtu: u16) !NativeTun {
        _ = name;
        _ = mtu;
        return error.TunNotSupportedOnThisPlatform;
    }

    pub fn deinit(self: *NativeTun) void {
        _ = self;
    }

    pub fn read(self: *NativeTun, buf: []u8) !usize {
        _ = self;
        _ = buf;
        return error.TunDisabled;
    }

    pub fn write(self: *NativeTun, buf: []const u8) !usize {
        _ = self;
        _ = buf;
        return error.TunDisabled;
    }
};

pub fn assignAddress(ifname: []const u8, addr: node.Address, mtu: u16) !void {
    _ = ifname;
    _ = addr;
    _ = mtu;
    return error.TunNotSupportedOnThisPlatform;
}
