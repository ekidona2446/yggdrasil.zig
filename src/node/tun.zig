//! TUN adapter -- creates and manages a TUN network interface.
//!
//! Platform-specific: uses /dev/net/tun on Linux. Provides both a blocking
//! read/write API (used by `initFd`-wrapping code) and helpers to drive the
//! fd through libxev's `xev.File` watcher for async I/O in the main loop.
//! Dispatches to a platform-specific backend:
//! Dispatches to a platform-specific backend:
//!   - Linux:   `/dev/net/tun`  ioctls (tun_linux.zig)
//!   - macOS:   the `utun` kernel control interface (tun_macos.zig)
//!   - Windows: the Wintun driver, loaded dynamically (tun_windows.zig)
//!
//! All backends expose the same `read`/`write`/`deinit` surface used by
//! `main.zig`, plus a platform-appropriate way to assign the Yggdrasil IPv6
//! address to the resulting interface.

const std = @import("std");
const builtin = @import("builtin");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const backend = switch (builtin.os.tag) {
    .linux => @import("tun_linux.zig"),
    .macos, .ios, .tvos, .watchos, .visionos => @import("tun_macos.zig"),
    .windows => @import("tun_windows.zig"),
    else => @import("tun_unsupported.zig"),
};

/// Windows-only: the bounded packet queue used to hand off packets from
/// Wintun's background reader thread to the main event loop (see
/// `tun_windows.zig` and `main.zig`'s `TunIoWindows`). Aliased through here
/// so `main.zig` doesn't need to import the platform backend directly.
pub const WindowsRecvQueue = if (builtin.os.tag == .windows) backend.RecvQueue else struct {
    gpa: std.mem.Allocator = undefined,
};

pub const TunAdapter = struct {
    native: backend.NativeTun,
    mtu: u16,
    enabled: bool,

    pub fn init(name: []const u8, addr_str: []const u8, mtu: u16) !TunAdapter {
        _ = addr_str; // IPv6 address assignment happens in `assignAddress`.
        const native = try backend.NativeTun.init(name, mtu);
        return .{ .native = native, .mtu = mtu, .enabled = native.enabled };
    }

    pub fn deinit(self: *TunAdapter) void {
        self.native.deinit();
        self.enabled = false;
    }

    pub fn read(self: *TunAdapter, buf: []u8) !usize {
        return self.native.read(buf);
    }

    pub fn write(self: *TunAdapter, buf: []const u8) !usize {
        return self.native.write(buf);
    }
    /// Interface name, as a NUL-terminated buffer (matches whatever the
    /// backend actually created -- e.g. the kernel may assign a different
    /// `utunN`/`wintun` name than requested).
    pub fn interfaceName(self: *const TunAdapter) [16:0]u8 {
        return self.native.name;
    }
};

/// Assign the Yggdrasil IPv6 address (with /7 on-link visibility, matching
/// the reference implementation) to the given interface, and bring it up.
/// Platform-specific privilege requirements apply (root/CAP_NET_ADMIN on
/// Unix, Administrator on Windows).
pub fn assignAddress(gpa: std.mem.Allocator, ifname: []const u8, addr: node.Address, mtu: u16) !void {
    _ = gpa;
    switch (builtin.os.tag) {
        .windows => @compileError("call node.tun.assignAddressForAdapter on Windows instead (needs the NativeTun for its LUID)"),
        else => return backend.assignAddress(ifname, addr, mtu),
    }
}

/// Windows variant: Wintun addresses are assigned by NET_LUID (obtained
/// from the adapter handle), not by interface name, so this takes the
/// `TunAdapter` itself rather than a name string.
pub fn assignAddressForAdapter(adapter: *TunAdapter, addr: node.Address, mtu: u16) !void {
    switch (builtin.os.tag) {
        .windows => return backend.assignAddress(&adapter.native, addr, mtu),
        else => return backend.assignAddress(std.mem.sliceTo(&adapter.native.name, 0), addr, mtu),
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
