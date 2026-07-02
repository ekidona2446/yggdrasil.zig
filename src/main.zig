//! yggdrasil.zig node entrypoint.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const id = ironwood.Crypto.generate();
    const addr = node.addrForKey(&id.public_key);
    const subnet = node.subnetForKey(&id.public_key);

    std.debug.print("yggdrasil.zig {s}\n", .{"0.0.1-dev"});
    std.debug.print("  public_key: ", .{});
    printHex(&id.public_key);
    std.debug.print("\n  address:    ", .{});
    printAddrBytes(&addr.bytes);
    std.debug.print("\n  subnet:     ", .{});
    printSubnetBytes(&subnet.bytes);
    std.debug.print("/64\n", .{});

    const iw_cfg = ironwood.Config.default();
    var core = try node.Core.init(gpa, id, iw_cfg, "");
    defer core.deinit();

    std.debug.print("  status:     running (press Ctrl+C to stop)\n", .{});

    while (true) {
        try core.maintenance();
        // Sleep 5 seconds via Linux nanosleep
        var req = std.os.linux.timespec{ .sec = 5, .nsec = 0 };
        var rem: std.os.linux.timespec = undefined;
        _ = std.os.linux.nanosleep(&req, &rem);
    }
}

fn printHex(key: *const [32]u8) void {
    const chars = "0123456789abcdef";
    var buf: [64]u8 = undefined;
    for (key, 0..) |b, i| {
        buf[i * 2] = chars[(b >> 4) & 0xF];
        buf[i * 2 + 1] = chars[b & 0xF];
    }
    std.debug.print("{s}", .{&buf});
}

fn printSubnetBytes(bytes: *const [8]u8) void {
    for (0..4) |i| {
        if (i > 0) std.debug.print(":", .{});
        std.debug.print("{x:0>2}{x:0>2}", .{ bytes[i * 2], bytes[i * 2 + 1] });
    }
}

fn printAddrBytes(bytes: *const [16]u8) void {
    for (0..8) |i| {
        if (i > 0) std.debug.print(":", .{});
        std.debug.print("{x:0>2}{x:0>2}", .{ bytes[i * 2], bytes[i * 2 + 1] });
    }
}
