//! Peer probe: Ironwood handshake + RTT measurement.
//! Usage: peer_probe <uri> [password]

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node");
const linux = std.os.linux;

const Metadata = node.version.Metadata;

// Raw sockaddr_in for IPv4
const sockaddr_in = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8 = [_]u8{0} ** 8,
};

fn parseIPv4(s: []const u8) !u32 {
    var parts: [4]u8 = undefined;
    var i: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (i >= 4) return error.InvalidIp;
        parts[i] = try std.fmt.parseInt(u8, part, 10);
        i += 1;
    }
    if (i != 4) return error.InvalidIp;
    return @as(u32, parts[0]) | (@as(u32, parts[1]) << 8) | (@as(u32, parts[2]) << 16) | (@as(u32, parts[3]) << 24);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const args = init.minimal.args;
    var args_iter = std.process.Args.Iterator.init(args);
    _ = args_iter.next();

    const uri = args_iter.next() orelse {
        std.debug.print("Usage: peer_probe <uri> [password]\n", .{});
        return;
    };
    const password = args_iter.next() orelse "";

    const parsed = node.links.parsePeerURI(uri) catch |e| {
        std.debug.print("FAIL|uri|{}\n", .{e});
        return;
    };

    const our_id = ironwood.Crypto.generate();

    // Parse IPv4 and build sockaddr_in
    const ip_be = parseIPv4(parsed.host) catch |e| {
        std.debug.print("FAIL|bad_ip|{}\n", .{e});
        return;
    };
    var sa: sockaddr_in = .{ .family = @intCast(linux.AF.INET), .port = std.mem.nativeToBig(u16, parsed.port), .addr = ip_be };

    // Socket
    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (fd < 0) {
        std.debug.print("FAIL|socket|{}\n", .{fd});
        return;
    }
    defer _ = linux.close(@intCast(fd));

    const t0 = getMicros();
    const connect_rc = linux.connect(@intCast(fd), @ptrCast(&sa), @sizeOf(sockaddr_in));
    if (connect_rc < 0) {
        std.debug.print("FAIL|connect|{}\n", .{connect_rc});
        return;
    }
    const t1 = getMicros();

    // Handshake
    const our_meta = Metadata.init(our_id.public_key, 0);
    const our_msg = our_meta.encode(&our_id, password, gpa) catch |e| {
        std.debug.print("FAIL|encode|{}\n", .{e});
        return;
    };
    defer gpa.free(our_msg);

    const wr = linux.write(@intCast(fd), our_msg.ptr, our_msg.len);
    if (wr < 0) { std.debug.print("FAIL|write|{}\n", .{wr}); return; }

    // Read header
    var header: [6]u8 = undefined;
    const hr = linux.read(@intCast(fd), &header, 6);
    if (hr < 0) { std.debug.print("FAIL|header|{}\n", .{hr}); return; }

    const body_len: u16 = std.mem.readInt(u16, header[4..6], .big);
    if (body_len > 8192) { std.debug.print("FAIL|body_too_big|{}\n", .{body_len}); return; }

    const body = gpa.alloc(u8, body_len) catch |e| { std.debug.print("FAIL|alloc|{}\n", .{e}); return; };
    defer gpa.free(body);

    var total_read: usize = 0;
    while (total_read < body_len) {
        const n = linux.read(@intCast(fd), body.ptr + total_read, body_len - total_read);
        if (n <= 0) break;
        total_read += @intCast(n);
    }

    const t2 = getMicros();
    const rtt_us = t2 - t0;
    const connect_us = t1 - t0;

    // Decode
    var full = std.ArrayListUnmanaged(u8).empty;
    full.appendSlice(gpa, &header) catch { std.debug.print("FAIL|oom\n", .{}); return; };
    full.appendSlice(gpa, body) catch { full.deinit(gpa); std.debug.print("FAIL|oom\n", .{}); return; };

    const peer_meta = Metadata.decode(full.items, password, gpa) catch |e| {
        full.deinit(gpa);
        std.debug.print("FAIL|decode|{}\n", .{e});
        return;
    };

    const key_hex = gpa.alloc(u8, 64) catch return;
    defer gpa.free(key_hex);
    const hx = "0123456789abcdef";
    for (peer_meta.public_key, 0..) |b, i| {
        key_hex[i * 2] = hx[(b >> 4) & 0xF];
        key_hex[i * 2 + 1] = hx[b & 0xF];
    }

    std.debug.print("OK|rtt_us={d}|connect_us={d}|key={s}|ver={}.{}\n", .{
        rtt_us, connect_us, key_hex, peer_meta.major_ver, peer_meta.minor_ver,
    });
}

fn getMicros() i128 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i128, ts.sec) * 1_000_000 + @divTrunc(@as(i128, ts.nsec), 1_000);
}
