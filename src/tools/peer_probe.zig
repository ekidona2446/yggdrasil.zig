//! Peer probe: Ironwood handshake + RTT measurement.
//! Usage: peer_probe <uri> [password]

const std = @import("std");
const builtin = @import("builtin");
const ironwood = @import("ironwood");
const node = @import("node");
const c = std.c;
const timemod = @import("util").time;
const is_windows = builtin.os.tag == .windows;

const Metadata = node.version.Metadata;

// Raw sockaddr_in for IPv4 -- identical layout on every target this probes
// (2-byte family  2-byte port  4-byte addr  8 bytes of padding), so no
// platform branch is needed for the struct itself, only for socket I/O.
const sockaddr_in = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8 = [_]u8{0} ** 8,
};

// ---------------------------------------------------------------------------
// Winsock2 fallbacks: `std.c.close` calls the CRT's file-handle `close`,
// which is *not* valid on a Winsock `SOCKET` (must use `closesocket`); values
// for AF/SOCK also differ from `std.c`'s POSIX-oriented definitions there.
// ---------------------------------------------------------------------------

const win = struct {
    const ws2_32 = std.os.windows.ws2_32;
    const SOCKET = usize;
    const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);
    extern "ws2_32" fn socket(af: c_int, socktype: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    extern "ws2_32" fn connect(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn send(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
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
    var args_iter = try std.process.Args.Iterator.initAllocator(args, gpa);
	defer args_iter.deinit();
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
    const family: u16 = if (is_windows) win.ws2_32.AF.INET else @intCast(c.AF.INET);
	var sa: sockaddr_in = .{ .family = family, .port = std.mem.nativeToBig(u16, parsed.port), .addr = ip_be };

	const t0 = timemod.monotonicNanos();

	if (is_windows) {
		const sock = win.socket(win.ws2_32.AF.INET, win.ws2_32.SOCK.STREAM, 0);
		if (sock == win.INVALID_SOCKET) {
			std.debug.print("FAIL|socket\n", .{});
			return;
		}
		defer _ = win.closesocket(sock);

		if (win.connect(sock, @ptrCast(&sa), @sizeOf(sockaddr_in)) != 0) {
			std.debug.print("FAIL|connect\n", .{});
			return;
		}
		const t1 = timemod.monotonicNanos();

		const our_meta = Metadata.init(our_id.public_key, 0);
        const our_msg = our_meta.encode(&our_id, password, gpa) catch |e| {
            std.debug.print("FAIL|encode|{}\n", .{e});
            return;
        };
        defer gpa.free(our_msg);

        if (win.send(sock, our_msg.ptr, @intCast(our_msg.len), 0) < 0) {
            std.debug.print("FAIL|write\n", .{});
            return;
        }

        var header: [6]u8 = undefined;
        if (win.recv(sock, &header, 6, 0) < 0) {
            std.debug.print("FAIL|header\n", .{});
            return;
        }

        const body_len: u16 = std.mem.readInt(u16, header[4..6], .big);
        if (body_len > 8192) {
            std.debug.print("FAIL|body_too_big|{}\n", .{body_len});
            return;
        }

        const body = gpa.alloc(u8, body_len) catch |e| {
            std.debug.print("FAIL|alloc|{}\n", .{e});
            return;
        };
        defer gpa.free(body);

        var total_read: usize = 0;
        while (total_read < body_len) {
            const n = win.recv(sock, body.ptr  total_read, @intCast(body_len - total_read), 0);
            if (n <= 0) break;
            total_read = @intCast(n);
        }

        const t2 = timemod.monotonicNanos();
        try report(gpa, &header, body, password, t0, t1, t2);
        return;
    }

    // Socket
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0);
    if (fd < 0) {
        std.debug.print("FAIL|socket|{}\n", .{fd});
        return;
    }
    defer _ = c.close(fd);

    const connect_rc = c.connect(fd, @ptrCast(&sa), @sizeOf(sockaddr_in));
    if (connect_rc < 0) {
        std.debug.print("FAIL|connect|{}\n", .{connect_rc});
        return;
    }
    const t1 = timemod.monotonicNanos();

    // Handshake
    const our_meta = Metadata.init(our_id.public_key, 0);
    const our_msg = our_meta.encode(&our_id, password, gpa) catch |e| {
        std.debug.print("FAIL|encode|{}\n", .{e});
        return;
    };
    defer gpa.free(our_msg);

    const wr = c.write(fd, our_msg.ptr, our_msg.len);
    if (wr < 0) {
        std.debug.print("FAIL|write|{}\n", .{wr});
        return;
    }

    // Read header
    var header: [6]u8 = undefined;
    const hr = c.read(fd, &header, 6);
    if (hr < 0) {
        std.debug.print("FAIL|header|{}\n", .{hr});
        return;
    }

    const body_len: u16 = std.mem.readInt(u16, header[4..6], .big);
    if (body_len > 8192) { std.debug.print("FAIL|body_too_big|{}\n", .{body_len}); return; }

    const body = gpa.alloc(u8, body_len) catch |e| { std.debug.print("FAIL|alloc|{}\n", .{e}); return; };
    defer gpa.free(body);

    var total_read: usize = 0;
    while (total_read < body_len) {
        const n = c.read(fd, body.ptr + total_read, body_len - total_read);
        if (n <= 0) break;
        total_read += @intCast(n);
    }

    const t2 = timemod.monotonicNanos();
    try report(gpa, &header, body, password, t0, t1, t2);
}

fn report(gpa: std.mem.Allocator, header: *const [6]u8, body: []const u8, password: []const u8, t0: u64, t1: u64, t2: u64) !void {
    const rtt_us = (t2 - t0) / 1000;
    const connect_us = (t1 - t0) / 1000;
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
