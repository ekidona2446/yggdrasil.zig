//! Portable non-blocking datagram I/O for the QUIC transport.
//!
//! Zig 0.16 removed `std.posix.recvfrom`, `std.posix.recv` and `std.posix.MSG`
//! from the standard library, so a UDP receive has to be declared by hand. The
//! previous QUIC code called `std.posix.system.recvfrom` together with
//! `std.posix.MSG.DONTWAIT`, which is a Linux-ism twice over:
//!
//!   `MSG_DONTWAIT` does not exist on Windows at all, and
//!   `std.posix.system` is the raw OS namespace, so the call did not even
//!     type-check on 0.16.
//!
//! This module instead puts the socket into non-blocking mode once (a POSIX
//! `fcntl(F_SETFL, O_NONBLOCK)` or a Windows `ioctlsocket(FIONBIO)`) and then
//! receives with `flags = 0`. That is the portable formulation of "drain
//! whatever datagrams are already queued and return immediately".
//!
//! The node always links libc — wolfSSL and libwebsockets are C libraries that
//! force it on every target — so binding `recvfrom(3)` / `ioctlsocket(2)`
//! directly from libc / Winsock is safe and needs no OS-specific syscalls.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{
    /// No datagram is queued right now. This is the normal outcome of a drain
    /// loop and must not be treated as a link failure.
    WouldBlock,
    /// The socket was rejected by the kernel. Treat as a link failure.
    Failed,
    /// The peer sent ICMP port-unreachable for a previous datagram. On POSIX
    /// this surfaces as ECONNRESET on a connected-less UDP socket.
    ConnectionReset,
};

pub const RecvResult = struct {
    /// Number of bytes written into the caller's buffer.
    n: usize,
    /// Source address as reported by the kernel, in host `sockaddr` layout.
    addr: std.posix.sockaddr,
    /// Length of the meaningful prefix of `addr`.
    addr_len: std.posix.socklen_t,
};

// ---------------------------------------------------------------------------
// Platform bindings
// ---------------------------------------------------------------------------

const is_windows = builtin.os.tag == .windows;

/// POSIX: `ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *,
/// socklen_t *)`. Windows: `int recvfrom(SOCKET, char *, int, int,
/// struct sockaddr *, int *)`.
const recvfrom_fn = if (is_windows) struct {
    extern "c" fn recvfrom(
        s: std.posix.socket_t,
        buf: [*]u8,
        len: c_int,
        flags: c_int,
        from: ?*std.posix.sockaddr,
        fromlen: ?*c_int,
    ) callconv(.c) c_int;
}.recvfrom else struct {
    extern "c" fn recvfrom(
        fd: c_int,
        buf: [*]u8,
        len: usize,
        flags: c_int,
        addr: ?*std.posix.sockaddr,
        addrlen: ?*std.posix.socklen_t,
    ) callconv(.c) isize;
}.recvfrom;

/// Windows only. `FIONBIO` is the same constant in every WinSDK release.
const FIONBIO: c_long = @bitCast(@as(u32, 0x8004667e));
const ioctlsocket_fn = struct {
    extern "c" fn ioctlsocket(s: std.posix.socket_t, cmd: c_long, argp: ?*u32) callconv(.c) c_int;
}.ioctlsocket;

/// POSIX only. `fcntl(3)` is variadic in every libc we target; declaring it
/// variadic here keeps the call ABI-correct on all of them.
const fcntl_fn = struct {
    extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) callconv(.c) c_int;
}.fcntl;

const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;

/// Last OS error code. On POSIX this is `errno`, taken through `std.c._errno`
/// (which already picks `__errno_location` / `__error` / `___errno` per target).
/// On Windows, socket errors are reported by `WSAGetLastError`, not `errno`,
/// and `std.c.E`'s Windows variant is exactly the WSA error numbering, so both
/// sides compare against `std.c.E`.
fn lastErrno() std.c.E {
    if (comptime is_windows) {
        const wsagetlasterror = struct {
            extern "c" fn WSAGetLastError() callconv(.c) c_int;
        }.WSAGetLastError;
        return @enumFromInt(wsagetlasterror());
    }
    return @enumFromInt(std.c._errno().*);
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Put `sock` into non-blocking mode. Must be called once per socket before
/// the first [`recvFrom`].
pub fn setNonblocking(sock: std.posix.socket_t) Error!void {
    if (comptime is_windows) {
        var on: u32 = 1;
        if (ioctlsocket_fn(sock, FIONBIO, &on) != 0) return error.Failed;
        return;
    }
    const flags = fcntl_fn(@intCast(sock), F_GETFL);
    if (flags < 0) return error.Failed;
    // O_NONBLOCK's numeric value differs per kernel (0o4000 on Linux, 0x0004 on
    // Darwin and the BSDs). `std.posix.O` is a packed bitfield that std fills
    // in per target, so take the bit from there rather than spelling out a
    // constant for each OS.
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (fcntl_fn(@intCast(sock), F_SETFL, flags | nonblock) < 0) return error.Failed;
}

/// Receive one datagram without blocking. Returns `error.WouldBlock` when the
/// socket's queue is empty, which is the expected end condition of a drain
/// loop.
pub fn recvFrom(sock: std.posix.socket_t, buf: []u8) Error!RecvResult {
    var addr: std.posix.sockaddr = undefined;
    while (true) {
        var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const rc: isize = if (comptime is_windows) blk: {
            var wlen: c_int = @intCast(addrlen);
            const r = recvfrom_fn(sock, buf.ptr, @intCast(buf.len), 0, &addr, &wlen);
            addrlen = @intCast(wlen);
            break :blk r;
        } else recvfrom_fn(@intCast(sock), buf.ptr, buf.len, 0, &addr, &addrlen);

        if (rc >= 0) return .{ .n = @intCast(rc), .addr = addr, .addr_len = addrlen };

        switch (lastErrno()) {
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionReset,
            else => return error.Failed,
        }
    }
}

const testing = std.testing;

test "udp_io: non-blocking drain returns WouldBlock on an empty socket" {
    // Exercises the real code path: create a datagram socket, flip it to
    // non-blocking, and confirm a receive on an empty queue reports
    // WouldBlock rather than stalling the event loop.
    const sock = std.posix.system.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    if (sock < 0) return error.SkipZigTest;
    defer _ = std.posix.system.close(sock);

    try setNonblocking(@intCast(sock));

    var buf: [64]u8 = undefined;
    const result = recvFrom(@intCast(sock), &buf);
    try testing.expectError(error.WouldBlock, result);
}

test "udp_io: loopback datagram round trip" {
    // Sends to ourselves and confirms recvFrom surfaces both the payload and
    // the source address, which is what the QUIC listener needs to key its
    // connection table on.
    const sock = std.posix.system.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    if (sock < 0) return error.SkipZigTest;
    defer _ = std.posix.system.close(sock);

    var sa = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0, // ephemeral
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [_]u8{0} ** 8,
    };
    if (std.posix.system.bind(@intCast(sock), @ptrCast(&sa), @sizeOf(std.posix.sockaddr.in)) != 0) {
        return error.SkipZigTest;
    }
    var bound: std.posix.sockaddr.in = undefined;
    var blen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    if (std.posix.system.getsockname(@intCast(sock), @ptrCast(&bound), &blen) != 0) {
        return error.SkipZigTest;
    }
    try setNonblocking(@intCast(sock));

    const payload = "yggdrasil";
    const sent = std.posix.system.sendto(
        @intCast(sock),
        payload.ptr,
        payload.len,
        0,
        @ptrCast(&bound),
        @sizeOf(std.posix.sockaddr.in),
    );
    try testing.expectEqual(@as(isize, payload.len), sent);

    var buf: [64]u8 = undefined;
    const got = try recvFrom(@intCast(sock), &buf);
    try testing.expectEqualSlices(u8, payload, buf[0..got.n]);
    try testing.expectEqual(@as(u16, std.posix.AF.INET), got.addr.family);
}
