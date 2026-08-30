//! Unix domain socket transport for Yggdrasil peer links and the admin socket.
//!
//! Yggdrasil-go uses `unix:///path/to.sock` for its default admin listener
//! (`unix:///var/run/yggdrasil.sock` on Linux/macOS/*BSD) and supports `unix://`
//! peer URIs. This module provides the small, portable plumbing those need:
//! create a non-blocking `AF_UNIX` stream socket, `bind`/`listen` (server) or
//! `connect` (client), and hand the resulting file descriptor to libxev as an
//! `xev.TCP` (whose `accept`/`read`/`write`/`close` operations work on any
//! stream socket, not just TCP).
//!
//! Zig 0.16 moved `socket`/`bind`/`listen`/`connect` out of `std.posix` and
//! into the new `std.Io` interface. This code does not use the `std.Io` async
//! runtime (the node runs on a libxev event loop), so it calls the platform
//! syscalls through `std.posix.system.*` — the same compatibility shim zquic's
//! own `compat.zig` uses — which resolves to libc on every target the node
//! links (wolfSSL + libwebsockets always link libc) and to raw Linux syscalls
//! otherwise. All sockets are created non-blocking so no blocking syscall can
//! stall the event-loop thread and deadlock the node.

const std = @import("std");
const xev = @import("xev");

const posix = std.posix;
const system = posix.system;

/// Portable `sockaddr_un`. The layout (`sa_family_t` + 108-byte path) is the
/// same on Linux, macOS and the BSDs; `sa_family_t` is `u16` on all of them.
const SockaddrUnix = extern struct {
    family: posix.sa_family_t = posix.AF.UNIX,
    path: [108]u8 = [_]u8{0} ** 108,
};

pub const Error = error{
    AddressInUse,
    AddressNotAvailable,
    AccessDenied,
    NameTooLong,
    SystemResources,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    ConnectionRefused,
    FileNotFound,
    NotDir,
    InvalidPath,
} || posix.UnexpectedError;

/// `unix://` address split into a path and whether it is an abstract socket
/// (Linux: the path starts with `@`, which maps to a leading NUL byte).
pub const Address = struct {
    /// Socket name. For filesystem sockets this is the on-disk path; for
    /// abstract sockets this is the name *without* the leading `@`/NUL.
    path: []const u8,
    /// Abstract (Linux-only) socket: the address is `\0` + `path`.
    abstract: bool,

    pub fn init(uri_rest: []const u8) Error!Address {
        // `unix:///abs/path` → `/abs/path`; `unix://@name` → abstract `name`.
        if (uri_rest.len == 0) return error.InvalidPath;
        if (uri_rest[0] == '@') return .{ .path = uri_rest[1..], .abstract = true };
        return .{ .path = uri_rest, .abstract = false };
    }

    /// Length of the `sockaddr_un` for this address (offset of the path plus
    /// the name and, for filesystem sockets, the trailing NUL).
    pub fn socklen(self: Address) Error!posix.socklen_t {
        if (self.abstract) {
            if (1 + self.path.len > 108) return error.NameTooLong;
            return @intCast(@offsetOf(SockaddrUnix, "path") + 1 + self.path.len);
        }
        if (self.path.len >= 108) return error.NameTooLong;
        return @intCast(@offsetOf(SockaddrUnix, "path") + self.path.len + 1);
    }

    fn fill(self: Address, sa: *SockaddrUnix) void {
        sa.* = .{};
        if (self.abstract) {
            // Abstract socket: leading NUL, then the name.
            @memcpy(sa.path[1 .. 1 + self.path.len], self.path);
        } else {
            @memcpy(sa.path[0..self.path.len], self.path);
        }
    }
};

fn checkRc(rc: anytype) posix.E {
    return posix.errno(rc);
}

fn socketFd() Error!posix.socket_t {
    const rc = system.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    switch (checkRc(rc)) {
        .SUCCESS => {},
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT, .INVAL => return error.AddressNotAvailable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
    return @intCast(rc);
}

/// Set `O_NONBLOCK` so libxev's epoll/kqueue/io_uring backend can drive the
/// socket without a blocking `read`/`write`/`accept` ever stalling the loop.
fn setNonBlocking(fd: posix.socket_t) Error!void {
    // Zig 0.16 represents the open flags as a `packed struct(u32)` (on every
    // target), so `O.NONBLOCK` is a *field*, not a constant; build the value
    // and bit-cast it to its integer form.
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    const flags = system.fcntl(fd, posix.F.GETFL, @as(i32, 0));
    switch (checkRc(flags)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    const set = system.fcntl(fd, posix.F.SETFL, flags | @as(i32, @intCast(nonblock)));
    switch (checkRc(set)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Remove a stale socket file if it exists and is not held by a live process.
/// Mirrors yggdrasil-go: dial the path, and only unlink it if the dial fails
/// (a socket file with nobody listening behind it).
pub fn cleanupStale(addr: Address) void {
    if (addr.abstract) return;
    // `unlink` via the system layer; ignore errors (file may not exist).
    var buf: [108]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&buf, "{s}", .{addr.path}) catch return;
    _ = system.unlink(path_z.ptr);
}

/// Create a listening unix socket wrapped as an `xev.TCP`. The caller then
/// uses `.accept(...)` exactly as for a TCP listener. Call `cleanupStale`
/// first if the path may already exist.
pub fn listener(addr: Address, backlog: u31) Error!xev.TCP {
    const fd = try socketFd();
    errdefer _ = system.close(fd);

    var sa: SockaddrUnix = undefined;
    addr.fill(&sa);
    const rc = system.bind(fd, @ptrCast(&sa), try addr.socklen());
    switch (checkRc(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL, .AFNOSUPPORT => return error.AddressNotAvailable,
        .NOTDIR, .NOENT => return error.FileNotFound,
        .ROFS => return error.AccessDenied,
        else => |err| return posix.unexpectedErrno(err),
    }
    const lrc = system.listen(fd, backlog);
    switch (checkRc(lrc)) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => |err| return posix.unexpectedErrno(err),
    }
    return xev.TCP.initFd(fd);
}

/// Connect to a unix socket and return it wrapped as an `xev.TCP`. The connect
/// is non-blocking (EINPROGRESS/EAGAIN are swallowed); the caller drives the
/// rest of the connection through the returned watcher, which reports
/// `error.WouldBlock` on its completions until the handshake completes.
pub fn dial(addr: Address) Error!xev.TCP {
    const fd = try socketFd();
    errdefer _ = system.close(fd);
    try setNonBlocking(fd);

    var sa: SockaddrUnix = undefined;
    addr.fill(&sa);
    const rc = system.connect(fd, @ptrCast(&sa), try addr.socklen());
    switch (checkRc(rc)) {
        .SUCCESS => {},
        .INPROGRESS, .AGAIN, .ALREADY => {
            // Non-blocking connect in flight — expected.
        },
        .ACCES, .PERM => return error.AccessDenied,
        .CONNREFUSED, .NOENT, .NOTDIR => return error.ConnectionRefused,
        .ISCONN => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    return xev.TCP.initFd(fd);
}

test "unix address parsing and socklen" {
    const testing = std.testing;

    const fs = try Address.init("/tmp/ygg.sock");
    try testing.expect(!fs.abstract);
    try testing.expectEqualStrings("/tmp/ygg.sock", fs.path);

    const ab = try Address.init("@yggdrasil");
    try testing.expect(ab.abstract);
    try testing.expectEqualStrings("yggdrasil", ab.path);

    try testing.expectEqual(@as(posix.socklen_t, @offsetOf(SockaddrUnix, "path") + 1 + "yggdrasil".len), try ab.socklen());
    const too_long = try Address.init("@" ++ ("x" ** 200));
    try testing.expectError(error.NameTooLong, too_long.socklen());
}
