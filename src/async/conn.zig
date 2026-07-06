//! `AsyncConn`: a type-erased async bidirectional byte stream.
//!
//! The interface is a manual vtable (fat pointer): `ptr` is the concrete
//! implementation and `vtable` holds the function pointers. Each operation
//! takes a caller-owned `*xev.Completion` (one per in-flight op) plus an opaque
//! `userdata` pointer threaded back into the callback.

const std = @import("std");
const xev = @import("xev");

pub const ReadError = xev.ReadError;
pub const WriteError = xev.WriteError;
pub const CloseError = xev.CloseError;

/// Callback invoked when a read completes. `n` is the result (bytes read or an
/// error; 0 / error.EOF style depends on the backend's ReadError set).
pub const ReadCallback = *const fn (userdata: ?*anyopaque, result: ReadError!usize) void;
/// Callback invoked when a write completes.
pub const WriteCallback = *const fn (userdata: ?*anyopaque, result: WriteError!usize) void;
/// Callback invoked when a close completes.
pub const CloseCallback = *const fn (userdata: ?*anyopaque, result: CloseError!void) void;

pub const VTable = struct {
    read: *const fn (
        ptr: *anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        buf: []u8,
        userdata: ?*anyopaque,
        cb: ReadCallback,
    ) void,
    write: *const fn (
        ptr: *anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        buf: []const u8,
        userdata: ?*anyopaque,
        cb: WriteCallback,
    ) void,
    close: *const fn (
        ptr: *anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        userdata: ?*anyopaque,
        cb: CloseCallback,
    ) void,
};

pub const AsyncConn = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn read(
        self: AsyncConn,
        loop: *xev.Loop,
        c: *xev.Completion,
        buf: []u8,
        userdata: ?*anyopaque,
        cb: ReadCallback,
    ) void {
        self.vtable.read(self.ptr, loop, c, buf, userdata, cb);
    }

    pub fn write(
        self: AsyncConn,
        loop: *xev.Loop,
        c: *xev.Completion,
        buf: []const u8,
        userdata: ?*anyopaque,
        cb: WriteCallback,
    ) void {
        self.vtable.write(self.ptr, loop, c, buf, userdata, cb);
    }

    pub fn close(
        self: AsyncConn,
        loop: *xev.Loop,
        c: *xev.Completion,
        userdata: ?*anyopaque,
        cb: CloseCallback,
    ) void {
        self.vtable.close(self.ptr, loop, c, userdata, cb);
    }
};

// ---------------------------------------------------------------------------
// TcpConn: AsyncConn backed by xev.TCP
// ---------------------------------------------------------------------------

/// Bridges libxev's strongly-typed callbacks back to the erased `AsyncConn`
/// callbacks by storing the user's callback + userdata for an in-flight op.
const Bridge = struct {
    cb_read: ?ReadCallback = null,
    cb_write: ?WriteCallback = null,
    cb_close: ?CloseCallback = null,
    userdata: ?*anyopaque = null,
};

/// `AsyncConn` implementation backed by `xev.TCP`.
///
/// We thread the user's callback + userdata through libxev's single userdata
/// slot by stashing them in per-direction `Bridge`s on the conn. Each logical
/// stream direction (read / write / close) uses its own caller-supplied
/// `*xev.Completion`, so the three bridges never collide with each other.
pub const TcpConn = struct {
    socket: xev.TCP,
    read_bridge: Bridge = .{},
    write_bridge: Bridge = .{},
    close_bridge: Bridge = .{},

    pub fn initFd(fd: anytype) TcpConn {
        return .{ .socket = xev.TCP.initFd(fd) };
    }

    pub fn fromSocket(socket: xev.TCP) TcpConn {
        return .{ .socket = socket };
    }

    pub fn asyncConn(self: *TcpConn) AsyncConn {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = VTable{
        .read = readImpl,
        .write = writeImpl,
        .close = closeImpl,
    };

    fn readImpl(
        ptr: *anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        buf: []u8,
        userdata: ?*anyopaque,
        cb: ReadCallback,
    ) void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        self.read_bridge = .{ .cb_read = cb, .userdata = userdata };
        self.socket.read(loop, c, .{ .slice = buf }, TcpConn, self, onRead);
    }

    fn onRead(
        ud: ?*TcpConn,
        _: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        _: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self = ud.?;
        if (self.read_bridge.cb_read) |cb| cb(self.read_bridge.userdata, r);
        return .disarm;
    }

    fn writeImpl(
        ptr: *anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        buf: []const u8,
        userdata: ?*anyopaque,
        cb: WriteCallback,
    ) void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        self.write_bridge = .{ .cb_write = cb, .userdata = userdata };
        self.socket.write(loop, c, .{ .slice = buf }, TcpConn, self, onWrite);
    }

    fn onWrite(
        ud: ?*TcpConn,
        _: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        _: xev.WriteBuffer,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self = ud.?;
        if (self.write_bridge.cb_write) |cb| cb(self.write_bridge.userdata, r);
        return .disarm;
    }

    fn closeImpl(
        ptr: *anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        userdata: ?*anyopaque,
        cb: CloseCallback,
    ) void {
        const self: *TcpConn = @ptrCast(@alignCast(ptr));
        self.close_bridge = .{ .cb_close = cb, .userdata = userdata };
        self.socket.close(loop, c, TcpConn, self, onClose);
    }

    fn onClose(
        ud: ?*TcpConn,
        _: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        r: xev.CloseError!void,
    ) xev.CallbackAction {
        const self = ud.?;
        if (self.close_bridge.cb_close) |cb| cb(self.close_bridge.userdata, r);
        return .disarm;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "AsyncConn vtable dispatches through a mock implementation" {
    // A minimal in-memory mock that records calls without touching the loop.
    const Mock = struct {
        read_calls: usize = 0,
        write_calls: usize = 0,
        close_calls: usize = 0,
        last_write_len: usize = 0,

        fn readImpl(
            ptr: *anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            buf: []u8,
            userdata: ?*anyopaque,
            cb: ReadCallback,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.read_calls += 1;
            // Pretend we read the whole buffer immediately.
            cb(userdata, buf.len);
        }
        fn writeImpl(
            ptr: *anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            buf: []const u8,
            userdata: ?*anyopaque,
            cb: WriteCallback,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.write_calls += 1;
            self.last_write_len = buf.len;
            cb(userdata, buf.len);
        }
        fn closeImpl(
            ptr: *anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            userdata: ?*anyopaque,
            cb: CloseCallback,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.close_calls += 1;
            cb(userdata, {});
        }
        const vt = VTable{ .read = readImpl, .write = writeImpl, .close = closeImpl };
        fn conn(self: *@This()) AsyncConn {
            return .{ .ptr = self, .vtable = &vt };
        }
    };

    const Result = struct {
        read_n: usize = 0,
        wrote_n: usize = 0,
        closed: bool = false,
        fn onRead(ud: ?*anyopaque, r: ReadError!usize) void {
            const res: *@This() = @ptrCast(@alignCast(ud.?));
            res.read_n = r catch 0;
        }
        fn onWrite(ud: ?*anyopaque, r: WriteError!usize) void {
            const res: *@This() = @ptrCast(@alignCast(ud.?));
            res.wrote_n = r catch 0;
        }
        fn onClose(ud: ?*anyopaque, r: CloseError!void) void {
            const res: *@This() = @ptrCast(@alignCast(ud.?));
            _ = r catch {};
            res.closed = true;
        }
    };

    var mock = Mock{};
    var res = Result{};
    const c = mock.conn();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var comp: xev.Completion = undefined;

    var rbuf: [16]u8 = undefined;
    c.read(&loop, &comp, &rbuf, &res, Result.onRead);
    c.write(&loop, &comp, "hello", &res, Result.onWrite);
    c.close(&loop, &comp, &res, Result.onClose);

    try testing.expectEqual(@as(usize, 1), mock.read_calls);
    try testing.expectEqual(@as(usize, 1), mock.write_calls);
    try testing.expectEqual(@as(usize, 1), mock.close_calls);
    try testing.expectEqual(@as(usize, 16), res.read_n);
    try testing.expectEqual(@as(usize, 5), res.wrote_n);
    try testing.expectEqual(@as(usize, 5), mock.last_write_len);
    try testing.expect(res.closed);
}
