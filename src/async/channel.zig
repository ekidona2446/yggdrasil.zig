//! Bounded MPSC channel for the libxev event loop.
//!
//! Design:
//!   - A mutex-protected ring buffer of `T` values (bounded capacity).
//!   - An `xev.Async` notifier so a consumer parked in the event loop is woken
//!     when an item is pushed.
//!   - `send` returns `error.Full` when at capacity (callers may drop or back
//!     off, matching the bounded tokio channel semantics with `try_send`).
//!   - `tryRecv` is non-blocking; `waitReceivable` registers a loop wakeup.
//!
//! Ownership: the channel stores `T` by value. If `T` owns heap memory, the
//! consumer is responsible for freeing dequeued items.

const std = @import("std");
const Allocator = std.mem.Allocator;
const xev = @import("xev");

pub const ChannelError = error{
    Full,
    Closed,
};

/// Minimal CAS spinlock guarding the ring buffer's tiny critical sections.
///
/// Zig 0.16 removed `std.Thread.Mutex`; the new `std.Io.Mutex` requires an `Io`
/// instance to lock. Our critical sections here are a handful of integer/field
/// operations, so a lightweight spinlock is both correct and dependency-free.
const SpinLock = struct {
    state: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn lock(self: *SpinLock) void {
        while (self.state.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }
    fn unlock(self: *SpinLock) void {
        self.state.store(false, .release);
    }
};

pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        mutex: SpinLock = .{},
        buf: []T,
        head: usize = 0,
        len: usize = 0,
        closed: bool = false,
        notifier: xev.Async,
        gpa: Allocator,

        /// Create a channel with the given fixed capacity (> 0).
        pub fn init(gpa: Allocator, capacity: usize) !Self {
            std.debug.assert(capacity > 0);
            return .{
                .buf = try gpa.alloc(T, capacity),
                .notifier = try xev.Async.init(),
                .gpa = gpa,
            };
        }

        pub fn deinit(self: *Self) void {
            self.notifier.deinit();
            self.gpa.free(self.buf);
        }

        /// Push an item. Returns error.Full if at capacity, error.Closed if the
        /// channel is closed. Safe to call from any thread.
        pub fn send(self: *Self, item: T) ChannelError!void {
            self.mutex.lock();
            if (self.closed) {
                self.mutex.unlock();
                return ChannelError.Closed;
            }
            if (self.len == self.buf.len) {
                self.mutex.unlock();
                return ChannelError.Full;
            }
            const tail = (self.head + self.len) % self.buf.len;
            self.buf[tail] = item;
            self.len += 1;
            self.mutex.unlock();

            // Wake a parked consumer. Best-effort; tryRecv also works on poll.
            self.notifier.notify() catch {};
        }

        /// Pop an item if available. Returns null when empty.
        pub fn tryRecv(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.len == 0) return null;
            const item = self.buf[self.head];
            self.head = (self.head + 1) % self.buf.len;
            self.len -= 1;
            return item;
        }

        pub fn isEmpty(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.len == 0;
        }

        pub fn close(self: *Self) void {
            self.mutex.lock();
            self.closed = true;
            self.mutex.unlock();
            self.notifier.notify() catch {};
        }

        pub fn isClosed(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.closed;
        }

        /// Register a one-shot wakeup that fires when an item may be receivable
        /// (an item was pushed or the channel was closed). The callback should
        /// drain via `tryRecv` and re-arm if it wants to keep consuming.
        pub fn waitReceivable(
            self: *Self,
            loop: *xev.Loop,
            c: *xev.Completion,
            comptime Userdata: type,
            userdata: ?*Userdata,
            comptime cb: *const fn (
                ud: ?*Userdata,
                l: *xev.Loop,
                c: *xev.Completion,
                r: xev.Async.WaitError!void,
            ) xev.CallbackAction,
        ) void {
            self.notifier.wait(loop, c, Userdata, userdata, cb);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "channel basic send/tryRecv FIFO order" {
    const gpa = testing.allocator;
    var ch = try Channel(u32).init(gpa, 4);
    defer ch.deinit();

    try testing.expect(ch.isEmpty());
    try ch.send(1);
    try ch.send(2);
    try ch.send(3);
    try testing.expect(!ch.isEmpty());

    try testing.expectEqual(@as(?u32, 1), ch.tryRecv());
    try testing.expectEqual(@as(?u32, 2), ch.tryRecv());
    try testing.expectEqual(@as(?u32, 3), ch.tryRecv());
    try testing.expectEqual(@as(?u32, null), ch.tryRecv());
}

test "channel reports Full at capacity and wraps after recv" {
    const gpa = testing.allocator;
    var ch = try Channel(u8).init(gpa, 2);
    defer ch.deinit();

    try ch.send(10);
    try ch.send(20);
    try testing.expectError(ChannelError.Full, ch.send(30));

    // Drain one, ring buffer should wrap and accept again.
    try testing.expectEqual(@as(?u8, 10), ch.tryRecv());
    try ch.send(30);
    try testing.expectEqual(@as(?u8, 20), ch.tryRecv());
    try testing.expectEqual(@as(?u8, 30), ch.tryRecv());
}

test "channel close rejects further sends" {
    const gpa = testing.allocator;
    var ch = try Channel(u8).init(gpa, 2);
    defer ch.deinit();

    try ch.send(1);
    ch.close();
    try testing.expect(ch.isClosed());
    try testing.expectError(ChannelError.Closed, ch.send(2));
    // Items queued before close are still drainable.
    try testing.expectEqual(@as(?u8, 1), ch.tryRecv());
}

test "channel send wakes a loop consumer" {
    const gpa = testing.allocator;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var ch = try Channel(u32).init(gpa, 4);
    defer ch.deinit();

    const State = struct {
        ch: *Channel(u32),
        got: ?u32 = null,
        fn cb(
            ud: ?*@This(),
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Async.WaitError!void,
        ) xev.CallbackAction {
            _ = r catch {};
            ud.?.got = ud.?.ch.tryRecv();
            return .disarm;
        }
    };
    var state = State{ .ch = &ch };
    var c: xev.Completion = undefined;
    ch.waitReceivable(&loop, &c, State, &state, State.cb);

    try ch.send(42);
    try loop.run(.until_done);
    try testing.expectEqual(@as(?u32, 42), state.got);
}
