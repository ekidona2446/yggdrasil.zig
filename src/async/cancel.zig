//! Cancellation token for cooperative shutdown of async tasks.
//!
//! Usage:
//!   - `cancel()` sets the flag (idempotent) and wakes any loop waiters.
//!   - `isCancelled()` is a cheap atomic check for poll-style loops.
//!   - `wait(loop, completion, Ud, ud, cb)` registers a one-shot callback that
//!     fires when the token is (or becomes) cancelled.
//!
//! The token is reference-shareable: clone the pointer, not the value. It must
//! outlive every loop/completion that references it.

const std = @import("std");
const xev = @import("xev");

pub const CancelToken = struct {
    /// Set to true once cancellation has been requested.
    flag: std.atomic.Value(bool),
    /// Cross-thread notifier used to wake event-loop waiters.
    notifier: xev.Async,

    pub fn init() !CancelToken {
        return .{
            .flag = std.atomic.Value(bool).init(false),
            .notifier = try xev.Async.init(),
        };
    }

    pub fn deinit(self: *CancelToken) void {
        self.notifier.deinit();
    }

    /// Request cancellation. Idempotent; safe to call from any thread.
    pub fn cancel(self: *CancelToken) void {
        // Only notify on the first transition false -> true to avoid spurious
        // wakeups, but cancellation itself is always observable afterwards.
        const was = self.flag.swap(true, .seq_cst);
        if (!was) {
            // Best-effort wakeup; if it fails the poll-based checks still work.
            self.notifier.notify() catch {};
        }
    }

    /// Cheap check for poll-style loops.
    pub fn isCancelled(self: *const CancelToken) bool {
        return self.flag.load(.seq_cst);
    }

    /// Register a one-shot wakeup that fires when the token is cancelled.
    ///
    /// If the token is already cancelled the callback will still fire on the
    /// next loop tick (the notifier was signalled at cancel time, or the caller
    /// should also check `isCancelled()` before waiting).
    pub fn wait(
        self: *CancelToken,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "cancel flag transitions and is idempotent" {
    var tok = try CancelToken.init();
    defer tok.deinit();

    try testing.expect(!tok.isCancelled());
    tok.cancel();
    try testing.expect(tok.isCancelled());
    tok.cancel(); // idempotent
    try testing.expect(tok.isCancelled());
}

test "cancel wakes a loop waiter" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var tok = try CancelToken.init();
    defer tok.deinit();

    const State = struct {
        woke: bool = false,
        fn cb(
            ud: ?*@This(),
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Async.WaitError!void,
        ) xev.CallbackAction {
            _ = r catch {};
            ud.?.woke = true;
            return .disarm;
        }
    };
    var state = State{};
    var c: xev.Completion = undefined;
    tok.wait(&loop, &c, State, &state, State.cb);

    // Request cancellation, then drive the loop until the waiter fires.
    tok.cancel();
    try loop.run(.until_done);
    try testing.expect(state.woke);
}
