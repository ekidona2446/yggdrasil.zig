//! Event-loop wrapper over `xev.Loop`.
//!
//! This is intentionally a thin convenience layer: the rest of the async code works
//! directly with `xev.Loop`, `xev.Completion`, and the watcher types (TCP/Async/Timer), which
//! is the idiomatic libxev style. The wrapper centralizes init/run/stop and
//! exposes the underlying loop pointer for the networking layer.

const std = @import("std");
const xev = @import("xev");

pub const RunMode = enum {
    /// Run until there are no more active completions.
    until_done,
    /// Process all currently-ready completions without blocking, then return.
    no_wait,
    /// Block until at least one completion is ready, process it, then return.
    once,

    fn toXev(self: RunMode) xev.RunMode {
        return switch (self) {
            .until_done => .until_done,
            .no_wait => .no_wait,
            .once => .once,
        };
    }
};

pub const EventLoop = struct {
    inner: xev.Loop,

    pub fn init() !EventLoop {
        return .{ .inner = try xev.Loop.init(.{}) };
    }

    pub fn deinit(self: *EventLoop) void {
        self.inner.deinit();
    }

    /// Access the underlying libxev loop (for passing to watchers).
    pub fn raw(self: *EventLoop) *xev.Loop {
        return &self.inner;
    }

    /// Run the loop in the given mode.
    pub fn run(self: *EventLoop, mode: RunMode) !void {
        try self.inner.run(mode.toXev());
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "event loop runs a timer to completion" {
    var loop = try EventLoop.init();
    defer loop.deinit();

    const State = struct {
        fired: bool = false,
        fn cb(
            ud: ?*@This(),
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            _ = r catch {};
            ud.?.fired = true;
            return .disarm;
        }
    };
    var state = State{};
    var timer = try xev.Timer.init();
    defer timer.deinit();
    var c: xev.Completion = undefined;
    timer.run(loop.raw(), &c, 1, State, &state, State.cb);

    try loop.run(.until_done);
    try testing.expect(state.fired);
}
