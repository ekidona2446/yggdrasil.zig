//! Monotonic clock helpers.
//!
//! Zig 0.16 removed `std.time.Instant`/`Timer`/`nanoTimestamp` (timing moved
//! behind the new `std.Io` interface). The packet queue needs a cheap
//! monotonic timestamp for age accounting and FIFO tie-breaking, so we read
//! `CLOCK_MONOTONIC` directly on Linux with a portable fallback.

const std = @import("std");
const builtin = @import("builtin");

/// A monotonic instant, expressed in nanoseconds since an unspecified epoch.
pub const Instant = struct {
    nanos: u64,

    pub fn now() Instant {
        return .{ .nanos = monotonicNanos() };
    }

    /// Nanoseconds elapsed from `self` to now (saturating at 0).
    pub fn elapsedNanos(self: Instant) u64 {
        const cur = monotonicNanos();
        return if (cur > self.nanos) cur - self.nanos else 0;
    }

    /// Order two instants (earlier < later).
    pub fn order(self: Instant, other: Instant) std.math.Order {
        return std.math.order(self.nanos, other.nanos);
    }
};

/// Read a monotonic clock in nanoseconds.
pub fn monotonicNanos() u64 {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        const rc = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        const signed: isize = @bitCast(rc);
        if (signed == 0) {
            const sec: u64 = @intCast(ts.sec);
            const nsec: u64 = @intCast(ts.nsec);
            return sec *% std.time.ns_per_s +% nsec;
        }
    }
    // Fallback: a process-local counter that is at least monotonic. Not wall
    // time, but sufficient for relative age/ordering when no clock is available.
    return fallbackCounter();
}

var fallback_state: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

fn fallbackCounter() u64 {
    return fallback_state.fetchAdd(1, .monotonic);
}

test "monotonic clock is non-decreasing" {
    const a = Instant.now();
    const b = Instant.now();
    try std.testing.expect(b.nanos >= a.nanos);
    // elapsed is saturating and never panics.
    _ = a.elapsedNanos();
}
