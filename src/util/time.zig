//! Monotonic clock helpers.
//!
//! Zig 0.16 removed `std.time.Instant`/`Timer`/`nanoTimestamp` (timing moved
//! behind the new `std.Io` interface). The packet queue needs a cheap
//! monotonic timestamp for age accounting and FIFO tie-breaking, so we read
//! the platform's native monotonic clock directly, with a portable fallback
//! for anything unrecognized:
//!
//!   - POSIX targets (Linux/macOS/*BSD/...): `std.c.clock_gettime` with
//!     `std.c.CLOCK.MONOTONIC` -- these all require linking libc anyway
//!     (wolfSSL does), and `std.c` already picks the platform-correct
//!     `clockid_t` numeric values (e.g. macOS's MONOTONIC = 6 differs from
//!     Linux's MONOTONIC = 1).
//!   - Windows: `QueryPerformanceCounter`/`QueryPerformanceFrequency` --
//!     `clock_gettime` is not part of the native Win32 API (`std.c`
//!     deliberately doesn't expose a `CLOCK` enum for `.windows`).
//!   - Anything else: a process-local monotonically-increasing counter.
//!     Not wall time, but sufficient for relative age/ordering.

const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

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
    return switch (native_os) {
        .windows => windowsMonotonicNanos(),
        // Zig 0.16 aliases `std.c.CLOCK` to the `clockid_t` enum. Enum
        // fields are not `@hasDecl`s (`@hasDecl(std.c.CLOCK, "MONOTONIC")`
        // is false even though `std.c.CLOCK.MONOTONIC` is a valid value),
        // so we dispatch on OS tag rather than reflection.
        .linux, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos, .haiku, .freebsd, .illumos, .netbsd, .dragonfly, .openbsd, .serenity => posixMonotonicNanos(),
        else => fallbackCounter(),
    };
}

/// Wall-clock seconds since the Unix epoch. Returns 0 if unavailable (the
/// Ironwood wire protocol treats 0 as "no timestamp" and simply skips
/// freshness comparisons in that case, matching the reference behavior of
/// a failed `time.Now().Unix()`).
pub fn wallClockSeconds() u64 {
    return switch (native_os) {
        .windows => windowsWallClockSeconds(),
        .linux, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos, .haiku, .freebsd, .illumos, .netbsd, .dragonfly, .openbsd, .serenity => posixWallClockSeconds(),
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// POSIX (Linux, macOS, *BSD, ...) via libc clock_gettime
// ---------------------------------------------------------------------------

fn posixMonotonicNanos() u64 {
    // Prefer the Linux syscall so modules that don't link libc (unit tests)
    // still get a real clock. Other POSIX targets go through libc.
    if (native_os == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.MONOTONIC, &ts) == 0) {
            const sec: u64 = @intCast(ts.sec);
            const nsec: u64 = @intCast(ts.nsec);
            return sec *% std.time.ns_per_s +% nsec;
        }
        return fallbackCounter();
    }
    if (!builtin.link_libc) return fallbackCounter();
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts) == 0) {
        const sec: u64 = @intCast(ts.sec);
        const nsec: u64 = @intCast(ts.nsec);
        return sec *% std.time.ns_per_s +% nsec;
    }
    return fallbackCounter();
}

fn posixWallClockSeconds() u64 {
    if (native_os == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.REALTIME, &ts) == 0 and ts.sec > 0) {
            return @intCast(ts.sec);
        }
        return 0;
    }
    if (!builtin.link_libc) return 0;
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts) == 0 and ts.sec > 0) {
        return @intCast(ts.sec);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Windows via QueryPerformanceCounter
// ---------------------------------------------------------------------------

extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *i64) callconv(.winapi) c_int;
extern "kernel32" fn QueryPerformanceFrequency(lpFrequency: *i64) callconv(.winapi) c_int;
extern "kernel32" fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *WindowsFileTime) callconv(.winapi) void;

const WindowsFileTime = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

/// FILETIME is 100ns intervals since 1601-01-01; Unix epoch is 1970-01-01.
const EPOCH_DIFFERENCE_100NS: u64 = 116444736000000000;

fn windowsWallClockSeconds() u64 {
    var ft: WindowsFileTime = undefined;
    GetSystemTimeAsFileTime(&ft);
    const ticks: u64 = (@as(u64, ft.dwHighDateTime) << 32) | @as(u64, ft.dwLowDateTime);
    if (ticks < EPOCH_DIFFERENCE_100NS) return 0;
    const unix_100ns = ticks - EPOCH_DIFFERENCE_100NS;
    return unix_100ns / 10_000_000;
}

var qpc_freq_cache: std.atomic.Value(i64) = std.atomic.Value(i64).init(0);

fn windowsMonotonicNanos() u64 {
    var freq = qpc_freq_cache.load(.monotonic);
    if (freq == 0) {
        var f: i64 = 0;
        if (QueryPerformanceFrequency(&f) == 0 or f <= 0) return fallbackCounter();
        qpc_freq_cache.store(f, .monotonic);
        freq = f;
    }
    var counter: i64 = 0;
    if (QueryPerformanceCounter(&counter) == 0) return fallbackCounter();
    if (counter < 0) return fallbackCounter();
    // Split into whole seconds  remainder to avoid overflow at ns
    // resolution for large counter values.
    const c: u64 = @intCast(counter);
    const f: u64 = @intCast(freq);
    const secs = c / f;
    const rem = c % f;
    return secs *% std.time.ns_per_s +% (rem *% std.time.ns_per_s) / f;
}

// ---------------------------------------------------------------------------
// Fallback: process-local monotonically-increasing counter
// ---------------------------------------------------------------------------

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

test "monotonic clock returns real nanoseconds, not a unit counter" {
    const a = monotonicNanos();
    // A process-local incrementing counter starts at 0/1; a real monotonic
    // clock on any supported OS is at least milliseconds since boot.
    try std.testing.expect(a > 1_000_000);
}

test "wall clock is a unix timestamp" {
    if (native_os == .windows or native_os == .linux or native_os == .macos or native_os == .freebsd) {
        const s = wallClockSeconds();
        // Later than 2020-01-01, earlier than 2100-01-01.
        try std.testing.expect(s > 1_577_836_800);
        try std.testing.expect(s < 4_102_444_800);
    }
}
