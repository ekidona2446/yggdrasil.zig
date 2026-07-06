//! Shared utilities.
//!
//! Currently holds monotonic-clock helpers; more
//! general-purpose helpers can live here as the port grows.

pub const time = @import("time.zig");

test {
    _ = time;
}
