//! Async runtime layer for yggdrasil.zig, built on libxev.
//!
//! This module is the single import surface for the networking layer
//! (peers.zig, core.zig) once those are ported.

const std = @import("std");

pub const loop = @import("loop.zig");
pub const channel = @import("channel.zig");
pub const cancel = @import("cancel.zig");
pub const conn = @import("conn.zig");

pub const EventLoop = loop.EventLoop;
pub const RunMode = loop.RunMode;
pub const Channel = channel.Channel;
pub const ChannelError = channel.ChannelError;
pub const CancelToken = cancel.CancelToken;
pub const AsyncConn = conn.AsyncConn;
pub const TcpConn = conn.TcpConn;

test {
    _ = loop;
    _ = channel;
    _ = cancel;
    _ = conn;
}
