//! yggdrasil-zig node entrypoint (placeholder).
//!
//! The full node wiring (TUN, transports, admin socket) will be ported once
//! the ironwood core is complete. For now this prints build/identity info so
//! the executable target compiles and links against ironwood + libxev.
//!
//! Note: Zig 0.16 routes buffered stdout through the new `std.Io` interface,
//! which we will wire up via libxev's event loop in the networking layer.
//! Until then we use `std.debug.print` (unbuffered, stderr) for diagnostics.

const std = @import("std");
const ironwood = @import("ironwood");

pub fn main() !void {
    const id = ironwood.Crypto.generate();
    const addr = ironwood.Addr.fromPublicKey(id.public_key);

    std.debug.print("yggdrasil-zig (ironwood core) — Zig {s}\n", .{@import("builtin").zig_version_string});
    std.debug.print("ephemeral node address: {f}\n", .{addr});
}
