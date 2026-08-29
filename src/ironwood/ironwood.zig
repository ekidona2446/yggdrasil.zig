//! ironwood: routing library (ed25519-addressed PacketConn over a spanning tree).
//!
//! Zig port of the Ironwood, targeting Zig 0.16 with
//! libxev for async I/O. This is the module root that re-exports the public
//! API and pulls in all submodules for testing.

const std = @import("std");

pub const types = @import("types.zig");
pub const crypto = @import("crypto.zig");
pub const config = @import("config.zig");
pub const wire = @import("wire.zig");
pub const bloom = @import("bloom.zig");
pub const signed = @import("signed.zig");
pub const traffic = @import("traffic.zig");
pub const pathfinder = @import("pathfinder.zig");
pub const router = @import("router.zig");
pub const encrypted = @import("encrypted/mod.zig");
pub const peers = @import("peers.zig");

// Primary public API re-exports.
pub const Addr = types.Addr;
pub const Error = types.Error;
pub const Config = config.Config;
pub const Crypto = crypto.Crypto;
pub const PublicKey = crypto.PublicKey;
pub const Sig = crypto.Sig;
pub const BloomFilter = bloom.BloomFilter;
pub const Blooms = bloom.Blooms;
pub const TrafficPacket = traffic.TrafficPacket;
pub const PacketQueue = traffic.PacketQueue;
pub const DeliveryQueue = traffic.DeliveryQueue;

test {
    // Pull in all submodule tests.
    _ = types;
    _ = crypto;
    _ = config;
    _ = wire;
    _ = bloom;
    _ = signed;
    _ = traffic;
    _ = pathfinder;
    _ = router;
}
