//! Yggdrasil node layer: addressing, configuration, version handshake,
//! protocol types, transports, admin API, multicast discovery, TUN adapter.

pub const address = @import("address.zig");
pub const config = @import("config.zig");
pub const version = @import("version.zig");
pub const proto = @import("proto.zig");
pub const core = @import("core.zig");
pub const links = @import("links.zig");

pub const Address = address.Address;
pub const Subnet = address.Subnet;
pub const addrForKey = address.addrForKey;
pub const subnetForKey = address.subnetForKey;
pub const Config = config.Config;
pub const Core = core.Core;

test {
    _ = address;
    _ = config;
    _ = version;
    _ = proto;
    _ = core;
}
