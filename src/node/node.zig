//! Yggdrasil node layer: addressing, configuration, version handshake,
//! protocol types, transports, admin API, multicast discovery, TUN adapter.

pub const address = @import("address.zig");
pub const config = @import("config.zig");
pub const version = @import("version.zig");
pub const proto = @import("proto.zig");
pub const core = @import("core.zig");
pub const links = @import("links.zig");
pub const firewall = @import("firewall.zig");
pub const ipv6rwc = @import("ipv6rwc.zig");
pub const admin = @import("admin.zig");
pub const tls = @import("tls.zig");
pub const tls_wolfssl = @import("tls_wolfssl.zig");
pub const multicast = @import("multicast.zig");
pub const tun = @import("tun.zig");
pub const dns = @import("dns.zig");
pub const network = @import("network.zig");

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
    _ = links;
    _ = firewall;
    _ = ipv6rwc;
    _ = admin;
    _ = tls;
    _ = tls_wolfssl;
    _ = multicast;
    _ = tun;
    _ = dns;
    _ = network;
}
