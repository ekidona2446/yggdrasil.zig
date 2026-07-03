//! yggdrasil.zig node entrypoint.
//!
//! Brings up a full Yggdrasil node: generates (or loads) an identity, starts
//! the ironwood router/session core, dials configured peers over TCP with
//! libxev, optionally listens for inbound peers, bridges a TUN device for
//! IPv6 traffic, and periodically runs router maintenance -- all on a single
//! event loop thread.
//!
//! Usage:
//!   yggdrasil [--peer <uri>]... [--listen <uri>]... [--tun <name|auto|none>]
//!             [--mtu <n>] [--password <pw>]

const std = @import("std");
const xev = @import("xev");
const ironwood = @import("ironwood");
const node = @import("node");

const Core = node.core.Core;
const NetworkManager = node.network.NetworkManager;
const TunAdapter = node.tun.TunAdapter;
const ReadWriteCloser = node.ipv6rwc.ReadWriteCloser;

const MAINTENANCE_INTERVAL_MS: u64 = 1000;
const TUN_READ_BUF_SIZE: usize = 65535 + 4;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var cli = try parseArgs(gpa, init.minimal.args);
    defer cli.deinit(gpa);

    const id = ironwood.Crypto.generate();
    const addr = node.addrForKey(&id.public_key);
    const subnet = node.subnetForKey(&id.public_key);

    std.debug.print("yggdrasil.zig {s}\n", .{"0.0.1-dev"});
    std.debug.print("public key: {x}\n", .{id.public_key});
    std.debug.print("address:    {f}\n", .{addr});
    std.debug.print("subnet:     {f}/64\n", .{subnet});

    var iw_cfg = ironwood.Config.default();
    // Critical for interop: real Yggdrasil peers transform keys through
    // SubnetForKey(key).GetKey() before inserting them into bloom filters.
    // Without this, our bloom filters never match lookups from (or to) the
    // rest of the network and path discovery silently fails.
    iw_cfg.bloom_transform = node.address.bloomKeyTransform;
    var core = try Core.init(gpa, id, iw_cfg, cli.password);
    defer core.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var net = NetworkManager.init(gpa, &loop, &core, id);
    defer net.deinit();

    var rwc = try ReadWriteCloser.init(gpa, &core, cli.mtu);
    defer rwc.deinit();

    var app = App{ .gpa = gpa, .net = &net, .rwc = &rwc, .tun = null };
    net.on_deliver = App.onDeliverTrampoline;
    net.on_deliver_ud = &app;
    net.on_discover = App.onDiscoverTrampoline;
    net.on_discover_ud = &app;

    // -- TUN setup ------------------------------------------------------
    var tun_adapter: ?TunAdapter = null;
    if (!std.mem.eql(u8, cli.tun_name, "none")) {
        tun_adapter = TunAdapter.init(cli.tun_name, "", @intCast(cli.mtu)) catch |err| blk: {
            std.debug.print("[ygg] warning: failed to create TUN device ({}); continuing without TUN (mesh routing still active)\n", .{err});
            break :blk null;
        };
        if (tun_adapter) |*t| {
            node.tun.assignAddress(gpa, std.mem.sliceTo(&t.name, 0), addr, @intCast(cli.mtu)) catch |err| {
                std.debug.print("[ygg] warning: failed to assign TUN address ({}); configure manually with `ip`\n", .{err});
            };
            std.debug.print("status:     tun device '{s}' up\n", .{std.mem.sliceTo(&t.name, 0)});
        }
    } else {
        std.debug.print("status:     tun disabled (--tun none)\n", .{});
    }

    var tun_io: ?TunIo = null;
    if (tun_adapter) |*t| {
        tun_io = TunIo{ .app = &app, .fd = t.fd, .file = xev.File.initFd(t.fd) };
        app.tun = &tun_io.?;
        tun_io.?.file.read(&loop, &tun_io.?.read_completion, .{ .slice = &tun_io.?.read_buf }, TunIo, &tun_io.?, TunIo.onRead);
    }

    // -- Peers / listeners ------------------------------------------------
    for (cli.peers.items) |peer_uri| {
        net.addOutboundPeer(peer_uri, .{ .password = cli.password }) catch |err| {
            std.debug.print("[ygg] failed to configure peer {s}: {}\n", .{ peer_uri, err });
        };
    }
    for (cli.listeners.items) |listen_uri| {
        net.addListener(listen_uri) catch |err| {
            std.debug.print("[ygg] failed to listen on {s}: {}\n", .{ listen_uri, err });
        };
    }

    std.debug.print("status:     running (press Ctrl+C to stop)\n", .{});

    // -- Maintenance timer --------------------------------------------------
    var maint_timer = try xev.Timer.init();
    defer maint_timer.deinit();
    var maint_completion: xev.Completion = undefined;
    var maint_ctx = MaintenanceCtx{ .net = &net, .timer = &maint_timer };
    maint_timer.run(&loop, &maint_completion, MAINTENANCE_INTERVAL_MS, MaintenanceCtx, &maint_ctx, MaintenanceCtx.onTick);

    try loop.run(.until_done);
}

const MaintenanceCtx = struct {
    net: *NetworkManager,
    timer: *xev.Timer,
    completion: xev.Completion = undefined,

    fn onTick(ud: ?*MaintenanceCtx, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const ctx = ud.?;
        ctx.net.runMaintenance() catch |err| {
            std.debug.print("[ygg] maintenance error: {}\n", .{err});
        };
        ctx.timer.run(loop, c, MAINTENANCE_INTERVAL_MS, MaintenanceCtx, ctx, onTick);
        return .disarm;
    }
};

/// Ties the network layer's callbacks (deliver / discover) to the TUN bridge.
const App = struct {
    gpa: std.mem.Allocator,
    net: *NetworkManager,
    rwc: *ReadWriteCloser,
    tun: ?*TunIo,

    fn onDeliverTrampoline(ud: ?*anyopaque, source: *const ironwood.PublicKey, data: []const u8) void {
        std.debug.print("[ygg] delivered {d} bytes from {x}\n", .{ data.len, source.* });
        const self: *App = @ptrCast(@alignCast(ud.?));
        if (self.rwc.handleInbound(source, data)) |pkt| {
            if (self.tun) |t| {
                t.write(pkt) catch |err| {
                    std.debug.print("[ygg] tun write error: {}\n", .{err});
                };
            }
        } else {
            std.debug.print("[ygg] handleInbound rejected payload (len={d})\n", .{data.len});
        }
    }

    fn onDiscoverTrampoline(ud: ?*anyopaque, key: *const ironwood.PublicKey) void {
        std.debug.print("[ygg] discovered path to {x}\n", .{key.*});
        const self: *App = @ptrCast(@alignCast(ud.?));
        const result = self.rwc.updateKey(key.*) catch |err| {
            std.debug.print("[ygg] updateKey error: {}\n", .{err});
            return;
        };
        self.net.flushFrames(result.frames);
    }
};

/// Bridges the TUN file descriptor into the event loop: reads packets and
/// forwards them through `ReadWriteCloser.handleOutbound` -> `NetworkManager`.
const TunIo = struct {
    app: *App,
    fd: std.posix.fd_t,
    file: xev.File,
    read_buf: [TUN_READ_BUF_SIZE]u8 = undefined,
    read_completion: xev.Completion = undefined,
    write_buf: [TUN_READ_BUF_SIZE]u8 = undefined,
    write_completion: xev.Completion = undefined,
    write_busy: bool = false,

    fn onRead(ud: ?*TunIo, loop: *xev.Loop, c: *xev.Completion, file: xev.File, buf: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
        _ = c;
        _ = file;
        const self = ud.?;
        const n = r catch |err| {
            std.debug.print("[ygg] tun read error: {}\n", .{err});
            return .disarm;
        };
        std.debug.print("[ygg] tun read {d} bytes\n", .{n});
        if (n > 0) {
            const pkt = buf.slice[0..n];
            if (self.app.rwc.handleOutbound(pkt)) |frames| {
                std.debug.print("[ygg] handleOutbound produced {d} frames\n", .{frames.len});
                self.app.net.flushFrames(frames);
            } else |err| {
                std.debug.print("[ygg] handleOutbound error: {}\n", .{err});
            }
        }
        self.file.read(loop, &self.read_completion, .{ .slice = &self.read_buf }, TunIo, self, onRead);
        return .disarm;
    }

    fn write(self: *TunIo, data: []const u8) !void {
        if (data.len > self.write_buf.len) return error.PacketTooLarge;
        // Best-effort synchronous write via the blocking fd: TUN writes are
        // rarely a bottleneck compared to the network path, and doing this
        // synchronously avoids needing a write queue for the (uncommon)
        // case of back-to-back inbound packets outrunning a single async
        // write's completion.
        const n = std.os.linux.write(self.fd, data.ptr, data.len);
        const signed: isize = @bitCast(n);
        if (signed < 0) return error.WriteFailed;
    }
};

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

const Cli = struct {
    peers: std.ArrayListUnmanaged([]const u8) = .empty,
    listeners: std.ArrayListUnmanaged([]const u8) = .empty,
    tun_name: []const u8 = "auto",
    mtu: u64 = 65535,
    password: []const u8 = &.{},

    fn deinit(self: *Cli, gpa: std.mem.Allocator) void {
        self.peers.deinit(gpa);
        self.listeners.deinit(gpa);
    }
};

fn parseArgs(gpa: std.mem.Allocator, raw_args: std.process.Args) !Cli {
    var cli = Cli{};
    var args = std.process.Args.Iterator.init(raw_args);
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--peer")) {
            if (args.next()) |v| try cli.peers.append(gpa, v);
        } else if (std.mem.eql(u8, arg, "--listen")) {
            if (args.next()) |v| try cli.listeners.append(gpa, v);
        } else if (std.mem.eql(u8, arg, "--tun")) {
            if (args.next()) |v| cli.tun_name = v;
        } else if (std.mem.eql(u8, arg, "--mtu")) {
            if (args.next()) |v| cli.mtu = std.fmt.parseInt(u64, v, 10) catch cli.mtu;
        } else if (std.mem.eql(u8, arg, "--password")) {
            if (args.next()) |v| cli.password = v;
        }
    }
    return cli;
}
