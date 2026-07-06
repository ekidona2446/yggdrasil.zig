//! yggdrasil.zig node entrypoint.
//!
//! Brings up a full Yggdrasil node: generates (or loads) an identity, starts
//! the ironwood router/session core, dials configured peers over TCP/TLS
//! with libxev, optionally listens for inbound peers, bridges a TUN device
//! for IPv6 traffic, and periodically runs router maintenance -- all on a
//! single event loop thread.
//!
//! Usage:
//!   yggdrasil [options]
//!
//!   Configuration:
//!     -c, --useconffile FILE   Read TOML config from FILE
//!         --useconf             Read TOML config from stdin
//!     -g, --genconf [FILE]      Print (or save) a new default config
//!     -n, --normaliseconf       With --useconf(file), print the config back
//!                                out with all defaults filled in
//!         --json                 Emit --genconf/--normaliseconf output as
//!                                JSON instead of TOML
//!         --autoconf             Run with an ephemeral identity and no
//!                                config file (peers/listen from CLI flags)
//!
//!   Info / one-shot:
//!     -v, --version              Print version and exit
//!     -a, --address              Print the IPv6 address for the config/CLI
//!                                identity and exit
//!     -s, --subnet               Print the IPv6 subnet and exit
//!     -k, --publickey            Print the hex public key and exit
//!         --exportkey             Print the private key as hex and exit
//!     -h, --help                  Print this help and exit
//!
//!   Runtime overrides (combinable with a config file; repeatable where
//!   noted):
//!         --peer URI              Add an outbound peer (repeatable)
//!         --listen URI            Add a listener (repeatable)
//!         --tun NAME|auto|none    TUN interface name (default: auto)
//!         --mtu N                 TUN MTU (default: 65535)
//!         --password PW           Shared password applied to CLI-added
//!                                peers/listeners without an explicit
//!                                per-URI password
//!         --admin-listen URI      Admin socket address ("" to disable)
//!         --loglevel LEVEL        error|warn|info|debug (default: info)
//!         --logto FILE|stdout     Log destination (default: stdout)

const std = @import("std");
const xev = @import("xev");
const ironwood = @import("ironwood");
const node = @import("node");

const Core = node.core.Core;
const NetworkManager = node.network.NetworkManager;
const TunAdapter = node.tun.TunAdapter;
const ReadWriteCloser = node.ipv6rwc.ReadWriteCloser;
const Config = node.config.Config;

const MAINTENANCE_INTERVAL_MS: u64 = 1000;
const TUN_READ_BUF_SIZE: usize = 65535 + 4;
const YGGDRASIL_ZIG_VERSION: []const u8 = "0.0.1-dev";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var cli = try parseArgs(gpa, init.minimal.args);
    defer cli.deinit(gpa);

    switch (cli.action) {
        .help => {
            printUsage();
            return;
        },
        .version => {
            std.debug.print("yggdrasil.zig {s}\n", .{YGGDRASIL_ZIG_VERSION});
            return;
        },
        .run => {},
    }

    // -- Load or generate configuration -------------------------------
    var cfg: Config = undefined;
    var cfg_owned = false;
    defer if (cfg_owned) cfg.deinit(gpa);

    if (cli.useconffile) |path| {
        const text = try readFileAlloc(gpa, io, path);
        defer gpa.free(text);
        cfg = try Config.parseToml(gpa, text);
        cfg_owned = true;
    } else if (cli.use_stdin_conf) {
        const text = try readStdinAlloc(gpa, io);
        defer gpa.free(text);
        cfg = try Config.parseToml(gpa, text);
        cfg_owned = true;
    } else {
        // --autoconf, --genconf with no --useconf(file), or simply no
        // config source given at all: `generateDefault` already mints a
        // fresh Ed25519 identity, which both serves as the ephemeral
        // runtime key (--autoconf / no config) and as the private_key
        // shown in `--genconf` output.
        cfg = try Config.generateDefault(gpa);
        cfg_owned = true;
    }

    // -- genconf / normaliseconf: print and exit before starting anything --
    if (cli.genconf) |maybe_path| {
        try emitConfig(gpa, io, &cfg, cli.json_output, maybe_path, cli.no_replace);
        return;
    }
    if (cli.normaliseconf) {
        try emitConfig(gpa, io, &cfg, cli.json_output, null, false);
        return;
    }

    // -- Resolve identity ------------------------------------------------
    const id: ironwood.Crypto = (try cfg.signingKey()) orelse ironwood.Crypto.generate();

    if (cli.exportkey) {
        var hex_buf: [128]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        const kp_bytes = id.key_pair.secret_key.toBytes();
        for (kp_bytes, 0..) |b, i| {
            hex_buf[i * 2] = hex_chars[(b >> 4) & 0xF];
            hex_buf[i * 2 + 1] = hex_chars[b & 0xF];
        }
        std.debug.print("{s}\n", .{hex_buf});
        return;
    }

    const addr = node.addrForKey(&id.public_key);
    const subnet = node.subnetForKey(&id.public_key);

    if (cli.print_address) {
        std.debug.print("{f}\n", .{addr});
        return;
    }
    if (cli.print_subnet) {
        std.debug.print("{f}/64\n", .{subnet});
        return;
    }
    if (cli.print_publickey) {
        std.debug.print("{x}\n", .{id.public_key});
        return;
    }

    // -- Merge CLI overrides on top of file config ------------------------
    var effective_peers = std.ArrayListUnmanaged([]const u8).empty;
    defer effective_peers.deinit(gpa);
    try effective_peers.appendSlice(gpa, cfg.peers);
    try effective_peers.appendSlice(gpa, cli.peers.items);

    var effective_listen = std.ArrayListUnmanaged([]const u8).empty;
    defer effective_listen.deinit(gpa);
    try effective_listen.appendSlice(gpa, cfg.listen);
    try effective_listen.appendSlice(gpa, cli.listeners.items);

    const tun_name = cli.tun_name orelse cfg.if_name;
    const mtu: u64 = cli.mtu orelse cfg.if_mtu;
    const admin_listen = cli.admin_listen orelse cfg.admin_listen;
    const password = cli.password;

    std.debug.print("yggdrasil.zig {s}\n", .{YGGDRASIL_ZIG_VERSION});
    std.debug.print("public key: {x}\n", .{id.public_key});
    std.debug.print("address: {f}\n", .{addr});
    std.debug.print("subnet: {f}/64\n", .{subnet});

    var iw_cfg = ironwood.Config.default();
    // Critical for interop: real Yggdrasil peers transform keys through
    // SubnetForKey(key).GetKey() before inserting them into bloom filters.
    // Without this, our bloom filters never match lookups from (or to) the
    // rest of the network and path discovery silently fails.
    iw_cfg.bloom_transform = node.address.bloomKeyTransform;
    var core = try Core.init(gpa, id, iw_cfg, cfg.group_password);
    defer core.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var net = NetworkManager.init(gpa, &loop, &core, id);
    defer net.deinit();

    var rwc = try ReadWriteCloser.init(gpa, &core, mtu);
    defer rwc.deinit();

    var app = App{ .gpa = gpa, .net = &net, .rwc = &rwc, .tun = null };
    net.on_deliver = App.onDeliverTrampoline;
    net.on_deliver_ud = &app;
    net.on_discover = App.onDiscoverTrampoline;
    net.on_discover_ud = &app;

    // -- TUN setup ------------------------------------------------------
    var tun_adapter: ?TunAdapter = null;
    if (!std.mem.eql(u8, tun_name, "none")) {
        tun_adapter = TunAdapter.init(tun_name, "", @intCast(mtu)) catch |err| blk: {
            std.debug.print("[ygg] warning: failed to create TUN device ({}); continuing without TUN (mesh routing still active)\n", .{err});
            break :blk null;
        };
        if (tun_adapter) |*t| {
            node.tun.assignAddress(gpa, std.mem.sliceTo(&t.name, 0), addr, @intCast(mtu)) catch |err| {
                std.debug.print("[ygg] warning: failed to assign TUN address ({}); configure manually with `ip`\n", .{err});
            };
            std.debug.print("status: tun device '{s}' up\n", .{std.mem.sliceTo(&t.name, 0)});
        }
    } else {
        std.debug.print("status: tun disabled (--tun none)\n", .{});
    }

    var tun_io: ?TunIo = null;
    if (tun_adapter) |*t| {
        tun_io = TunIo{ .app = &app, .fd = t.fd, .file = xev.File.initFd(t.fd) };
        app.tun = &tun_io.?;
        tun_io.?.file.read(&loop, &tun_io.?.read_completion, .{ .slice = &tun_io.?.read_buf }, TunIo, &tun_io.?, TunIo.onRead);
    }

    // -- Peers / listeners ------------------------------------------------
    for (effective_peers.items) |peer_uri| {
        net.addOutboundPeer(peer_uri, .{ .password = password }) catch |err| {
            std.debug.print("[ygg] failed to configure peer {s}: {}\n", .{ peer_uri, err });
        };
    }
    for (effective_listen.items) |listen_uri| {
        net.addListener(listen_uri) catch |err| {
            std.debug.print("[ygg] failed to listen on {s}: {}\n", .{ listen_uri, err });
        };
    }

    if (admin_listen.len > 0) {
        std.debug.print("status: admin socket configured for {s} (not yet wired up)\n", .{admin_listen});
    }

    std.debug.print("status: running (press Ctrl+C to stop)\n", .{});

    // -- Maintenance timer --------------------------------------------------
    var maint_timer = try xev.Timer.init();
    defer maint_timer.deinit();
    var maint_completion: xev.Completion = undefined;
    var maint_ctx = MaintenanceCtx{ .net = &net, .timer = &maint_timer };
    maint_timer.run(&loop, &maint_completion, MAINTENANCE_INTERVAL_MS, MaintenanceCtx, &maint_ctx, MaintenanceCtx.onTick);

    try loop.run(.until_done);
}

// ---------------------------------------------------------------------------
// genconf / normaliseconf output
// ---------------------------------------------------------------------------

fn emitConfig(gpa: std.mem.Allocator, io: std.Io, cfg: *const Config, json_output: bool, maybe_path: ?[]const u8, no_replace: bool) !void {
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();

    if (json_output) {
        try emitConfigJson(&w.writer, cfg);
    } else {
        try cfg.writeToml(&w.writer);
    }

    const bytes = w.written();
    if (maybe_path) |path| {
        if (no_replace) {
            if (std.Io.Dir.cwd().access(io, path, .{})) |_| {
                std.debug.print("{s} already exists; not overwriting (--no-replace)\n", .{path});
                return;
            } else |_| {}
        }
        var file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        std.debug.print("wrote config to {s}\n", .{path});
    } else {
        std.debug.print("{s}\n", .{bytes});
    }
}

fn emitConfigJson(writer: *std.Io.Writer, cfg: *const Config) !void {
    try writer.writeAll("{\n");
    try writer.print("  \"private_key\": \"{s}\",\n", .{cfg.private_key});
    try writer.writeAll("  \"peers\": [");
    for (cfg.peers, 0..) |p, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{p});
    }
    try writer.writeAll("],\n");
    try writer.writeAll("  \"listen\": [");
    for (cfg.listen, 0..) |l, i| {
        if (i > 0) try writer.writeAll(", ");
        try writer.print("\"{s}\"", .{l});
    }
    try writer.writeAll("],\n");
    try writer.print("  \"admin_listen\": \"{s}\",\n", .{cfg.admin_listen});
    try writer.print("  \"if_name\": \"{s}\",\n", .{cfg.if_name});
    try writer.print("  \"if_mtu\": {d},\n", .{cfg.if_mtu});
    try writer.print("  \"node_info_privacy\": {},\n", .{cfg.node_info_privacy});
    try writer.print("  \"firewall\": {{ \"enable\": {} }}\n", .{cfg.firewall.enable});
    try writer.writeAll("}\n");
}

fn readFileAlloc(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const size = @as(usize, @intCast((try file.stat(io)).size));
    const buf = try gpa.alloc(u8, size);
    errdefer gpa.free(buf);
    var reader_buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &reader_buf);
    var total: usize = 0;
    while (total < size) {
        const n = try file_reader.interface.readSliceShort(buf[total..]);
        if (n == 0) break;
        total += n;
    }
    return gpa.realloc(buf, total);
}

fn readStdinAlloc(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(gpa);
    var stdin_buf: [4096]u8 = undefined;
    const stdin_file = std.Io.File.stdin();
    var stdin_reader = stdin_file.reader(io, &stdin_buf);
    while (true) {
        const chunk = stdin_reader.interface.take(4096) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (chunk.len == 0) break;
        try out.appendSlice(gpa, chunk);
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Maintenance / app plumbing (unchanged from earlier revisions)
// ---------------------------------------------------------------------------

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

const Action = enum { run, help, version };

const Cli = struct {
    action: Action = .run,

    // Config source selection.
    useconffile: ?[]const u8 = null,
    use_stdin_conf: bool = false,
    autoconf: bool = false,

    // genconf / normaliseconf.
    genconf: ??[]const u8 = null, // outer optional = "flag present"; inner = "FILE arg given"
    normaliseconf: bool = false,
    json_output: bool = false,
    no_replace: bool = false,

    // One-shot info queries.
    print_address: bool = false,
    print_subnet: bool = false,
    print_publickey: bool = false,
    exportkey: bool = false,

    // Runtime overrides.
    peers: std.ArrayListUnmanaged([]const u8) = .empty,
    listeners: std.ArrayListUnmanaged([]const u8) = .empty,
    tun_name: ?[]const u8 = null,
    mtu: ?u64 = null,
    password: []const u8 = &.{},
    admin_listen: ?[]const u8 = null,
    loglevel: []const u8 = "info",
    logto: []const u8 = "stdout",

    fn deinit(self: *Cli, gpa: std.mem.Allocator) void {
        self.peers.deinit(gpa);
        self.listeners.deinit(gpa);
    }
};

fn printUsage() void {
    std.debug.print(
        \\yggdrasil.zig -- an experimental async-Zig Yggdrasil mesh node
        \\
        \\Configuration:
        \\  -c, --useconffile FILE   Read TOML config from FILE
        \\      --useconf            Read TOML config from stdin
        \\  -g, --genconf [FILE]     Print (or save) a new default config
        \\  -n, --normaliseconf      With --useconf(file), print the config
        \\                           back out with all defaults filled in
        \\      --json               Emit --genconf/--normaliseconf as JSON
        \\      --no-replace         With --genconf FILE, don't overwrite an
        \\                           existing file
        \\      --autoconf           Ephemeral identity, no config file
        \\
        \\Info / one-shot:
        \\  -v, --version            Print version and exit
        \\  -a, --address            Print the IPv6 address and exit
        \\  -s, --subnet             Print the IPv6 subnet and exit
        \\  -k, --publickey          Print the hex public key and exit
        \\      --exportkey          Print the private key as hex and exit
        \\  -h, --help               Print this help and exit
        \\
        \\Runtime overrides (repeatable where noted):
        \\      --peer URI           Add an outbound peer (repeatable)
        \\      --listen URI         Add a listener (repeatable)
        \\      --tun NAME|auto|none TUN interface name (default: auto)
        \\      --mtu N              TUN MTU (default: 65535)
        \\      --password PW        Shared password for CLI-added peers
        \\      --admin-listen URI   Admin socket address ("" to disable)
        \\      --loglevel LEVEL     error|warn|info|debug (default: info)
        \\      --logto FILE|stdout  Log destination (default: stdout)
        \\
        \\Peer URI schemes: tcp://host:port, tls://host:port (real TLS 1.3
        \\via wolfSSL). Query params: ?key=HEX&password=PW&priority=N.
        \\
    , .{});
}

fn parseArgs(gpa: std.mem.Allocator, raw_args: std.process.Args) !Cli {
    var cli = Cli{};
    var args = std.process.Args.Iterator.init(raw_args);
    _ = args.next();

    while (args.next()) |arg| {
        if (eqAny(arg, &.{ "-h", "--help" })) {
            cli.action = .help;
        } else if (eqAny(arg, &.{ "-v", "--version" })) {
            cli.action = .version;
        } else if (eqAny(arg, &.{ "-c", "--useconffile" })) {
            cli.useconffile = args.next();
        } else if (std.mem.eql(u8, arg, "--useconf")) {
            cli.use_stdin_conf = true;
        } else if (std.mem.eql(u8, arg, "--autoconf")) {
            cli.autoconf = true;
        } else if (eqAny(arg, &.{ "-g", "--genconf" })) {
            // Optional trailing FILE argument: only consume it if present
            // and not itself another flag. `std.process.Args.Iterator` has
            // no `peek()`, but on POSIX it's a trivially-copyable index
            // into argv, so we can "peek" by copying, trying `next()`, and
            // restoring the copy if it turns out to be another flag.
            const saved = args;
            if (args.next()) |maybe_file| {
                if (maybe_file.len > 0 and maybe_file[0] != '-') {
                    cli.genconf = maybe_file;
                } else {
                    args = saved;
                    cli.genconf = @as(?[]const u8, null);
                }
            } else {
                cli.genconf = @as(?[]const u8, null);
            }
        } else if (eqAny(arg, &.{ "-n", "--normaliseconf" })) {
            cli.normaliseconf = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            cli.json_output = true;
        } else if (std.mem.eql(u8, arg, "--no-replace")) {
            cli.no_replace = true;
        } else if (eqAny(arg, &.{ "-a", "--address" })) {
            cli.print_address = true;
        } else if (eqAny(arg, &.{ "-s", "--subnet" })) {
            cli.print_subnet = true;
        } else if (eqAny(arg, &.{ "-k", "--publickey" })) {
            cli.print_publickey = true;
        } else if (std.mem.eql(u8, arg, "--exportkey")) {
            cli.exportkey = true;
        } else if (std.mem.eql(u8, arg, "--peer")) {
            if (args.next()) |v| try cli.peers.append(gpa, v);
        } else if (std.mem.eql(u8, arg, "--listen")) {
            if (args.next()) |v| try cli.listeners.append(gpa, v);
        } else if (std.mem.eql(u8, arg, "--tun")) {
            cli.tun_name = args.next();
        } else if (std.mem.eql(u8, arg, "--mtu")) {
            if (args.next()) |v| cli.mtu = std.fmt.parseInt(u64, v, 10) catch cli.mtu;
        } else if (std.mem.eql(u8, arg, "--password")) {
            if (args.next()) |v| cli.password = v;
        } else if (std.mem.eql(u8, arg, "--admin-listen")) {
            cli.admin_listen = args.next();
        } else if (std.mem.eql(u8, arg, "--loglevel")) {
            if (args.next()) |v| cli.loglevel = v;
        } else if (std.mem.eql(u8, arg, "--logto")) {
            if (args.next()) |v| cli.logto = v;
        }
    }
    return cli;
}

fn eqAny(arg: []const u8, options: []const []const u8) bool {
    for (options) |o| {
        if (std.mem.eql(u8, arg, o)) return true;
    }
    return false;
}
