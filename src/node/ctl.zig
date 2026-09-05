//! Control mode: drive a running node's admin socket from the command line.
//!
//! Turns a *second* `yggdrasil` invocation into an admin client:
//! `yggdrasil getSelf`, `yggdrasil getPeers`, `yggdrasil addPeer uri=tcp://…`
//! query the already-running daemon instead of starting one, keyed off the
//! presence of positional arguments. This module brings the same behaviour to
//! yggdrasil.zig, over the same wire protocol yggdrasil-go, and
//! this node's own `node.admin` module speak: one newline-terminated JSON
//! request in, one newline-terminated JSON reply out.
//!
//!     yggdrasil getSelf
//!     yggdrasil -e tcp://10.99.0.2:9001 getPeers
//!     yggdrasil --json getTree
//!     yggdrasil addPeer uri=tcp://example.org:1234
//!     yggdrasil getNodeInfo key=<64 hex chars>
//!
//! The endpoint accepts the same URIs as `--admin-listen`:
//!   tcp://host:port        (default tcp://localhost:9001)
//!   unix:///path/to.sock   (Unix-like targets only; `unix://@name` is an
//!                          abstract socket on Linux)
//!
//! `unix://` is *not* silently accepted on Windows: the platform's `AF_UNIX`
//! is a partial implementation (no abstract sockets, socket files need a
//! filesystem with reparse points, winsock support is missing on older
//! builds), so connecting would fail somewhere deeper with a worse message.
//! `node.unix_socket` owns that decision for the whole binary, so this module
//! asks it instead of growing a second platform switch of its own.

const std = @import("std");
const node = @import("node");

const Io = std.Io;
const net = Io.net;
const unix_socket = node.unix_socket;

pub const default_endpoint: []const u8 = "tcp://localhost:9001";
pub const default_port: u16 = 9001;

/// Biggest reply we will read. `getTree` on a well-connected node is the worst
/// case, and it is still only tens of kilobytes; 1 MiB leaves headroom
/// without pinning a big buffer for every invocation.
const reply_buffer_len: usize = 1024 * 1024;

/// Command results belong on stdout so they can be piped; diagnostics go to
/// stderr so they cannot be mistaken for the answer.
fn emitOut(comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(std.Options.debug_io, &buf);
    w.interface.print(fmt, args) catch return;
    w.interface.flush() catch return;
}

fn emitErr(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}

/// Run one control command and print its result. Returns an error when the
/// socket could not be reached or the reply could not be understood; a reply
/// that *was* understood but reports failure exits with status 1.
pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    endpoint: []const u8,
    command: []const u8,
    args: []const []const u8,
    json_output: bool,
) !void {
    var stream = connect(gpa, io, endpoint) catch |err| {
        emitErr("ctl: cannot reach admin socket {s}: {}\n", .{ endpoint, err });
        return err;
    };
    defer stream.close(io);

    const request = try buildRequest(gpa, command, args);
    defer gpa.free(request);

    // `Stream.Writer`/`Stream.Reader` are wrappers: the `std.Io.Writer` they
    // drive lives in `.interface`.
    var wbuf: [4096]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(request) catch |err| {
        emitErr("ctl: sending request to {s} failed: {}\n", .{ endpoint, err });
        return err;
    };
    w.interface.flush() catch |err| {
        emitErr("ctl: sending request to {s} failed: {}\n", .{ endpoint, err });
        return err;
    };

    // One reply document -- but not necessarily one reply *line*.
    // yggdrasil-go answers with `json.Encoder` + `SetIndent("", "  ")`, i.e.
    // pretty-printed over many lines, and this node mirrors it.
    var rbuf: [16384]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var reply = std.ArrayListUnmanaged(u8).empty;
    defer reply.deinit(gpa);
    var chunk: [8192]u8 = undefined;
    while (reply.items.len < reply_buffer_len) {
        const n = r.interface.readSliceShort(&chunk) catch |err| {
            emitErr("ctl: reading the reply from {s} failed: {}\n", .{ endpoint, err });
            return err;
        };
        if (n == 0) break; // peer closed: the document is complete by definition
        try reply.appendSlice(gpa, chunk[0..n]);
        if (std.json.parseFromSlice(std.json.Value, gpa, reply.items, .{})) |complete| {
            complete.deinit();
            break;
        } else |_| {} // partial: keep going
    }
    if (std.mem.trim(u8, reply.items, " \t\r\n").len == 0) {
        emitErr("ctl: empty response from {s}\n", .{endpoint});
        return error.EmptyResponse;
    }

    var parsed = std.json.parseFromSlice(std.json.Value, gpa, reply.items, .{}) catch |err| {
        emitErr("ctl: {s} sent a reply that is not JSON: {}\n", .{ endpoint, err });
        return err;
    };
    defer parsed.deinit();

    try printReply(gpa, command, parsed.value, json_output);
}

// ---------------------------------------------------------------------------
// endpoint parsing / connection
// ---------------------------------------------------------------------------

fn connect(gpa: std.mem.Allocator, io: Io, endpoint: []const u8) !net.Stream {
    if (std.mem.startsWith(u8, endpoint, "unix://")) {
        const rest = endpoint["unix://".len..];
        if (comptime !unix_socket.supported) {
            unix_socket.reportUnsupported("admin endpoint", endpoint);
            return error.Unsupported;
        }
        // `unix://@name` is an abstract socket; std represents those by a
        // leading NUL byte in the path, while the URI spells it with `@`
        // (the same convention `unix_socket.Address.init` uses for links).
        const path = if (rest.len > 0 and rest[0] == '@')
            try std.fmt.allocPrint(gpa, "\x00{s}", .{rest[1..]})
        else
            rest;
        defer if (path.ptr != rest.ptr) gpa.free(path);

        const ua = try net.UnixAddress.init(path);
        return net.UnixAddress.connect(&ua, io);
    }

    const rest = if (std.mem.startsWith(u8, endpoint, "tcp://"))
        endpoint["tcp://".len..]
    else
        endpoint;
    if (rest.len == 0) {
        emitErr("ctl: empty admin endpoint\n", .{});
        return error.InvalidEndpoint;
    }

    const hp = try splitHostPort(rest);
    const addr = try net.IpAddress.resolve(io, hp.host, hp.port);
    return net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp });
}

/// Split `host:port`, honouring a bracketed IPv6 literal (`[::1]:9001`) and
/// defaulting the port when it is absent. A bare IPv6 literal without
/// brackets is ambiguous with `host:port` and is read as host + port, which is
/// why the bracketed form exists.
fn splitHostPort(text: []const u8) !struct { host: []const u8, port: u16 } {
    if (text[0] == '[') {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse {
            emitErr("ctl: malformed address `{s}` (missing `]`)\n", .{text});
            return error.InvalidEndpoint;
        };
        const host = text[1..close];
        const after = text[close + 1 ..];
        if (after.len == 0) return .{ .host = host, .port = default_port };
        if (after[0] != ':') {
            emitErr("ctl: malformed address `{s}`\n", .{text});
            return error.InvalidEndpoint;
        }
        return .{ .host = host, .port = try parsePort(after[1..]) };
    }
    if (std.mem.lastIndexOfScalar(u8, text, ':')) |i| {
        if (i + 1 == text.len) return .{ .host = text[0..i], .port = default_port };
        return .{ .host = text[0..i], .port = try parsePort(text[i + 1 ..]) };
    }
    return .{ .host = text, .port = default_port };
}

fn parsePort(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10) catch {
        emitErr("ctl: `{s}` is not a port number\n", .{text});
        return error.InvalidEndpoint;
    };
}

// ---------------------------------------------------------------------------
// request / reply rendering
// ---------------------------------------------------------------------------

/// `{"request":"…","arguments":{…},"keepalive":false}\n`, written directly as
/// text: the request has a fixed shape, so there is nothing to gain from
/// building a `std.json.Value` tree just to serialise it again.
fn buildRequest(gpa: std.mem.Allocator, command: []const u8, args: []const []const u8) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(gpa);
    errdefer w.deinit();
    const jw = &w.writer;

    try jw.writeAll("{\"request\":");
    try std.json.Stringify.encodeJsonString(command, .{}, jw);
    try jw.writeAll(",\"arguments\":{");
    var first = true;
    for (args) |kv| {
        if (!first) try jw.writeByte(',');
        first = false;
        if (std.mem.indexOfScalar(u8, kv, '=')) |i| {
            try std.json.Stringify.encodeJsonString(kv[0..i], .{}, jw);
            try jw.writeByte(':');
            try std.json.Stringify.encodeJsonString(kv[i + 1 ..], .{}, jw);
        } else {
            // A bare word (`getNodeInfo 0011…`) still has to produce valid
            // JSON, so it is sent as a boolean argument rather than dropped.
            try std.json.Stringify.encodeJsonString(kv, .{}, jw);
            try jw.writeAll(":true");
        }
    }
    try jw.writeAll("},\"keepalive\":false}\n");
    return w.toOwnedSlice();
}

fn printReply(gpa: std.mem.Allocator, command: []const u8, reply: std.json.Value, json_output: bool) !void {
    if (json_output) {
        const text = try std.json.Stringify.valueAlloc(gpa, reply, .{ .whitespace = .indent_2 });
        defer gpa.free(text);
        emitOut("{s}\n", .{text});
        return;
    }

    const status = strOf(field(reply, "status"));
    if (status.len == 0 or !std.ascii.eqlIgnoreCase(status, "success")) {
        const err_text = strOf(field(reply, "error"));
        emitErr("Error: {s}\n", .{if (err_text.len > 0) err_text else status});
        std.process.exit(1);
    }

    const data = field(reply, "response") orelse {
        // Successful but payload-free, e.g. `addPeer`.
        emitOut("OK\n", .{});
        return;
    };

    const lower = try std.ascii.allocLowerString(gpa, command);
    defer gpa.free(lower);

    if (std.mem.eql(u8, lower, "list")) return printList(data);
    if (std.mem.eql(u8, lower, "getself")) return printSelf(data);
    if (std.mem.eql(u8, lower, "getpeers")) return printPeers(data);
    if (std.mem.eql(u8, lower, "getsessions")) return printSessions(data);

    const text = try std.json.Stringify.valueAlloc(gpa, data, .{ .whitespace = .indent_2 });
    defer gpa.free(text);
    emitOut("{s}\n", .{text});
}

/// `list` is the one reply whose shape differs between implementations that
/// still speak the same protocol: this node return an
/// array of `{command, description, fields}` objects.
fn printList(data: std.json.Value) !void {
    const list = field(data, "list") orelse return;
    if (list != .array) return;
    const items = list.array;
    emitOut("Available commands:\n", .{});
    for (items.items) |item| {
        if (item == .string) {
            emitOut("  {s}\n", .{item.string});
            continue;
        }
        const name = strOf(field(item, "command"));
        if (name.len == 0) continue;
        const desc = strOf(field(item, "description"));
        if (field(item, "fields")) |f| {
            if (f == .array and f.array.items.len > 0) {
                var args = std.ArrayListUnmanaged(u8).empty;
                defer args.deinit(std.heap.smp_allocator);
                for (f.array.items, 0..) |a, i| {
                    if (i != 0) args.appendSlice(std.heap.smp_allocator, ", ") catch {};
                    args.appendSlice(std.heap.smp_allocator, strOf(a)) catch {};
                }
                emitOut("  {s} {s}\n", .{ pad(30, name), desc });
                emitOut("      arguments: {s}\n", .{args.items});
                continue;
            }
        }
        emitOut("  {s} {s}\n", .{ pad(30, name), desc });
    }
}

fn printSelf(data: std.json.Value) !void {
    const Row = struct { label: []const u8, key: []const u8 };
    const rows = [_]Row{
        .{ .label = "Build name", .key = "build_name" },
        .{ .label = "Build version", .key = "build_version" },
        .{ .label = "Public key", .key = "key" },
        .{ .label = "IPv6 address", .key = "address" },
        .{ .label = "IPv6 subnet", .key = "subnet" },
        .{ .label = "Coordinates", .key = "coordinates" },
        .{ .label = "Routing entries", .key = "routing_entries" },
    };
    for (rows) |row| {
        if (field(data, row.key)) |v| {
            switch (v) {
                .string => emitOut("{s}: {s}\n", .{ pad(16, row.label), v.string }),
                else => {
                    var buf: [32]u8 = undefined;
                    emitOut("{s}: {s}\n", .{ pad(16, row.label), numStr(&buf, v) });
                },
            }
        }
    }
}

fn printPeers(data: std.json.Value) !void {
    const list = field(data, "peers") orelse return;
    if (list != .array) return;
    const peers = list.array;
    if (peers.items.len == 0) {
        emitOut("No peers connected.\n", .{});
        return;
    }
    emitOut("{s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s}\n", .{
        pad(34, "URI"), pad(6, "State"), pad(4, "Dir"), pad(30, "IP Address"),
        pad(9, "Latency"), pad(6, "Cost"), pad(8, "Uptime"), pad(9, "RX"),
        pad(9, "TX"), pad(11, "RX Rate"), pad(11, "TX Rate"), pad(3, "Pr"),
        pad(20, "Last Error"),
    });
    for (peers.items) |peer| {
        var lat: [16]u8 = undefined;
        var up: [16]u8 = undefined;
        var rx: [16]u8 = undefined;
        var tx: [16]u8 = undefined;
        var rxr: [20]u8 = undefined;
        var txr: [20]u8 = undefined;
        var cost: [16]u8 = undefined;
        var prio: [8]u8 = undefined;
        // `remote` is the field name yggdrasil-go uses for the peer URI.
        const uri = strOf(field(peer, "remote") orelse field(peer, "uri"));
        const is_up = boolOf(field(peer, "up"));
        const inbound = boolOf(field(peer, "inbound"));
        // yggdrasil-go serialises `time.Duration`, i.e. nanoseconds.
        const latency_ms = asF64(field(peer, "latency")) / 1_000_000.0;
        emitOut("{s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s} {s}\n", .{
            pad(34, uri),
            pad(6, if (is_up) "Up" else "Down"),
            pad(4, if (inbound) "In" else "Out"),
            pad(30, strOf(field(peer, "address"))),
            pad(9, if (latency_ms > 0) (std.fmt.bufPrint(&lat, "{d:.1}ms", .{latency_ms}) catch "-") else "-"),
            pad(6, numStr(&cost, field(peer, "cost"))),
            pad(8, uptimeStr(&up, asF64(field(peer, "uptime")))),
            pad(9, bytesStr(&rx, asF64(field(peer, "bytes_recvd")))),
            pad(9, bytesStr(&tx, asF64(field(peer, "bytes_sent")))),
            pad(11, rateStr(&rxr, asF64(field(peer, "rate_recvd")))),
            pad(11, rateStr(&txr, asF64(field(peer, "rate_sent")))),
            pad(3, numStr(&prio, field(peer, "priority"))),
            pad(20, strOf(field(peer, "last_error"))),
        });
    }
}

fn printSessions(data: std.json.Value) !void {
    const list = field(data, "sessions") orelse return;
    if (list != .array) return;
    const sessions = list.array;
    if (sessions.items.len == 0) {
        emitOut("No sessions established.\n", .{});
        return;
    }
    emitOut("{s} {s} {s} {s} {s} {s} {s}\n", .{
        pad(30, "IP Address"), pad(9, "Latency"), pad(8, "Uptime"),
        pad(9, "RX"), pad(9, "TX"), pad(11, "RX Rate"), pad(11, "TX Rate"),
    });
    for (sessions.items) |s| {
        var lat: [16]u8 = undefined;
        var up: [16]u8 = undefined;
        var rx: [16]u8 = undefined;
        var tx: [16]u8 = undefined;
        var rxr: [20]u8 = undefined;
        var txr: [20]u8 = undefined;
        const latency_ms = asF64(field(s, "latency")) / 1_000_000.0;
        emitOut("{s} {s} {s} {s} {s} {s} {s}\n", .{
            pad(30, strOf(field(s, "address"))),
            pad(9, if (latency_ms > 0) (std.fmt.bufPrint(&lat, "{d:.1}ms", .{latency_ms}) catch "-") else "-"),
            pad(8, uptimeStr(&up, asF64(field(s, "uptime")))),
            pad(9, bytesStr(&rx, asF64(field(s, "bytes_recvd")))),
            pad(9, bytesStr(&tx, asF64(field(s, "bytes_sent")))),
            pad(11, rateStr(&rxr, asF64(field(s, "rate_recvd")))),
            pad(11, rateStr(&txr, asF64(field(s, "rate_sent")))),
        });
    }
}

// ---------------------------------------------------------------------------
// JSON + formatting helpers
// ---------------------------------------------------------------------------

fn field(v: std.json.Value, key: []const u8) ?std.json.Value {
    return switch (v) {
        .object => |o| o.get(key),
        else => null,
    };
}

fn strOf(v: ?std.json.Value) []const u8 {
    return switch (v orelse return "") {
        .string => |s| s,
        else => "",
    };
}

fn boolOf(v: ?std.json.Value) bool {
    return switch (v orelse return false) {
        .bool => |b| b,
        else => false,
    };
}

fn asF64(v: ?std.json.Value) f64 {
    return switch (v orelse return 0) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .bool => |b| if (b) 1 else 0,
        else => 0,
    };
}

/// Render a numeric JSON value without a decimal point when it is a whole
/// number, so `routing_entries: 5` does not print as `5.0`.
fn numStr(buf: []u8, v: ?std.json.Value) []const u8 {
    const x = v orelse return "";
    return switch (x) {
        .integer => |i| std.fmt.bufPrint(buf, "{d}", .{i}) catch "",
        .float => |f| std.fmt.bufPrint(buf, "{d}", .{f}) catch "",
        .string => |s| s,
        else => "",
    };
}

fn uptimeStr(buf: []u8, seconds: f64) []const u8 {
    const total: u64 = @intFromFloat(@max(seconds, 0));
    const d = total / 86400;
    const h = (total % 86400) / 3600;
    const m = (total % 3600) / 60;
    const s = total % 60;
    return if (d > 0)
        std.fmt.bufPrint(buf, "{d}d{d}h", .{ d, h }) catch "-"
    else if (h > 0)
        std.fmt.bufPrint(buf, "{d}h{d}m", .{ h, m }) catch "-"
    else if (m > 0)
        std.fmt.bufPrint(buf, "{d}m{d}s", .{ m, s }) catch "-"
    else
        std.fmt.bufPrint(buf, "{d}s", .{s}) catch "-";
}

fn bytesStr(buf: []u8, n: f64) []const u8 {
    if (n <= 0) return "-";
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    var value = n;
    var unit: usize = 0;
    while (value >= 1024 and unit + 1 < units.len) : (unit += 1) value /= 1024;
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch "-";
}

fn rateStr(buf: []u8, bytes_per_second: f64) []const u8 {
    if (bytes_per_second <= 0) return "-";
    const units = [_][]const u8{ "B/s", "KiB/s", "MiB/s", "GiB/s" };
    var value = bytes_per_second;
    var unit: usize = 0;
    while (value >= 1024 and unit + 1 < units.len) : (unit += 1) value /= 1024;
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ value, units[unit] }) catch "-";
}

/// Left-align `s` in a fixed-width field. Table columns are padded by hand
/// rather than through `std.fmt`'s fill/alignment so the widths stay next to
/// the headers they belong to.
fn pad(comptime width: usize, s: []const u8) [width]u8 {
    var out: [width]u8 = @splat(' ');
    const n = @min(s.len, width);
    @memcpy(out[0..n], s[0..n]);
    return out;
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test "endpoint parsing" {
    const testing = std.testing;

    const v4 = try splitHostPort("127.0.0.1:9001");
    try testing.expectEqualStrings("127.0.0.1", v4.host);
    try testing.expectEqual(@as(u16, 9001), v4.port);

    const v6 = try splitHostPort("[200:1::2]:1234");
    try testing.expectEqualStrings("200:1::2", v6.host);
    try testing.expectEqual(@as(u16, 1234), v6.port);

    const no_port = try splitHostPort("localhost");
    try testing.expectEqualStrings("localhost", no_port.host);
    try testing.expectEqual(default_port, no_port.port);

    try testing.expectError(error.InvalidEndpoint, splitHostPort("[::1"));
    try testing.expectError(error.InvalidEndpoint, splitHostPort("host:http"));
}

test "request encoding" {
    const testing = std.testing;
    const gpa = testing.allocator;

    const plain = try buildRequest(gpa, "getSelf", &.{});
    defer gpa.free(plain);
    try testing.expectEqualStrings("{\"request\":\"getSelf\",\"arguments\":{},\"keepalive\":false}\n", plain);

    const with_args = try buildRequest(gpa, "addPeer", &.{"uri=tcp://example.org:1234"});
    defer gpa.free(with_args);
    try testing.expectEqualStrings(
        "{\"request\":\"addPeer\",\"arguments\":{\"uri\":\"tcp://example.org:1234\"},\"keepalive\":false}\n",
        with_args,
    );

    // A quoted value has to survive as a single JSON string.
    const quoted = try buildRequest(gpa, "addPeer", &.{"uri=tcp://a\"b:1"});
    defer gpa.free(quoted);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, quoted[0 .. quoted.len - 1], .{});
    defer parsed.deinit();
    const uri = parsed.value.object.get("arguments").?.object.get("uri").?;
    try testing.expectEqualStrings("tcp://a\"b:1", uri.string);
}

test "number and duration rendering" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;

    try testing.expectEqualStrings("5", numStr(&buf, .{ .integer = 5 }));
    try testing.expectEqualStrings("", numStr(&buf, null));
    try testing.expectEqualStrings("1m1s", uptimeStr(&buf, 61.4));
    try testing.expectEqualStrings("1m1s", uptimeStr(&buf, 61.9));
    try testing.expectEqualStrings("42s", uptimeStr(&buf, 42.7));
    try testing.expectEqualStrings("2h0m", uptimeStr(&buf, 7200));
    try testing.expectEqualStrings("3d4h", uptimeStr(&buf, 3 * 86400 + 4 * 3600));
    try testing.expectEqualStrings("1.0 KiB", bytesStr(&buf, 1024));
    try testing.expectEqualStrings("-", bytesStr(&buf, 0));
    try testing.expectEqualStrings("1.5 KiB/s", rateStr(&buf, 1536));
}

test "padding" {
    try std.testing.expectEqualStrings("ab        ", pad(10, "ab")[0..]);
    try std.testing.expectEqualStrings("abcdefghij", pad(10, "abcdefghijklmn")[0..]);
}
