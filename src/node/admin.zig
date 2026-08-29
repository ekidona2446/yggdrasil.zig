//! Admin JSON socket -- the Zig counterpart of yggdrasil-go's `src/admin`.
//!
//! Everything here is byte-checked against a running reference node: the reply
//! envelope, the two-space indentation, which fields `omitempty` hides, the
//! exact error strings and the exact `list` table (see `tests/README.md` for the
//! capture harness). Details that are easy to get wrong and are *not* obvious
//! from a glance at the Go source:
//!
//!   * The reply is written with `json.Encoder.SetIndent("", "  ")`: Go first
//!     marshals the whole response compactly and then re-indents it.
//!     `writeIndentJson` is a port of `encoding/json.appendIndent`, including
//!     the deferred-indent trick that keeps `{}`/`[]` on one line.
//!   * `response` has no `omitempty`, so failures carry `"response": null`.
//!   * `request` is echoed even when the handler failed, but *not* when the
//!     request itself could not be decoded -- then Go reports `{"request":""}`,
//!     with `arguments` missing entirely, because `AdminSocketRequest` is only
//!     assigned to the response after a successful unmarshal.
//!   * Unknown *top-level* fields are ignored: `DisallowUnknownFields()` is set
//!     on the decoder, but the decoder only produces a `json.RawMessage`.
//!   * Byte counters are plain numbers. `admin.DataUnit` is a `uint64` with a
//!     `String()` method and *no* `MarshalJSON`, so the human-readable form
//!     only ever reaches `yggdrasilctl`'s pretty printer, never the wire. The
//!     `DataUnit` below is kept for that printer.
//!   * `uptime` is a `float64` of seconds; `latency` and `last_error_time` are
//!     `time.Duration`, i.e. integer nanoseconds.
//!   * Peer sorting mirrors Go's comparators literally, including their
//!     `int(a - b)` truncations, which make sub-second uptime differences
//!     compare equal.

const std = @import("std");
const xev = @import("xev");
const ironwood = @import("ironwood");
const node = @import("node.zig");
const timemod = @import("util").time;

const Core = node.core.Core;
const PublicKey = ironwood.PublicKey;

/// `version.BuildName()`. A plain `go build` of the reference reports
/// "unknown" because these are injected with `-ldflags` by `./build`; release
/// binaries report "Yggdrasil", which is what we put here.
pub const BUILD_NAME: []const u8 = "Yggdrasil";
pub const BUILD_VERSION: []const u8 = node.version.VERSION_STRING;

// ---------------------------------------------------------------------------
// JSON primitives
// ---------------------------------------------------------------------------

/// `encoding/json` string escaping: control bytes as `\u00XX`, `"`/`\`
/// escaped, and -- unlike most encoders -- `<`, `>` and `&` escaped as
/// `\u003C` etc. (`json.Marshal`'s HTML escaping, which `json.Encoder` keeps by
/// default). Forward slashes are *not* escaped, U+2028/U+2029 are not either.
pub fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            '<' => try w.writeAll("\\u003c"),
            '>' => try w.writeAll("\\u003e"),
            '&' => try w.writeAll("\\u0026"),
            else => {
                if (c < 0x20) {
                    try w.print("\\u{x:0>4}", .{c});
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeByte('"');
}

/// A 32-byte key as the lowercase hex string the reference uses everywhere.
fn writeJsonHexKey(w: *std.Io.Writer, key: *const PublicKey) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (key) |b| try w.print("{x:0>2}", .{b});
    try w.writeByte('"');
}

/// `net.IP.String()` for a 16-byte address: RFC 5952 (longest run of >= 2 zero
/// groups collapses to `::`, ties won by the leftmost run). Deliberately not a
/// second implementation -- `node.address.formatIpv6` is what the TUN and DNS
/// paths use, so an address can only ever be rendered one way.
fn writeIpv6(w: *std.Io.Writer, bytes: *const [16]u8) std.Io.Writer.Error!void {
    try node.address.formatIpv6(bytes, w);
}

fn ipv6ToString(bytes: *const [16]u8, buf: []u8) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    try writeIpv6(&w, bytes);
    return buf[0..w.end];
}

/// `core.Subnet()` is a `*net.IPNet`, so its `String()` carries the prefix
/// length -- `301:eed8:6175:2345::/64`, not a bare address.
fn subnetToString(bytes: *const [8]u8, buf: []u8) ![]u8 {
    var full: [16]u8 = [_]u8{0} ** 16;
    @memcpy(full[0..8], bytes);
    var w = std.Io.Writer.fixed(buf);
    try writeIpv6(&w, &full);
    try w.writeAll("/64");
    return buf[0..w.end];
}

/// A `float64` as Go's JSON encoder writes it: the shortest decimal that
/// round-trips, with no `.0` for integral values. Zig's `{d}` agrees with Go for
/// every value produced here (seconds of uptime); Go would switch to exponent
/// form above ~1e21, a magnitude no uptime or byte count reaches.
fn writeGoNumber(w: *std.Io.Writer, v: f64) std.Io.Writer.Error!void {
    if (std.math.isNan(v) or std.math.isInf(v)) return w.writeAll("0");
    try w.print("{d}", .{v});
}

/// `admin.DataUnit`, kept for `yggdrasilctl`'s text output: `String()` is
/// `%2.1f<unit>` for 100 bytes and up, `%dB` below. The JSON API sends these
/// values as numbers, so nothing in this module uses it for the wire.
pub const DataUnit = struct {
    value: u64 = 0,

    pub fn write(self: DataUnit, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const v: f64 = @floatFromInt(self.value);
        const k: f64 = 1024.0;
        const m = k * 1024.0;
        const g = m * 1024.0;
        const t = g * 1024.0;
        if (self.value >= 1024 * 1024 * 1024 * 1024) {
            return writeGoFloat(w, v / t, "TB");
        } else if (self.value >= 1024 * 1024 * 1024) {
            return writeGoFloat(w, v / g, "GB");
        } else if (self.value >= 1024 * 1024) {
            return writeGoFloat(w, v / m, "MB");
        } else if (self.value >= 100) {
            return writeGoFloat(w, v / k, "KB");
        } else {
            return w.print("{d}B", .{self.value});
        }
    }

    pub fn string(self: DataUnit) ![]u8 {
        var buf: [32]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try self.write(&w);
        return buf[0..w.end];
    }
};

/// `%2.1f`: one decimal place, right-padded to a minimum width of two. The
/// formatted number is never shorter than three characters, so the padding is
/// unreachable -- which is why `0.1KB` has no leading space.
fn writeGoFloat(w: *std.Io.Writer, v: f64, suffix: []const u8) std.Io.Writer.Error!void {
    var buf: [40]u8 = undefined;
    const num = std.fmt.bufPrint(&buf, "{d:.1}", .{v}) catch "0.0";
    if (num.len < 2) try w.writeByte(' ');
    try w.writeAll(num);
    try w.writeAll(suffix);
}

/// Re-marshal a parsed value the way Go's `json.Marshal` does: compact, object
/// keys sorted. Used for the `arguments` echo, where Go re-marshals what it
/// decoded rather than reprinting the request text.
pub fn compactJson(gpa: std.mem.Allocator, w: *std.Io.Writer, v: std.json.Value) !void {
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .integer => |i| try w.print("{d}", .{i}),
        .float => |f| try writeGoNumber(w, f),
        .number_string => |s| try w.writeAll(s),
        .string => |s| try writeJsonString(w, s),
        .array => |arr| {
            try w.writeByte('[');
            for (arr.items, 0..) |item, i| {
                if (i != 0) try w.writeByte(',');
                try compactJson(gpa, w, item);
            }
            try w.writeByte(']');
        },
        .object => |o| {
            try w.writeByte('{');
            var keys = std.ArrayListUnmanaged([]const u8).empty;
            defer keys.deinit(gpa);
            var it = o.iterator();
            while (it.next()) |entry| try keys.append(gpa, entry.key_ptr.*);
            std.sort.block([]const u8, keys.items, {}, struct {
                fn less(ctx: void, a: []const u8, b: []const u8) bool {
                    _ = ctx;
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.less);
            for (keys.items, 0..) |k, i| {
                if (i != 0) try w.writeByte(',');
                try writeJsonString(w, k);
                try w.writeByte(':');
                try compactJson(gpa, w, o.get(k).?);
            }
            try w.writeByte('}');
        },
    }
}

/// `encoding/hex`'s `isHex`, spelled out so the checks can share it.
fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

/// JSON whitespace, exactly as `encoding/json` defines it.
fn isJsSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// Index just past the JSON value that starts at or after `from`, null if the
/// text is malformed. The document has already been parsed successfully, so this
/// only has to be careful about strings and nesting, not validate.
fn jsonValueEnd(text: []const u8, from: usize) ?usize {
    var i = from;
    while (i < text.len and isJsSpace(text[i])) i += 1;
    if (i >= text.len) return null;
    switch (text[i]) {
        '{', '[' => {
            var depth: usize = 0;
            var in_str = false;
            var esc = false;
            var k = i;
            while (k < text.len) : (k += 1) {
                const c = text[k];
                if (in_str) {
                    if (esc) {
                        esc = false;
                    } else if (c == '\\') {
                        esc = true;
                    } else if (c == '"') {
                        in_str = false;
                    }
                    continue;
                }
                if (c == '"') {
                    in_str = true;
                } else if (c == '{' or c == '[') {
                    depth += 1;
                } else if (c == '}' or c == ']') {
                    if (depth == 0) return null;
                    depth -= 1;
                    if (depth == 0) return k + 1;
                }
            }
            return null;
        },
        '"' => {
            var k = i + 1;
            var esc = false;
            while (k < text.len) : (k += 1) {
                if (esc) {
                    esc = false;
                } else if (text[k] == '\\') {
                    esc = true;
                } else if (text[k] == '"') return k + 1;
            }
            return null;
        },
        else => {
            var k = i;
            while (k < text.len and (std.ascii.isAlphanumeric(text[k]) or text[k] == '-' or text[k] == '+' or text[k] == '.')) k += 1;
            return if (k == i) null else k;
        },
    }
}

/// Byte range of the value of a top-level member of a JSON object.
fn jsonMemberSpan(text: []const u8, want: []const u8) ?struct { start: usize, end: usize } {
    var i = jsonValueEnd(text, 0) orelse return null;
    if (text.len == 0 or text[0] != '{') {
        // Leading whitespace is allowed, so step over it first.
        var j: usize = 0;
        while (j < text.len and isJsSpace(text[j])) j += 1;
        if (j >= text.len or text[j] != '{') return null;
        i = j + 1;
    } else {
        i = 1;
    }
    while (true) {
        while (i < text.len and (isJsSpace(text[i]) or text[i] == ',')) i += 1;
        if (i >= text.len) return null;
        if (text[i] == '}') return null;
        if (text[i] != '"') return null;
        const key_end = jsonValueEnd(text, i) orelse return null;
        // Key names are compared as written: an escaped key (`"\u0061"`) is a
        // valid spelling that this does not resolve, and the caller then falls
        // back to re-serialising the parsed value.
        const key = text[i + 1 .. key_end - 1];
        var k = key_end;
        while (k < text.len and isJsSpace(text[k])) k += 1;
        if (k >= text.len or text[k] != ':') return null;
        const val_end = jsonValueEnd(text, k + 1) orelse return null;
        const val_start = blk: {
            var v = k + 1;
            while (v < text.len and isJsSpace(text[v])) v += 1;
            break :blk v;
        };
        if (std.mem.eql(u8, key, want)) return .{ .start = val_start, .end = val_end };
        i = val_end;
    }
}

/// Go's `compact` over a `json.RawMessage`: drop the whitespace between tokens and
/// escape `<`, `>`, `&`, U+2028 and U+2029, and copy everything else -- including
/// the inside of strings -- verbatim.
fn compactRaw(w: *std.Io.Writer, src: []const u8) !void {
    var in_str = false;
    var esc = false;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const c = src[i];
        if (in_str) {
            if (c == '<') {
                try w.writeAll("\\u003c");
            } else if (c == '>') {
                try w.writeAll("\\u003e");
            } else if (c == '&') {
                try w.writeAll("\\u0026");
            } else if (c == 0xE2 and i + 2 < src.len and src[i + 1] == 0x80 and (src[i + 2] & 0xFE) == 0xA8) {
                // U+2028 / U+2029, the two code points `json.Marshal` escapes on
                // top of the HTML-sensitive ones.
                try w.writeAll(if ((src[i + 2] & 0x01) == 0) "\\u2028" else "\\u2029");
                i += 2;
            } else {
                try w.writeByte(c);
            }
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (isJsSpace(c)) continue;
        if (c == '"') in_str = true;
        try w.writeByte(c);
    }
}

/// Go's `json.UnmarshalTypeError.Value` name for a JSON kind, as it appears in
/// `json: cannot unmarshal X into ...`.
fn jsonKind(v: std.json.Value) []const u8 {
    return switch (v) {
        .array => "array",
        .object => "object",
        .string => "string",
        .bool => "bool",
        .integer, .float, .number_string => "number",
        .null => "null",
    };
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub const Command = enum {
    list,
    debug_remote_get_peers,
    debug_remote_get_self,
    debug_remote_get_tree,
    get_multicast_interfaces,
    get_node_info,
    get_paths,
    get_peers,
    get_self,
    get_sessions,
    get_tree,
    get_tun,
    add_peer,
    remove_peer,
};

pub const HandlerSpec = struct {
    /// The registered name, lower-cased: `AddHandler` keys its map with
    /// `strings.ToLower(name)` and `list` reports the map *key*, so a Go node
    /// answers `getSelf` but lists it as `getself`.
    name: []const u8,
    desc: []const u8,
    args: []const []const u8 = &.{},
    cmd: Command,
};

/// The table a reference node reports, byte-sorted the way `list` sorts it
/// (`strings.Compare` on the command name).
pub const HANDLERS = [_]HandlerSpec{
    .{ .name = "addpeer", .desc = "Add a peer to the peer list", .args = &.{ "uri", "interface" }, .cmd = .add_peer },
    .{ .name = "debug_remotegetpeers", .desc = "Debug use only", .args = &.{"key"}, .cmd = .debug_remote_get_peers },
    .{ .name = "debug_remotegetself", .desc = "Debug use only", .args = &.{"key"}, .cmd = .debug_remote_get_self },
    .{ .name = "debug_remotegettree", .desc = "Debug use only", .args = &.{"key"}, .cmd = .debug_remote_get_tree },
    .{ .name = "getmulticastinterfaces", .desc = "Show which interfaces multicast is enabled on", .cmd = .get_multicast_interfaces },
    .{ .name = "getnodeinfo", .desc = "Request nodeinfo from a remote node by its public key", .args = &.{"key"}, .cmd = .get_node_info },
    .{ .name = "getpaths", .desc = "Show established paths through this node", .cmd = .get_paths },
    .{ .name = "getpeers", .desc = "Show directly connected peers", .args = &.{"sort"}, .cmd = .get_peers },
    .{ .name = "getself", .desc = "Show details about this node", .cmd = .get_self },
    .{ .name = "getsessions", .desc = "Show established traffic sessions with remote nodes", .cmd = .get_sessions },
    .{ .name = "gettree", .desc = "Show known Tree entries", .cmd = .get_tree },
    .{ .name = "gettun", .desc = "Show information about the node's TUN interface", .cmd = .get_tun },
    .{ .name = "list", .desc = "List available commands", .cmd = .list },
    .{ .name = "removepeer", .desc = "Remove a peer from the peer list", .args = &.{ "uri", "interface" }, .cmd = .remove_peer },
};

fn commandFromName(lowered: []const u8) ?Command {
    for (HANDLERS) |h| {
        if (std.mem.eql(u8, lowered, h.name)) return h.cmd;
    }
    return null;
}

comptime {
    // `list` sorts with `strings.Compare`, so the table has to be in byte order
    // or our reply order would differ from the reference's.
    for (HANDLERS[1..], 0..) |h, i| {
        if (std.mem.order(u8, HANDLERS[i].name, h.name) != .lt) {
            @compileError("HANDLERS must be sorted by name");
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors the admin socket can report. The URI-related ones are the network
/// layer's own, so a peering failure surfaces with the reference's wording.
pub const AdminError = node.network.LinkError || error{
    FailedToFindRequest,
    FailedToUnmarshalRequest,
    NoRequestSpecified,
    UnknownAction,
    TimedOut,
    NoRemoteKey,
    InvalidKeyHex,
    InvalidKeyLength,
    NotAvailable,
    OutOfMemory,
    WriteFailed,
};

/// `err.Error()`, i.e. the text that lands in the `"error"` field. These are
/// `src/core/link.go`'s `linkError` constants and `src/admin/*.go`'s literal
/// messages.
fn errorText(e: AdminError) []const u8 {
    return switch (e) {
        error.FailedToFindRequest => "failed to find request",
        error.FailedToUnmarshalRequest => "failed to unmarshal request",
        error.NoRequestSpecified => "no request specified",
        error.UnknownAction => "unknown action",
        error.PeerExists => "peer is already configured",
        error.PeerNotFound => "peer is not configured",
        error.PriorityInvalid => "priority value is invalid",
        error.PinnedKeyInvalid => "pinned public key is invalid",
        error.PasswordInvalid => "invalid password supplied",
        error.MaxBackoffInvalid => "max backoff duration invalid",
        error.UnsupportedSNI => "SNI not supported on this link type",
        error.NoSuitableIPs => "peer has no suitable addresses",
        error.ConnectedToSelf => "node cannot connect to self",
        error.UnknownScheme => "link schema unknown",
        error.InvalidURI => "unable to parse peering URI",
        error.ResolveFailed => "failed to resolve",
        error.ConnectFailed => "failed to connect",
        error.NotSupported => "not supported",
        error.NotAvailable => "not available",
        error.WriteFailed => "failed to marshal response",
        error.TimedOut => "timed out waiting for response",
        error.NoRemoteKey => "no remote public key supplied",
        error.InvalidKeyHex => "failed to decode public key",
        error.InvalidKeyLength => "invalid public key length",
        error.OutOfMemory => "out of memory",
    };
}

// ---------------------------------------------------------------------------
// Extension points (TUN, multicast, remote debug, peering)
// ---------------------------------------------------------------------------

pub const RemoteDebug = enum { get_self, get_peers, get_tree };

/// Everything `AdminSocket` cannot reach on its own: the TUN adapter, the
/// multicast module, the in-band (session `proto`) requests and the dialer.
pub const Hooks = struct {
    /// `uri`/`sintf` are the `AddPeerRequest` fields verbatim; the caller owns
    /// them, so a hook that keeps them must copy them (the network layer does).
    add_peer: ?*const fn (ctx: *anyopaque, uri: []const u8, sintf: []const u8) AdminError!void = null,
    remove_peer: ?*const fn (ctx: *anyopaque, uri: []const u8, sintf: []const u8) AdminError!void = null,
    /// `NodeInfo` this node would report about itself, as a JSON object.
    node_info: ?*const fn (ctx: *anyopaque) []const u8 = null,
    tun: ?*const fn (ctx: *anyopaque, out: *std.Io.Writer) AdminError!void = null,
    multicast_interfaces: ?*const fn (ctx: *anyopaque, out: *std.Io.Writer) AdminError!void = null,
    /// `getNodeInfo` for a remote key: the reply JSON object, `{"<hex key>":
    /// {...}}`, i.e. what Go re-marshals a `map[string]json.RawMessage` into.
    remote_node_info: ?*const fn (ctx: *anyopaque, key: *const PublicKey, out: *std.Io.Writer) AdminError!void = null,
    /// `debug_remoteGetSelf`/`GetPeers`/`GetTree`, same in-band transport.
    remote_debug: ?*const fn (ctx: *anyopaque, kind: RemoteDebug, key: *const PublicKey, out: *std.Io.Writer) AdminError!void = null,
    ctx: *anyopaque = undefined,
};

// ---------------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------------

pub const AdminSocket = struct {
    core: *Core,
    net: ?*node.network.NetworkManager = null,
    gpa: std.mem.Allocator,
    hooks: Hooks = .{},
    /// Verbatim `error` text for the current reply, for the Go messages that
    /// embed the offending value (an error code cannot carry that). Set and
    /// consumed within one `handleRequest` call.
    err_text: []const u8 = "",
    err_buf: [256]u8 = undefined,

    pub fn init(gpa: std.mem.Allocator, core: *Core) AdminSocket {
        return .{ .core = core, .gpa = gpa };
    }

    /// The decoded request, re-emitted the way `AdminSocketRequest` marshals.
    const Request = struct {
        name: []const u8 = "",
        /// The compacted `arguments` text. Null only when Go never got as far as
        /// assigning `resp.Request` (a request that could not be decoded), which
        /// is what makes `omitempty` hide the field in the echo.
        arguments: ?[]const u8 = null,
    };

    /// Handle one request. The reply is allocator-owned and newline-terminated;
    /// the caller frees it.
    pub fn handleRequest(self: *AdminSocket, line: []const u8) ![]u8 {
        self.err_text = "";

        // Go decodes into a `json.RawMessage` first, so a document that is not
        // valid JSON fails with "failed to find request"; one that is valid but
        // not a request object fails with "failed to unmarshal request". Both
        // happen before `resp.Request` is assigned, so neither echoes anything.
        var doc = std.json.parseFromSlice(std.json.Value, self.gpa, line, .{
            .duplicate_field_behavior = .use_last,
        }) catch return self.renderError(error.FailedToFindRequest, null, null);
        defer doc.deinit();

        if (doc.value != .object) return self.renderError(error.FailedToUnmarshalRequest, null, null);
        const obj = doc.value.object;

        var name: ?[]const u8 = null;
        var arguments: ?std.json.Value = null;
        var keepalive = false;
        var it = obj.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, "request")) {
                if (entry.value_ptr.* != .string) return self.renderError(error.FailedToUnmarshalRequest, null, null);
                name = entry.value_ptr.string;
            } else if (std.mem.eql(u8, entry.key_ptr.*, "arguments")) {
                arguments = entry.value_ptr.*;
            } else if (std.mem.eql(u8, entry.key_ptr.*, "keepalive")) {
                if (entry.value_ptr.* != .bool) return self.renderError(error.FailedToUnmarshalRequest, null, null);
                keepalive = entry.value_ptr.bool;
            }
            // Anything else is ignored: `DisallowUnknownFields()` was set on the
            // `json.RawMessage` decode, where it has no effect.
        }

        // `arguments` defaults to `{}` (`req.Arguments = []byte("{}")` before the
        // decode). The echo is the *caller's own bytes* compacted, not a
        // re-serialisation of the parsed value: Go marshals a `json.RawMessage`
        // with `compact`, which preserves key order, `\u` escapes and the exact
        // spelling of numbers. Handlers are given the same text, so what a handler
        // saw and what the echo shows can never disagree.
        var args_buf = std.Io.Writer.Allocating.initCapacity(self.gpa, 256) catch return error.OutOfMemory;
        defer args_buf.deinit();
        if (arguments) |a| {
            if (jsonMemberSpan(line, "arguments")) |span| {
                compactRaw(&args_buf.writer, line[span.start..span.end]) catch return error.OutOfMemory;
            } else {
                // A key spelled with escapes (`"\u0061rguments"`) is a real member
                // of the object but has no name we can match textually, so fall
                // back to re-serialising the parsed value.
                compactJson(self.gpa, &args_buf.writer, a) catch return error.OutOfMemory;
            }
        }
        if (args_buf.written().len == 0) args_buf.writer.writeAll("{}") catch return error.OutOfMemory;
        const args_text = args_buf.written();

        const nm = name orelse "";
        const req = Request{ .name = nm, .arguments = args_text };
        if (nm.len == 0) return self.renderError(error.NoRequestSpecified, req, keepalive);

        // Handlers are keyed by the lower-cased name, and the "unknown action"
        // message quotes that lower-cased name, not what was sent.
        var lower: [64]u8 = undefined;
        const lowered: []const u8 = if (nm.len <= lower.len) std.ascii.lowerString(&lower, nm) else nm;
        const cmd = commandFromName(lowered) orelse {
            const msg = std.fmt.allocPrint(self.gpa, "unknown action '{s}', try 'list' for help", .{lowered}) catch return error.OutOfMemory;
            defer self.gpa.free(msg);
            self.err_text = msg;
            return self.renderError(error.UnknownAction, req, keepalive);
        };

        var body = std.Io.Writer.Allocating.initCapacity(self.gpa, 8192) catch return error.OutOfMemory;
        defer body.deinit();
        const r: AdminError!void = switch (cmd) {
            .list => self.listBody(&body.writer),
            .get_self => self.getSelfBody(&body.writer, args_text),
            .get_peers => self.getPeersBody(&body.writer, args_text),
            .get_tree => self.getTreeBody(&body.writer, args_text),
            .get_paths => self.getPathsBody(&body.writer, args_text),
            .get_sessions => self.getSessionsBody(&body.writer, args_text),
            .get_tun => self.getTunBody(&body.writer, args_text),
            .get_multicast_interfaces => self.getMulticastInterfacesBody(&body.writer, args_text),
            .add_peer => self.peerMutationBody(&body.writer, args_text, true),
            .remove_peer => self.peerMutationBody(&body.writer, args_text, false),
            .get_node_info => self.getNodeInfoBody(&body.writer, args_text),
            .debug_remote_get_self => self.remoteDebugBody(&body.writer, args_text, .get_self),
            .debug_remote_get_peers => self.remoteDebugBody(&body.writer, args_text, .get_peers),
            .debug_remote_get_tree => self.remoteDebugBody(&body.writer, args_text, .get_tree),
        };
        r catch |e| return self.renderError(e, req, keepalive);

        return self.renderSuccess(&req, keepalive, body.written());
    }

    /// Whether the reply was for a `keepalive: true` request, i.e. whether the
    /// connection must stay open for the next one.
    pub fn isKeepalive(self: *AdminSocket, line: []const u8) bool {
        var doc = std.json.parseFromSlice(std.json.Value, self.gpa, line, .{ .ignore_unknown_fields = true }) catch return false;
        defer doc.deinit();
        if (doc.value != .object) return false;
        const v = doc.value.object.get("keepalive") orelse return false;
        return v == .bool and v.bool;
    }

    // -- envelope ------------------------------------------------------

    fn renderSuccess(self: *AdminSocket, req: *const Request, keepalive: bool, body: []const u8) ![]u8 {
        var out = std.Io.Writer.Allocating.initCapacity(self.gpa, body.len + 256) catch return error.OutOfMemory;
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeAll("{\"status\":\"success\",\"request\":");
        try self.writeRequest(w, req, keepalive);
        try w.writeAll(",\"response\":");
        try w.writeAll(body);
        try w.writeAll("}");
        // The indented copy is independent of the compact buffer, so the temp
        // writer is released here (`errdefer` alone would leak every reply).
        const res = indentAlloc(self.gpa, out.written()) catch out.toOwnedSlice();
        out.deinit();
        return res;
    }

    fn renderError(self: *AdminSocket, err: AdminError, req: ?Request, keepalive: ?bool) ![]u8 {
        var out = std.Io.Writer.Allocating.initCapacity(self.gpa, 256) catch return error.OutOfMemory;
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeAll("{\"status\":\"error\",\"error\":");
        try writeJsonString(w, if (self.err_text.len > 0) self.err_text else errorText(err));
        try w.writeAll(",\"request\":");
        if (req) |r| {
            try self.writeRequest(w, &r, keepalive orelse false);
        } else {
            // `resp.Request` was never assigned: the zero value has a nil
            // `json.RawMessage`, and `omitempty` hides it.
            try w.writeAll("{\"request\":\"\"}");
        }
        // `response` has no `omitempty` in Go, so a failure always shows null.
        try w.writeAll(",\"response\":null}");
        const res = indentAlloc(self.gpa, out.written()) catch out.toOwnedSlice();
        out.deinit();
        return res;
    }

    fn writeRequest(self: *AdminSocket, w: *std.Io.Writer, req: *const Request, keepalive: bool) !void {
        _ = self;
        try w.writeAll("{\"request\":");
        try writeJsonString(w, req.name);
        if (req.arguments) |a| {
            try w.writeAll(",\"arguments\":");
            try w.writeAll(a);
        }
        if (keepalive) try w.writeAll(",\"keepalive\":true");
        try w.writeAll("}");
    }

    /// Set the reply's `error` text verbatim and return the code to propagate.
    fn setErr(self: *AdminSocket, comptime fmt: []const u8, args: anytype, comptime e: AdminError) AdminError {
        self.err_text = std.fmt.bufPrint(&self.err_buf, fmt, args) catch "";
        return e;
    }

    // -- commands ------------------------------------------------------

    fn listBody(self: *AdminSocket, w: *std.Io.Writer) AdminError!void {
        _ = self;
        try w.writeAll("{\"list\":[");
        for (HANDLERS, 0..) |h, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll("{\"command\":");
            try writeJsonString(w, h.name);
            try w.writeAll(",\"description\":");
            try writeJsonString(w, h.desc);
            if (h.args.len > 0) { // `fields,omitempty`
                try w.writeAll(",\"fields\":[");
                for (h.args, 0..) |a, j| {
                    if (j != 0) try w.writeByte(',');
                    try writeJsonString(w, a);
                }
                try w.writeByte(']');
            }
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }

    fn getSelfBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        try self.requireArgs(arguments, "admin.GetSelfRequest");
        const info = node.core.getSelfInfo(self.core);
        // `GetSelfResponse`: build_name, build_version, key, address,
        // routing_entries, subnet.
        try w.writeAll("{\"build_name\":");
        try writeJsonString(w, BUILD_NAME);
        try w.writeAll(",\"build_version\":");
        try writeJsonString(w, BUILD_VERSION);
        try w.writeAll(",\"key\":");
        try writeJsonHexKey(w, &info.key);
        var buf: [64]u8 = undefined;
        try w.writeAll(",\"address\":");
        try writeJsonString(w, try ipv6ToString(&self.core.address.bytes, &buf));
        try w.writeAll(",\"routing_entries\":");
        try w.print("{d}", .{info.routing_entries});
        try w.writeAll(",\"subnet\":");
        var sbuf: [80]u8 = undefined;
        try writeJsonString(w, try subnetToString(&self.core.subnet.bytes, &sbuf));
        try w.writeByte('}');
    }

    fn getPeersBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        var sort_buf: [64]u8 = undefined;
        var sort_by: []const u8 = "";
        var args = try self.parseArgsObject(arguments, "admin.GetPeersRequest");
        defer args.deinit();
        if (args.value.object.get("sort")) |v| {
            if (v != .string) return self.setErr("json: cannot unmarshal {s} into Go struct field GetPeersRequest.sort of type string", .{jsonKind(v)}, error.FailedToUnmarshalRequest);
            sort_by = std.fmt.bufPrint(&sort_buf, "{s}", .{v.string}) catch sort_buf[0..0];
        }

        const nm = self.net orelse return error.NotAvailable;
        const peers = try nm.snapshotPeers(self.gpa);
        defer nm.freePeerSnapshot(self.gpa, peers);

        sortPeers(peers, sort_by);

        try w.writeAll("{\"peers\":[");
        for (peers, 0..) |p, i| {
            if (i != 0) try w.writeByte(',');
            try writePeerEntry(w, p);
        }
        try w.writeAll("]}");
    }

    fn getTreeBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        try self.requireArgs(arguments, "admin.GetTreeRequest");
        const entries = try node.core.getTreeInfo(self.core, self.gpa);
        defer self.gpa.free(entries);
        // Sorted by the hex key string, like the reference.
        std.sort.block(node.core.TreeEntryInfo, entries, {}, struct {
            fn less(ctx: void, a: node.core.TreeEntryInfo, b: node.core.TreeEntryInfo) bool {
                _ = ctx;
                return keyLess(a.key, b.key);
            }
        }.less);
        try w.writeAll("{\"tree\":[");
        for (entries, 0..) |e, i| {
            if (i != 0) try w.writeByte(',');
            var buf: [64]u8 = undefined;
            // TreeEntry: address, key, parent, sequence.
            try w.writeAll("{\"address\":");
            try writeJsonString(w, try ipv6ToString(&node.addrForKey(&e.key).bytes, &buf));
            try w.writeAll(",\"key\":");
            try writeJsonHexKey(w, &e.key);
            try w.writeAll(",\"parent\":");
            try writeJsonHexKey(w, &e.parent);
            try w.writeAll(",\"sequence\":");
            try w.print("{d}", .{e.sequence});
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }

    fn getPathsBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        try self.requireArgs(arguments, "admin.GetPathsRequest");
        const paths = try node.core.getPathsInfo(self.core, self.gpa);
        defer node.core.freePathEntryList(self.gpa, paths);
        std.sort.block(node.core.PathEntryInfo, paths, {}, struct {
            fn less(ctx: void, a: node.core.PathEntryInfo, b: node.core.PathEntryInfo) bool {
                _ = ctx;
                return keyLess(a.key, b.key);
            }
        }.less);
        try w.writeAll("{\"paths\":[");
        for (paths, 0..) |p, i| {
            if (i != 0) try w.writeByte(',');
            var buf: [64]u8 = undefined;
            // PathEntry: address, key, path, sequence.
            try w.writeAll("{\"address\":");
            try writeJsonString(w, try ipv6ToString(&node.addrForKey(&p.key).bytes, &buf));
            try w.writeAll(",\"key\":");
            try writeJsonHexKey(w, &p.key);
            try w.writeAll(",\"path\":[");
            for (p.path, 0..) |port, j| {
                if (j != 0) try w.writeByte(',');
                try w.print("{d}", .{port});
            }
            try w.writeByte(']');
            try w.writeAll(",\"sequence\":");
            try w.print("{d}", .{p.sequence});
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }

    fn getSessionsBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        try self.requireArgs(arguments, "admin.GetSessionsRequest");
        const sessions = try node.core.getSessions(self.core);
        defer self.gpa.free(sessions);
        std.sort.block(node.core.SessionInfo, sessions, {}, struct {
            fn less(ctx: void, a: node.core.SessionInfo, b: node.core.SessionInfo) bool {
                _ = ctx;
                return keyLess(a.key, b.key);
            }
        }.less);
        try w.writeAll("{\"sessions\":[");
        for (sessions, 0..) |s, i| {
            if (i != 0) try w.writeByte(',');
            var buf: [64]u8 = undefined;
            // SessionEntry: address, key, bytes_recvd, bytes_sent, uptime.
            try w.writeAll("{\"address\":");
            try writeJsonString(w, try ipv6ToString(&node.addrForKey(&s.key).bytes, &buf));
            try w.writeAll(",\"key\":");
            try writeJsonHexKey(w, &s.key);
            try w.writeAll(",\"bytes_recvd\":");
            try w.print("{d}", .{s.rx});
            try w.writeAll(",\"bytes_sent\":");
            try w.print("{d}", .{s.tx});
            try w.writeAll(",\"uptime\":");
            try writeGoNumber(w, secondsSince(s.since_ns));
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }

    fn getTunBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        try self.requireArgs(arguments, "tun.GetTUNRequest");
        if (self.hooks.tun) |f| return f(self.hooks.ctx, w);
        // `GetTUNResponse` has `enabled` only; name/mtu are `omitempty` and the
        // reference leaves them unset when no interface was created.
        try w.writeAll("{\"enabled\":false}");
    }

    fn getMulticastInterfacesBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        try self.requireArgs(arguments, "multicast.GetMulticastInterfacesRequest");
        if (self.hooks.multicast_interfaces) |f| return f(self.hooks.ctx, w);
        try w.writeAll("{\"multicast_interfaces\":[]}");
    }

    /// `add` is comptime so the Go struct name in a type error can be picked
    /// without building the message at runtime.
    fn peerMutationBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8, comptime add: bool) AdminError!void {
        const req_name = if (add) "AddPeerRequest" else "RemovePeerRequest";
        var args = try self.parseArgsObject(arguments, "admin." ++ req_name);
        defer args.deinit();
        // An absent `uri` is the empty string in Go, and `url.Parse("")`
        // succeeds, so an empty URI is rejected by the *scheme* check.
        const uri = args.value.object.get("uri") orelse std.json.Value{ .string = "" };
        if (uri != .string) return self.setErr("json: cannot unmarshal {s} into Go struct field " ++ req_name ++ ".uri of type string", .{jsonKind(uri)}, error.FailedToUnmarshalRequest);
        const sintf_v = args.value.object.get("interface") orelse std.json.Value{ .string = "" };
        if (sintf_v != .string) return self.setErr("json: cannot unmarshal {s} into Go struct field " ++ req_name ++ ".interface of type string", .{jsonKind(sintf_v)}, error.FailedToUnmarshalRequest);
        // The parsed JSON is released when this function returns, so both strings
        // are copied into storage that outlives the call.
        var uri_buf: [512]u8 = undefined;
        var sintf_buf: [64]u8 = undefined;
        if (uri.string.len > uri_buf.len or sintf_v.string.len > sintf_buf.len) return error.InvalidURI;
        @memcpy(uri_buf[0..uri.string.len], uri.string);
        @memcpy(sintf_buf[0..sintf_v.string.len], sintf_v.string);
        const uri_text = uri_buf[0..uri.string.len];
        const sintf = sintf_buf[0..sintf_v.string.len];

        const nm = self.net orelse return error.NotAvailable;
        _ = node.network.parsePeerURI(uri_text) catch |e| {
            // `e` here is a runtime capture, so the error code has to be
            // spelled out for `setErr`'s comptime parameter.
            if (e == error.InvalidURI) return self.setErr("unable to parse peering URI: parse \"{s}\": invalid URI for request", .{uri_text}, error.InvalidURI);
            return e;
        };

        if (add) {
            if (self.hooks.add_peer) |f| {
                try f(self.hooks.ctx, uri_text, sintf);
            } else {
                try nm.addOutboundPeer(uri_text, .{ .sintf = sintf });
            }
        } else {
            if (self.hooks.remove_peer) |f| {
                try f(self.hooks.ctx, uri_text, sintf);
            } else {
                try nm.removeOutboundPeer(uri_text, sintf);
            }
        }
        // `AddPeerResponse`/`RemovePeerResponse` are empty structs.
        try w.writeAll("{}");
    }

    fn getNodeInfoBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8) AdminError!void {
        const key_text = try self.parseKeyArg(arguments, "core.GetNodeInfoRequest", "GetNodeInfoRequest") orelse return error.NoRemoteKey;
        const key = try self.decodeKeyHex(key_text);
        var remote = std.Io.Writer.Allocating.initCapacity(self.gpa, 1024) catch return error.OutOfMemory;
        defer remote.deinit();
        const f = self.hooks.remote_node_info orelse return error.NotAvailable;
        try f(self.hooks.ctx, &key, &remote.writer);
        // `GetNodeInfoResponse` is a `map[string]json.RawMessage` keyed by the
        // hex key of the node that answered.
        try w.writeByte('{');
        try writeJsonHexKey(w, &key);
        try w.writeByte(':');
        try w.writeAll(remote.written());
        try w.writeByte('}');
    }

    /// `debug_remoteGetSelf`/`GetPeers`/`GetTree`. Unlike `getNodeInfo` these do
    /// not check for an empty key: it decodes to zero bytes and fails the length
    /// check instead. `kind` is comptime so the Go type names in argument errors
    /// are resolved at compile time.
    fn remoteDebugBody(self: *AdminSocket, w: *std.Io.Writer, arguments: []const u8, comptime kind: RemoteDebug) AdminError!void {
        const suffix = switch (kind) {
            .get_self => "GetSelf",
            .get_peers => "GetPeers",
            .get_tree => "GetTree",
        };
        const key_text = try self.parseKeyArg(arguments, "core.Debug" ++ suffix ++ "Request", "Debug" ++ suffix ++ "Request") orelse
            return error.InvalidKeyLength;
        const key = try self.decodeKeyHex(key_text);
        const f = self.hooks.remote_debug orelse return error.NotAvailable;
        try f(self.hooks.ctx, kind, &key, w);
    }

    /// `{key:"..."}`, shared by `getNodeInfo` and the debug handlers: in Go they
    /// all unmarshal a struct with one string field and hex-decode it. False
    /// means no key was supplied, which `getNodeInfo` reports as
    /// `no remote public key supplied`.
    fn parseKeyArg(self: *AdminSocket, arguments: []const u8, comptime type_name: []const u8, comptime field_name: []const u8) AdminError!?[]const u8 {
        var args = try self.parseArgsObject(arguments, type_name);
        defer args.deinit();
        const v = args.value.object.get("key") orelse return null;
        if (v != .string) return self.setErr("json: cannot unmarshal {s} into Go struct field " ++ field_name ++ ".key of type string", .{jsonKind(v)}, error.FailedToUnmarshalRequest);
        if (v.string.len == 0) return null;
        return v.string;
    }

    /// `encoding/hex`'s failure wordings. Go wraps them as
    /// `failed to decode public key: <inner>`, and they outrank the 32-byte
    /// length check, which the caller does afterwards.
    fn hexDecodeErr(self: *AdminSocket, text: []const u8) AdminError {
        if (text.len % 2 != 0) return self.setErr("failed to decode public key: encoding/hex: odd length hex string", .{}, error.InvalidKeyHex);
        for (text) |c| {
            if (isHexDigit(c)) continue;
            // `hex.InvalidByteError` prints the byte as a rune, so 0x7f and below
            // are quoted as characters and everything else as an escape.
            if (c >= 0x20 and c < 0x7f) return self.setErr("failed to decode public key: encoding/hex: invalid byte: U+{X:0>4} '{c}'", .{ c, c }, error.InvalidKeyHex);
            return self.setErr("failed to decode public key: encoding/hex: invalid byte: U+{X:0>4} '\\x{x:0>2}'", .{ c, c }, error.InvalidKeyHex);
        }
        return error.InvalidKeyHex;
    }

    /// Decode a hex public key: every byte must be a hex digit and the length must
    /// be exactly 32 bytes, in that order.
    fn decodeKeyHex(self: *AdminSocket, text: []const u8) AdminError!PublicKey {
        var out: PublicKey = undefined;
        // Go decodes into a buffer sized from the input, so an odd length or a
        // non-hex byte is a decode error whatever the length turns out to be, and
        // only after that does it check that the result is 32 bytes.
        for (text) |c| {
            if (!isHexDigit(c)) return self.hexDecodeErr(text);
        }
        if (text.len % 2 != 0) return self.hexDecodeErr(text);
        if (text.len / 2 != out.len) return error.InvalidKeyLength;
        _ = std.fmt.hexToBytes(&out, text) catch return error.InvalidKeyHex;
        return out;
    }

    /// A handler whose request struct has no fields still decodes the arguments:
    /// `[]` or `"x"` is a type error in Go even though nothing is read out of it,
    /// and the message names the (empty) struct type.
    fn requireArgs(self: *AdminSocket, arguments: []const u8, comptime type_name: []const u8) AdminError!void {
        var args = try self.parseArgsObject(arguments, type_name);
        args.deinit();
    }

    /// Decode the arguments to a JSON object. `null` is accepted -- Go's
    /// `Unmarshal(null, &struct)` is a no-op -- and anything else that is not an
    /// object reproduces Go's type error text, which is what a user of
    /// `yggdrasilctl` sees when they pass e.g. `sort=1` to a string field.
    fn parseArgsObject(self: *AdminSocket, arguments: []const u8, comptime type_name: []const u8) AdminError!std.json.Parsed(std.json.Value) {
        var parsed = std.json.parseFromSlice(std.json.Value, self.gpa, arguments, .{}) catch
            return self.setErr("json: cannot unmarshal end-object into Go value of type {s}", .{type_name}, error.FailedToUnmarshalRequest);
        errdefer parsed.deinit();
        switch (parsed.value) {
            // `"arguments":null` is a no-op for Go's decoder, so every field
            // keeps its zero value; an empty object models that and saves every
            // handler from re-checking for `.null`.
            .null => {
                parsed.value = .{ .object = .{} };
                return parsed;
            },
            .object => return parsed,
            else => |v| return self.setErr("json: cannot unmarshal {s} into Go value of type {s}", .{ jsonKind(v), type_name }, error.FailedToUnmarshalRequest),
        }
    }
};

/// `admin.PeerEntry`, in Go's field-declaration order with Go's `omitempty`
/// rules on each field.
fn writePeerEntry(w: *std.Io.Writer, p: node.network.PeerSnapshot) !void {
    try w.writeByte('{');
    if (p.uri.len > 0) { // `remote,omitempty`
        try w.writeAll("\"remote\":");
        try writeJsonString(w, p.uri);
        try w.writeByte(',');
    }
    try w.writeAll("\"up\":"); // booleans and port/priority/cost have no omitempty
    try w.writeAll(if (p.up) "true" else "false");
    try w.writeAll(",\"inbound\":");
    try w.writeAll(if (p.inbound) "true" else "false");
    if (p.address_len > 0) { // `address,omitempty`
        try w.writeAll(",\"address\":");
        try writeJsonString(w, p.address[0..p.address_len]);
    }
    try w.writeAll(",\"key\":"); // no omitempty: an unidentified link shows ""
    if (p.has_key) {
        try writeJsonHexKey(w, &p.key);
    } else {
        try w.writeAll("\"\"");
    }
    try w.writeAll(",\"port\":");
    try w.print("{d}", .{p.port});
    try w.writeAll(",\"priority\":");
    try w.print("{d}", .{p.priority});
    try w.writeAll(",\"cost\":");
    try w.print("{d}", .{p.cost});
    try writeDataUnitField(w, "bytes_recvd", p.rx_bytes);
    try writeDataUnitField(w, "bytes_sent", p.tx_bytes);
    try writeDataUnitField(w, "rate_recvd", p.rx_rate);
    try writeDataUnitField(w, "rate_sent", p.tx_rate);
    if (p.uptime_ns != 0) { // `uptime,omitempty`
        try w.writeAll(",\"uptime\":");
        try writeGoNumber(w, @as(f64, @floatFromInt(p.uptime_ns)) / std.time.ns_per_s);
    }
    if (p.latency_ns != 0) { // `latency,omitempty` (only copied when > 0)
        try w.writeAll(",\"latency\":");
        try w.print("{d}", .{p.latency_ns});
    }
    if (p.last_error_age_ns != 0) { // `last_error_time,omitempty`
        try w.writeAll(",\"last_error_time\":");
        try w.print("{d}", .{p.last_error_age_ns});
    }
    if (p.last_error.len > 0) { // `last_error,omitempty`
        try w.writeAll(",\"last_error\":");
        try writeJsonString(w, p.last_error);
    }
    try w.writeByte('}');
}

fn writeDataUnitField(w: *std.Io.Writer, name: []const u8, v: u64) !void {
    if (v == 0) return; // `omitempty` on a DataUnit (uint64) hides zero
    try w.writeByte(',');
    try w.writeByte('"');
    try w.writeAll(name);
    try w.writeAll("\":");
    try w.print("{d}", .{v});
}

// ---------------------------------------------------------------------------
// Sorting, mirroring `src/admin/getpeers.go` literally
// ---------------------------------------------------------------------------

fn keyLess(a: PublicKey, b: PublicKey) bool {
    // Go compares the hex strings; fixed-length lowercase hex orders the same
    // as the raw bytes it encodes.
    return std.mem.order(u8, &a, &b) == .lt;
}

/// Go's `int(a - b)` on `uint64`: wrapping subtraction, sign-extended.
fn u64Cmp(a: u64, b: u64) i64 {
    return @bitCast(a -% b);
}

/// Go's `int(a.Uptime - b.Uptime)` on `float64`: truncated towards zero, so two
/// uptimes less than a second apart compare equal.
fn f64Cmp(a: f64, b: f64) i64 {
    const d = a - b;
    if (!(d != 0)) return 0;
    const t = @trunc(d);
    if (t >= 9.2e18) return std.math.maxInt(i64);
    if (t <= -9.2e18) return std.math.minInt(i64);
    return @intFromFloat(t);
}

fn peerUptime(p: node.network.PeerSnapshot) f64 {
    return @as(f64, @floatFromInt(p.uptime_ns)) / std.time.ns_per_s;
}

/// Default: outbound peers first, then key, priority, cost, uptime.
fn cmpDefault(a: node.network.PeerSnapshot, b: node.network.PeerSnapshot) i64 {
    if (!a.inbound and b.inbound) return -1;
    if (a.inbound and !b.inbound) return 1;
    if (keyLess(a.key, b.key)) return -1;
    if (keyLess(b.key, a.key)) return 1;
    const prio = u64Cmp(a.priority, b.priority);
    if (prio != 0) return prio;
    const cost = u64Cmp(a.cost, b.cost);
    if (cost != 0) return cost;
    return f64Cmp(peerUptime(a), peerUptime(b));
}

fn cmpCost(a: node.network.PeerSnapshot, b: node.network.PeerSnapshot) i64 {
    const cost = u64Cmp(a.cost, b.cost);
    if (cost != 0) return cost;
    if (keyLess(a.key, b.key)) return -1;
    if (keyLess(b.key, a.key)) return 1;
    const prio = u64Cmp(a.priority, b.priority);
    if (prio != 0) return prio;
    return f64Cmp(peerUptime(a), peerUptime(b));
}

fn cmpUptime(a: node.network.PeerSnapshot, b: node.network.PeerSnapshot) i64 {
    const up = f64Cmp(peerUptime(a), peerUptime(b));
    if (up != 0) return up;
    if (keyLess(a.key, b.key)) return -1;
    if (keyLess(b.key, a.key)) return 1;
    const prio = u64Cmp(a.priority, b.priority);
    if (prio != 0) return prio;
    return u64Cmp(a.cost, b.cost);
}

fn sortPeers(peers: []node.network.PeerSnapshot, sort_by: []const u8) void {
    var lower: [16]u8 = undefined;
    // `strings.ToLower(req.SortBy)`, and anything unknown falls into the
    // default comparator.
    const key = if (sort_by.len <= lower.len) std.ascii.lowerString(&lower, sort_by) else sort_by;
    // `slices.SortStableFunc` is stable, so ties keep the input order, which
    // matters because Go's input order comes from a map walk; `std.sort.block`
    // is the stable sort to match it with.
    if (std.mem.eql(u8, key, "uptime")) {
        std.sort.block(node.network.PeerSnapshot, peers, {}, struct {
            fn less(ctx: void, a: node.network.PeerSnapshot, b: node.network.PeerSnapshot) bool {
                _ = ctx;
                return cmpUptime(a, b) < 0;
            }
        }.less);
    } else if (std.mem.eql(u8, key, "cost")) {
        std.sort.block(node.network.PeerSnapshot, peers, {}, struct {
            fn less(ctx: void, a: node.network.PeerSnapshot, b: node.network.PeerSnapshot) bool {
                _ = ctx;
                return cmpCost(a, b) < 0;
            }
        }.less);
    } else {
        std.sort.block(node.network.PeerSnapshot, peers, {}, struct {
            fn less(ctx: void, a: node.network.PeerSnapshot, b: node.network.PeerSnapshot) bool {
                _ = ctx;
                return cmpDefault(a, b) < 0;
            }
        }.less);
    }
}

fn secondsSince(since_ns: u64) f64 {
    const now = timemod.monotonicNanos();
    const delta = if (now > since_ns) now - since_ns else 0;
    return @as(f64, @floatFromInt(delta)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

// ---------------------------------------------------------------------------
// Indentation: json.Encoder.SetIndent("", "  ")
// ---------------------------------------------------------------------------

pub fn indentAlloc(gpa: std.mem.Allocator, compact: []const u8) ![]u8 {
    var out = std.Io.Writer.Allocating.initCapacity(gpa, compact.len * 2 + 64) catch return error.OutOfMemory;
    errdefer out.deinit();
    try writeIndentJson(&out.writer, compact);
    return out.toOwnedSlice();
}

/// Port of `encoding/json.appendIndent` with `prefix=""`, `indent="  "`.
///
/// Two rules make this differ from a naive pretty-printer, and both are visible
/// in real replies: the indent after `{`/`[` is *delayed* until the next token so
/// that empty containers stay `{}`/`[]`, and the break is a newline *followed*
/// by the indentation (Go's `appendNewline`), which is why a `,` at depth 0
/// leaves no trailing whitespace behind.
pub fn writeIndentJson(w: *std.Io.Writer, compact: []const u8) !void {
    var need_indent = false;
    var depth: u32 = 0;
    var in_string = false;
    var escaped = false;

    for (compact) |c| {
        if (in_string) {
            // Bytes inside a string are "semantically uninteresting" and pass
            // through untouched (Go's `scanContinue` branch).
            try w.writeByte(c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }

        const closer = c == '}' or c == ']';
        if (need_indent and !closer) {
            need_indent = false;
            depth += 1;
            try newlineIndent(w, depth, "  ");
        }

        switch (c) {
            '"' => {
                in_string = true;
                try w.writeByte(c);
            },
            '{', '[' => {
                need_indent = true;
                try w.writeByte(c);
            },
            '}', ']' => {
                if (need_indent) {
                    need_indent = false; // `{}` / `[]` stay on one line
                } else {
                    depth -= 1;
                    try newlineIndent(w, depth, "  ");
                }
                try w.writeByte(c);
            },
            ',' => {
                try w.writeByte(c);
                try newlineIndent(w, depth, "  ");
            },
            ':' => try w.writeAll(": "),
            else => try w.writeByte(c),
        }
    }
    // `Encoder.Encode` appends a newline after the document.
    try w.writeByte('\n');
}

/// Go's `appendNewline`: the newline first, then `prefix` + `indent * depth`
/// (which is why a break at depth 0 leaves no trailing spaces and the *next*
/// token sits on an indented line).
fn newlineIndent(w: *std.Io.Writer, depth: u32, indent: []const u8) !void {
    try w.writeByte('\n');
    var k: u32 = 0;
    while (k < depth) : (k += 1) try w.writeAll(indent);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testCore(gpa: std.mem.Allocator) !Core {
    const id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    // A node with no peers still has one tree entry and one routing entry: its
    // own self-announcement. Take the root position up front so the admin views
    // look like a reference node that has been running, not like a bare router.
    _ = try core.router.becomeRoot();
    return core;
}

test "dataunit string form matches go" {
    const cases = [_]struct { v: u64, want: []const u8 }{
        .{ .v = 0, .want = "0B" },
        .{ .v = 1, .want = "1B" },
        .{ .v = 99, .want = "99B" },
        .{ .v = 100, .want = "0.1KB" },
        .{ .v = 1024, .want = "1.0KB" },
        .{ .v = 1024 * 1024, .want = "1.0MB" },
        .{ .v = 12 * 1024 * 1024, .want = "12.0MB" },
        .{ .v = 1024 * 1024 * 1024, .want = "1.0GB" },
        .{ .v = 1024 * 1024 * 1024 * 1024, .want = "1.0TB" },
    };
    for (cases) |c| {
        const s = try (DataUnit{ .value = c.v }).string();
        try testing.expectEqualStrings(c.want, s);
    }
}

test "address rendering matches go" {
    var buf: [64]u8 = undefined;
    // Captured from a live reference node running the key below:
    // address 201:eed8:6175:2345:a997:d3fa:3c2a:aea7, subnet 301:eed8:...:/64.
    const full = [_]u8{ 0x02, 0x01, 0xee, 0xd8, 0x61, 0x75, 0x23, 0x45, 0xa9, 0x97, 0xd3, 0xfa, 0x3c, 0x2a, 0xae, 0xa7 };
    try testing.expectEqualStrings("201:eed8:6175:2345:a997:d3fa:3c2a:aea7", try ipv6ToString(&full, &buf));

    try testing.expectEqualStrings("::", try ipv6ToString(&[_]u8{0} ** 16, &buf));

    // RFC 5952 4.2.2: a tie between zero runs goes to the leftmost one, so the
    // leading pair is compressed and the trailing four groups are left out.
    const lead = [_]u8{ 0, 0, 0, 0, 0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqualStrings("0:0:2001::1", try ipv6ToString(&lead, &buf));

    const trail = [_]u8{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectEqualStrings("2001:db8::", try ipv6ToString(&trail, &buf));

    // A single zero group is never compressed.
    const mid = [_]u8{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };
    try testing.expectEqualStrings("2001:db8:0:1:0:2:0:3", try ipv6ToString(&mid, &buf));

    const sub: [8]u8 = .{ 0x03, 0x01, 0xee, 0xd8, 0x61, 0x75, 0x23, 0x45 };
    try testing.expectEqualStrings("301:eed8:6175:2345::/64", try subnetToString(&sub, &buf));
}

test "indent json matches go's two-space encoder" {
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeIndentJson(&w, "{\"a\":1,\"b\":[1,2],\"c\":{},\"d\":{\"e\":\"f\"},\"g\":[]}");
    try testing.expectEqualStrings(
        \\{
        \\  "a": 1,
        \\  "b": [
        \\    1,
        \\    2
        \\  ],
        \\  "c": {},
        \\  "d": {
        \\    "e": "f"
        \\  },
        \\  "g": []
        \\}
        \\
    , buf[0..w.end]);
}

test "envelope shape matches go" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);

    // `list`: the whole handler table, byte-sorted, `fields` only where Go
    // registered argument names, and every name lower-cased.
    const result = try admin.handleRequest("{\"request\":\"list\"}");
    defer gpa.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "\"command\": \"addpeer\"") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\"command\": \"gettun\"") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\"command\": \"getself\"") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\"fields\": [\n          \"uri\",\n          \"interface\"\n        ]") != null);

    // `getSelf`: field order, numeric routing_entries, CIDR subnet, and the
    // request echo with defaulted arguments.
    const selfres = try admin.handleRequest("{\"request\":\"getSelf\"}");
    defer gpa.free(selfres);
    try testing.expect(std.mem.indexOf(u8, selfres, "\"status\": \"success\"") != null);
    try testing.expect(std.mem.indexOf(u8, selfres, "\"build_name\": \"Yggdrasil\"") != null);
    try testing.expect(std.mem.indexOf(u8, selfres, "\"routing_entries\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, selfres, "/64\"") != null);
    try testing.expect(std.mem.indexOf(u8, selfres, "\"request\": {\n    \"request\": \"getSelf\",\n    \"arguments\": {}\n  },\n  \"response\"") != null);

    // Failures keep the echo and add `"response": null`.
    const bad = try admin.handleRequest("{\"request\":\"bogus\"}");
    defer gpa.free(bad);
    try testing.expect(std.mem.indexOf(u8, bad, "\"error\": \"unknown action 'bogus', try 'list' for help\"") != null);
    try testing.expect(std.mem.indexOf(u8, bad, "\"response\": null") != null);

    // A keepalive request echoes the flag; everything else must not.
    const ka = try admin.handleRequest("{\"request\":\"list\",\"keepalive\":true}");
    defer gpa.free(ka);
    try testing.expect(std.mem.indexOf(u8, ka, "\"keepalive\": true") != null);
    try testing.expect(std.mem.indexOf(u8, selfres, "\"keepalive\"") == null);
}

test "action names are matched case-insensitively and reported lower-cased" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);

    // A mixed-case name with underscores resolves, ...
    const ok = try admin.handleRequest("{\"request\":\"debug_remoteGetSelf\"}");
    defer gpa.free(ok);
    try testing.expect(std.mem.indexOf(u8, ok, "unknown action") == null);

    // ... and an unknown one is reported in lower case, as Go builds the message
    // from the map key it looked up rather than from what was sent.
    const bad = try admin.handleRequest("{\"request\":\"BogusThing\"}");
    defer gpa.free(bad);
    try testing.expect(std.mem.indexOf(u8, bad, "unknown action 'bogusthing', try 'list' for help") != null);
    // The echo keeps the caller's spelling.
    try testing.expect(std.mem.indexOf(u8, bad, "\"request\": \"BogusThing\"") != null);
}

test "parse-stage failures echo an empty request without arguments" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);

    for ([_][]const u8{ "not json at all", "[1,2,3]", "{\"request\":123}" }) |line| {
        const r = try admin.handleRequest(line);
        defer gpa.free(r);
        try testing.expect(std.mem.indexOf(u8, r, "\"request\": {\n    \"request\": \"\"\n  },\n  \"response\": null") != null);
        try testing.expect(std.mem.indexOf(u8, r, "\"arguments\"") == null);
    }

    // A document that decodes but has no `request`: `arguments` was pre-set to
    // `{}` before the unmarshal, so it *is* echoed.
    const none = try admin.handleRequest("{}");
    defer gpa.free(none);
    try testing.expect(std.mem.indexOf(u8, none, "\"error\": \"no request specified\"") != null);
    try testing.expect(std.mem.indexOf(u8, none, "\"arguments\": {}") != null);

    // Unknown top-level fields are ignored, not rejected.
    const extra = try admin.handleRequest("{\"request\":\"getPaths\",\"wat\":1}");
    defer gpa.free(extra);
    try testing.expect(std.mem.indexOf(u8, extra, "\"status\": \"success\"") != null);
    try testing.expect(std.mem.indexOf(u8, extra, "\"paths\": []") != null);
}

test "arguments are echoed re-marshalled" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);

    const r = try admin.handleRequest("{\"request\":\"getPeers\",  \"arguments\": { \"sort\" : \"cost\" } }");
    defer gpa.free(r);
    // Compacted by `json.Marshal` (the whitespace in the request is gone) and
    // then re-indented by the encoder.
    try testing.expect(std.mem.indexOf(u8, r, "\"arguments\": {\n      \"sort\": \"cost\"\n    }") != null);

    // `null` arguments are echoed as null and still work.
    const n = try admin.handleRequest("{\"request\":\"getSessions\",\"arguments\":null}");
    defer gpa.free(n);
    try testing.expect(std.mem.indexOf(u8, n, "\"arguments\": null") != null);
    try testing.expect(std.mem.indexOf(u8, n, "\"status\": \"success\"") != null);

    // Non-object arguments produce Go's type error.
    const a = try admin.handleRequest("{\"request\":\"getPeers\",\"arguments\":[]}");
    defer gpa.free(a);
    try testing.expect(std.mem.indexOf(u8, a, "json: cannot unmarshal array into Go value of type admin.GetPeersRequest") != null);
    const b = try admin.handleRequest("{\"request\":\"getPeers\",\"arguments\":{\"sort\":1}}");
    defer gpa.free(b);
    try testing.expect(std.mem.indexOf(u8, b, "cannot unmarshal number into Go struct field GetPeersRequest.sort of type string") != null);
}

test "html characters are escaped in echoed strings" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);
    const r = try admin.handleRequest("{\"request\":\"get><&\"}");
    defer gpa.free(r);
    try testing.expect(std.mem.indexOf(u8, r, "get\\u003e\\u003c\\u0026") != null);
}

test "peer entry omitempty rules" {
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var p = node.network.PeerSnapshot{ .uri = "tcp://127.0.0.1:19001", .up = true };
    p.key = [_]u8{0} ** 32;
    try writePeerEntry(&w, p);
    // A link that has not completed its handshake: no `address`, `key` present
    // but empty, no counters, no uptime/latency/last_error. Identical to what a
    // Go node reports for a dial that is still in flight.
    try testing.expectEqualStrings(
        "{\"remote\":\"tcp://127.0.0.1:19001\",\"up\":true,\"inbound\":false,\"key\":\"\",\"port\":0,\"priority\":0,\"cost\":0}",
        buf[0..w.end],
    );
}

test "peer entry with counters matches go" {
    var p = node.network.PeerSnapshot{
        .uri = "tcp://127.0.0.1:19001",
        .up = true,
        .has_key = true,
        .port = 1,
        .cost = 1,
        .rx_bytes = 759,
        .tx_bytes = 719,
        .uptime_ns = 19_200_711_328,
        .latency_ns = 650_000,
    };
    p.key = [_]u8{0} ** 32;
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writePeerEntry(&w, p);
    // Byte counters are numbers (DataUnit has no MarshalJSON) and `uptime`
    // keeps the full float precision of `Duration.Seconds()`.
    try testing.expect(std.mem.indexOf(u8, buf[0..w.end], "\"bytes_recvd\":759,\"bytes_sent\":719") != null);
    try testing.expect(std.mem.indexOf(u8, buf[0..w.end], "\"uptime\":19.200711328,\"latency\":650000") != null);
}

test "peer sorting reproduces go's comparator quirks" {
    const mk = struct {
        fn f(uri: []const u8, inbound: bool, uptime_ns: u64, cost: u64) node.network.PeerSnapshot {
            var p = node.network.PeerSnapshot{ .uri = uri, .inbound = inbound, .uptime_ns = uptime_ns, .cost = cost, .has_key = true };
            p.key = [_]u8{0} ** 32;
            return p;
        }
    }.f;
    var peers = [_]node.network.PeerSnapshot{
        mk("c", true, 5 * std.time.ns_per_s, 7),
        mk("a", false, 1 * std.time.ns_per_s, 3),
        mk("b", false, 1 * std.time.ns_per_s + 500 * std.time.ns_per_ms, 3),
    };
    sortPeers(&peers, "");
    // Outbound first; `a` and `b` differ by 0.5s, which `int(diff)` truncates
    // to zero, so the stable sort keeps their input order.
    try testing.expectEqualStrings("a", peers[0].uri);
    try testing.expectEqualStrings("b", peers[1].uri);
    try testing.expectEqualStrings("c", peers[2].uri);

    sortPeers(&peers, "cost");
    try testing.expectEqualStrings("c", peers[2].uri);

    sortPeers(&peers, "uptime");
    try testing.expectEqualStrings("a", peers[0].uri);
    try testing.expectEqualStrings("b", peers[1].uri);
    try testing.expectEqualStrings("c", peers[2].uri);
}

test "unknown scheme is reported like go" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);
    var loop = try xev.Loop.init(.{});
    var nm = node.network.NetworkManager.init(gpa, &loop, &core, ironwood.Crypto.generate());
    defer nm.deinit();
    admin.net = &nm;
    defer admin.net = null;

    for ([_][]const u8{ "bogus", "" }) |uri| {
        const arg = try std.fmt.allocPrint(gpa, "{{\"request\":\"addPeer\",\"arguments\":{{\"uri\":\"{s}\"}}}}", .{uri});
        defer gpa.free(arg);
        const r = try admin.handleRequest(arg);
        defer gpa.free(r);
        try testing.expect(std.mem.indexOf(u8, r, "\"error\": \"link schema unknown\"") != null);
    }

    // A configured peer cannot be added twice, and a missing one cannot be
    // removed; both wordings are `src/core/link.go`'s `linkError` constants.
    const add = try admin.handleRequest("{\"request\":\"addPeer\",\"arguments\":{\"uri\":\"tcp://127.0.0.1:1\"}}");
    defer gpa.free(add);
    try testing.expect(std.mem.indexOf(u8, add, "\"status\": \"success\"") != null);
    const dup = try admin.handleRequest("{\"request\":\"addPeer\",\"arguments\":{\"uri\":\"tcp://127.0.0.1:1\"}}");
    defer gpa.free(dup);
    try testing.expect(std.mem.indexOf(u8, dup, "\"error\": \"peer is already configured\"") != null);
    const rm = try admin.handleRequest("{\"request\":\"removePeer\",\"arguments\":{\"uri\":\"tcp://10.9.9.9:1\"}}");
    defer gpa.free(rm);
    try testing.expect(std.mem.indexOf(u8, rm, "\"error\": \"peer is not configured\"") != null);
}

test "admin requests do not leak" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var admin = AdminSocket.init(gpa, &core);
    for ([_][]const u8{
        "{\"request\":\"list\"}",
        "{\"request\":\"getSelf\"}",
        "{\"request\":\"getTree\"}",
        "{\"request\":\"getPaths\"}",
        "{\"request\":\"getSessions\"}",
        "{\"request\":\"getPeers\"}",
        "{\"request\":\"gettun\"}",
        "{\"request\":\"bogus\"}",
        "[1,2,3]",
        "garbage",
        "{}",
        "{\"request\":\"getPeers\",\"arguments\":[]}",
        "{\"request\":\"getNodeInfo\",\"arguments\":{\"key\":\"00\"}}",
    }) |line| {
        const r = try admin.handleRequest(line);
        gpa.free(r);
    }
}

/// Captured replies from a reference yggdrasil-go node. Only the test below
/// refers to `golden.cases`, so a release build parses the file and drops it.
const golden = @import("admin_golden.zig");

/// Values the fixtures stand in for the node under test: the reference node's
/// key/address/subnet/build strings cannot be ours, but every other byte can.
const Tokens = struct {
    key: []const u8,
    addr: []const u8,
    subnet: []const u8,
    routing: []const u8,
    uri: []const u8,

    fn lookup(self: Tokens, name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "KEY")) return self.key;
        if (std.mem.eql(u8, name, "ADDR")) return self.addr;
        if (std.mem.eql(u8, name, "SUBNET")) return self.subnet;
        if (std.mem.eql(u8, name, "BUILD_NAME")) return BUILD_NAME;
        if (std.mem.eql(u8, name, "BUILD_VERSION")) return BUILD_VERSION;
        if (std.mem.eql(u8, name, "ROUTING")) return self.routing;
        if (std.mem.eql(u8, name, "URI")) return self.uri;
        return null;
    }
};

/// Replace `@NAME@` tokens. An unknown token is copied through, which makes the
/// comparison fail with the token visible rather than silently passing.
fn expandTokens(w: *std.Io.Writer, text: []const u8, tokens: Tokens) !void {
    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '@') {
            if (std.mem.indexOfScalarPos(u8, text, i + 1, '@')) |end| {
                const name = text[i + 1 .. end];
                if (name.len > 0 and std.ascii.isUpper(name[0])) {
                    if (tokens.lookup(name)) |v| {
                        try w.writeAll(v);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        try w.writeByte(text[i]);
        i += 1;
    }
}

test "replies match a reference yggdrasil-go node byte for byte" {
    const gpa = testing.allocator;
    var core = try testCore(gpa);
    defer core.deinit();
    var loop = try xev.Loop.init(.{});
    var nm = node.network.NetworkManager.init(gpa, &loop, &core, core.crypto);
    defer nm.deinit();
    var admin = AdminSocket.init(gpa, &core);
    admin.net = &nm;
    defer admin.net = null;

    const info = node.core.getSelfInfo(&core);
    var key_hex: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_hex, "{x}", .{info.key});
    var abuf: [64]u8 = undefined;
    const addr = try ipv6ToString(&core.address.bytes, &abuf);
    var sbuf: [80]u8 = undefined;
    const subnet = try subnetToString(&core.subnet.bytes, &sbuf);
    var routef: [24]u8 = undefined;
    const routing = try std.fmt.bufPrint(&routef, "{d}", .{info.routing_entries});

    const tokens = Tokens{
        .key = key,
        .addr = addr,
        .subnet = subnet,
        .routing = routing,
        // The reference's captures name the peer it was told to add; our node is
        // configured with the same URI in the same request.
        .uri = "tcp://127.0.0.1:1",
    };

    var differing: usize = 0;
    for (golden.cases) |c| {
        var out = std.Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        try expandTokens(&out.writer, c.expect, tokens);
        const got = try admin.handleRequest(c.request);
        defer gpa.free(got);
        if (std.mem.eql(u8, out.written(), got)) continue;
        differing += 1;
        // Print both replies with a marker per line so whitespace differences
        // (which are the most likely kind here) are visible without a hexdump.
        std.debug.print("\n=== {s}\n--- reference ---\n", .{c.name});
        var wit = std.mem.splitScalar(u8, out.written(), '\n');
        while (wit.next()) |l| std.debug.print("|{s}\n", .{l});
        std.debug.print("--- ours ---\n", .{});
        var git = std.mem.splitScalar(u8, got, '\n');
        while (git.next()) |l| std.debug.print("|{s}\n", .{l});
    }
    // One failure per run would make fixing a batch of them a slog.
    try testing.expectEqual(@as(usize, 0), differing);
}
