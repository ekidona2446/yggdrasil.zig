//! In-band protocol for debug_remote and getNodeInfo commands.
//! Messages sent as session traffic through the encrypted PacketConn.

const std = @import("std");
const ironwood = @import("ironwood");

const PublicKey = ironwood.PublicKey;

/// Response message to send back to a peer.
pub const ProtoResponse = struct {
    dest: PublicKey,
    data: []u8,
};

/// Protocol message types (after session decryption).
const TYPE_PROTO_NODEINFO_REQUEST: u8 = 1;
const TYPE_PROTO_NODEINFO_RESPONSE: u8 = 2;
const TYPE_PROTO_DEBUG: u8 = 255;

/// Debug message subtypes.
const TYPE_DEBUG_GET_SELF_REQUEST: u8 = 1;
const TYPE_DEBUG_GET_SELF_RESPONSE: u8 = 2;
const TYPE_DEBUG_GET_PEERS_REQUEST: u8 = 3;
const TYPE_DEBUG_GET_PEERS_RESPONSE: u8 = 4;
const TYPE_DEBUG_GET_TREE_REQUEST: u8 = 5;
const TYPE_DEBUG_GET_TREE_RESPONSE: u8 = 6;

/// Timeout for remote requests (6 seconds).
pub const REQUEST_TIMEOUT_NS: u64 = 6 * std.time.ns_per_s;

/// Cleanup interval (30 seconds).
pub const CLEANUP_INTERVAL_NS: u64 = 30 * std.time.ns_per_s;

/// Callback expiry (60 seconds).
pub const CALLBACK_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;

// ---------------------------------------------------------------------------
// ProtoHandler
// ---------------------------------------------------------------------------

/// Handles in-band protocol messages. Single-threaded (event-loop model).
pub const ProtoHandler = struct {
    gpa: std.mem.Allocator,
    /// Callbacks: key -> pending response channel.
    callbacks: std.AutoHashMapUnmanaged(PublicKey, PendingCallback),

    pub fn init(gpa: std.mem.Allocator) ProtoHandler {
        return .{ .gpa = gpa, .callbacks = .{} };
    }

    pub fn deinit(self: *ProtoHandler) void {
        var it = self.callbacks.iterator();
        while (it.next()) |entry| {
            // Free any stored data
            if (entry.value_ptr.data) |d| self.gpa.free(d);
        }
        self.callbacks.deinit(self.gpa);
    }

    /// Handle an incoming protocol message. Returns a response to send back,
    /// or null if the message is a response to our pending request.
    pub fn handleMessage(
        self: *ProtoHandler,
        from_key: PublicKey,
        payload: []const u8,
        our_key: *const PublicKey,
        routing_entries: usize,
        peer_keys: []const PublicKey,
        tree_keys: []const PublicKey,
        nodeinfo_json: []const u8,
    ) ?ProtoResponse {
        if (payload.len == 0) return null;

        switch (payload[0]) {
            TYPE_PROTO_DEBUG => {
                if (payload.len < 2) return null;
                return self.handleDebug(from_key, payload[1..], our_key, routing_entries, peer_keys, tree_keys);
            },
            TYPE_PROTO_NODEINFO_REQUEST => {
                return self.handleNodeInfoRequest(from_key, nodeinfo_json);
            },
            TYPE_PROTO_NODEINFO_RESPONSE => {
                if (payload.len < 2) return null;
                self.handleNodeInfoResponse(from_key, payload[1..]);
                return null;
            },
            else => return null,
        }
    }

    fn handleDebug(
        self: *ProtoHandler,
        from_key: PublicKey,
        data: []const u8,
        our_key: *const PublicKey,
        routing_entries: usize,
        peer_keys: []const PublicKey,
        tree_keys: []const PublicKey,
    ) ?ProtoResponse {
        if (data.len == 0) return null;
        switch (data[0]) {
            TYPE_DEBUG_GET_SELF_REQUEST => {
                const entries_str = tryBufPrint(self.gpa, "{d}", .{routing_entries}) catch return null;
                defer self.gpa.free(entries_str);
                const key_hex = tryBufPrintHex(self.gpa, our_key) catch return null;
                defer self.gpa.free(key_hex);
                const json = std.fmt.allocPrint(self.gpa, "{{\"key\":\"{s}\",\"routing_entries\":\"{s}\"}}", .{ key_hex, entries_str }) catch return null;
                defer self.gpa.free(json);
                const msg = makeMsg(self.gpa, &[_]u8{ TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_SELF_RESPONSE }, json) catch return null;
                return .{ .dest = from_key, .data = msg };
            },
            TYPE_DEBUG_GET_SELF_RESPONSE => {
                self.deliverResponse(from_key, data[1..]);
                return null;
            },
            TYPE_DEBUG_GET_PEERS_REQUEST => {
                const msg = makeKeyListMsg(self.gpa, TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_PEERS_RESPONSE, peer_keys) catch return null;
                return .{ .dest = from_key, .data = msg };
            },
            TYPE_DEBUG_GET_PEERS_RESPONSE => {
                self.deliverResponse(from_key, data[1..]);
                return null;
            },
            TYPE_DEBUG_GET_TREE_REQUEST => {
                const msg = makeKeyListMsg(self.gpa, TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_TREE_RESPONSE, tree_keys) catch return null;
                return .{ .dest = from_key, .data = msg };
            },
            TYPE_DEBUG_GET_TREE_RESPONSE => {
                self.deliverResponse(from_key, data[1..]);
                return null;
            },
            else => return null,
        }
    }

    fn handleNodeInfoRequest(
        self: *ProtoHandler,
        from_key: PublicKey,
        nodeinfo_json: []const u8,
    ) ?ProtoResponse {
        const msg = makeMsg(self.gpa, &[_]u8{TYPE_PROTO_NODEINFO_RESPONSE}, nodeinfo_json) catch return null;
        return .{ .dest = from_key, .data = msg };
    }

    fn handleNodeInfoResponse(self: *ProtoHandler, from_key: PublicKey, data: []const u8) void {
        self.deliverResponse(from_key, data);
    }

    fn deliverResponse(self: *ProtoHandler, from_key: PublicKey, data: []const u8) void {
        if (self.callbacks.getPtr(from_key)) |cb| {
            cb.data = self.gpa.dupe(u8, data) catch null;
        }
    }

    /// Register a pending callback. Returns an id for polling.
    pub fn registerCallback(self: *ProtoHandler, target: PublicKey) !void {
        try self.callbacks.put(self.gpa, target, .{ .data = null, .created_ns = monotonicNs() });
    }

    /// Try to take a completed response. Returns null if not ready yet.
    pub fn takeResponse(self: *ProtoHandler, target: PublicKey) ?[]u8 {
        if (self.callbacks.getPtr(target)) |cb| {
            return cb.data;
        }
        return null;
    }

    /// Clean up expired callbacks.
    pub fn cleanupExpired(self: *ProtoHandler) void {
        const now = monotonicNs();
        var to_remove = std.ArrayListUnmanaged(PublicKey).empty;
        defer to_remove.deinit(self.gpa);

        var it = self.callbacks.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.created_ns > CALLBACK_TIMEOUT_NS) {
                to_remove.append(self.gpa, entry.key_ptr.*) catch {};
            }
        }
        for (to_remove.items) |k| {
            if (self.callbacks.fetchRemove(k)) |kv| {
                if (kv.value.data) |d| self.gpa.free(d);
            }
        }
    }
};

const PendingCallback = struct {
    data: ?[]u8 = null,
    created_ns: u64,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tryBufPrint(gpa: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    const str = try std.fmt.allocPrint(gpa, fmt, args);
    return str;
}

fn tryBufPrintHex(gpa: std.mem.Allocator, key: *const PublicKey) ![]u8 {
    const hex = try gpa.alloc(u8, 64);
    errdefer gpa.free(hex);
    const chars = "0123456789abcdef";
    for (key, 0..) |b, i| {
        hex[i * 2] = chars[(b >> 4) & 0xF];
        hex[i * 2 + 1] = chars[b & 0xF];
    }
    return hex;
}

fn makeMsg(gpa: std.mem.Allocator, header: []const u8, body: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, header.len + body.len);
    @memcpy(out[0..header.len], header);
    @memcpy(out[header.len..], body);
    return out;
}

fn makeKeyListMsg(gpa: std.mem.Allocator, proto_type: u8, debug_type: u8, keys: []const PublicKey) ![]u8 {
    const out = try gpa.alloc(u8, 2 + keys.len * 32);
    out[0] = proto_type;
    out[1] = debug_type;
    for (keys, 0..) |k, i| {
        @memcpy(out[2 + i * 32 ..][0..32], &k);
    }
    return out;
}

fn monotonicNs() u64 {
    if (@import("builtin").os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        if (std.os.linux.clock_gettime(.MONOTONIC, &ts) == 0)
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }
    return @intCast(std.time.nanoTimestamp());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "node info request response" {
    const gpa = testing.allocator;
    var handler = ProtoHandler.init(gpa);
    defer handler.deinit();

    const our_key = [_]u8{1} ** 32;
    const from_key = [_]u8{2} ** 32;
    const nodeinfo = "{\"name\":\"test\"}";

    // Incoming request -> response
    const response = handler.handleMessage(from_key, &[_]u8{TYPE_PROTO_NODEINFO_REQUEST}, &our_key, 0, &.{}, &.{}, nodeinfo);
    try testing.expect(response != null);
    defer gpa.free(response.?.data);
    try testing.expectEqual(TYPE_PROTO_NODEINFO_RESPONSE, response.?.data[0]);
    try testing.expectEqualSlices(u8, nodeinfo, response.?.data[1..]);
}

test "debug get self request" {
    const gpa = testing.allocator;
    var handler = ProtoHandler.init(gpa);
    defer handler.deinit();

    const our_key = [_]u8{3} ** 32;
    const from_key = [_]u8{4} ** 32;
    const request = [_]u8{ TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_SELF_REQUEST };

    const response = handler.handleMessage(from_key, &request, &our_key, 42, &.{}, &.{}, "{}");
    try testing.expect(response != null);
    defer gpa.free(response.?.data);
    try testing.expectEqual(TYPE_PROTO_DEBUG, response.?.data[0]);
    try testing.expectEqual(TYPE_DEBUG_GET_SELF_RESPONSE, response.?.data[1]);
    // Should contain our key in hex
    try testing.expect(std.mem.indexOf(u8, response.?.data, "03030303") != null);
    try testing.expect(std.mem.indexOf(u8, response.?.data, "42") != null);
}
