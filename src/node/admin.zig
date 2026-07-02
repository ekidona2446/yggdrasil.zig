//! Admin JSON-RPC socket for node monitoring and control.

const std = @import("std");
const ironwood = @import("ironwood");
const node = @import("node.zig");

const Core = node.core.Core;
const PublicKey = ironwood.PublicKey;

pub const AdminSocket = struct {
    core: *Core,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, core: *Core) AdminSocket {
        return .{ .core = core, .gpa = gpa };
    }

    pub fn handleRequest(self: *AdminSocket, line: []const u8) ![]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, self.gpa, line, .{}) catch {
            return try self.gpa.dupe(u8, "{\"status\":\"error\"}");
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return try self.gpa.dupe(u8, "{\"status\":\"error\"}"),
        };

        const req_name = if (obj.get("request")) |r| r.string else return try self.gpa.dupe(u8, "{\"status\":\"error\"}");
        const body = try self.dispatch(req_name);
        defer self.gpa.free(body);

        const result = try std.fmt.allocPrint(self.gpa,
            "{{\"status\":\"success\",\"request\":\"{s}\",\"response\":{s}}}", .{ req_name, body });
        return result;
    }

    fn dispatch(self: *AdminSocket, cmd: []const u8) ![]u8 {
        if (std.mem.eql(u8, cmd, "list")) return try self.gpa.dupe(u8,
            "{\"list\":[\"list\",\"getself\",\"getpeers\",\"gettree\",\"getpaths\",\"getsessions\"]}");
        if (std.mem.eql(u8, cmd, "getself")) return try self.getSelf();
        if (std.mem.eql(u8, cmd, "getpeers")) return try self.gpa.dupe(u8, "{\"peers\":[]}");
        if (std.mem.eql(u8, cmd, "gettree")) return try self.gpa.dupe(u8, "{\"tree\":[]}");
        if (std.mem.eql(u8, cmd, "getpaths")) return try self.gpa.dupe(u8, "{\"paths\":[]}");
        if (std.mem.eql(u8, cmd, "getsessions")) return try self.gpa.dupe(u8, "{\"sessions\":[]}");
        return try self.gpa.dupe(u8, "{}");
    }

    fn getSelf(self: *AdminSocket) ![]u8 {
        const key_hex = try hexEncode(self.gpa, &self.core.selfKey());
        defer self.gpa.free(key_hex);
        return try std.fmt.allocPrint(self.gpa,
            "{{\"build_name\":\"yggdrasil-zig\",\"build_version\":\"0.1.0-dev\",\"key\":\"{s}\"}}", .{key_hex});
    }
};

fn hexEncode(gpa: std.mem.Allocator, key: *const PublicKey) ![]u8 {
    const out = try gpa.alloc(u8, 64);
    errdefer gpa.free(out);
    const chars = "0123456789abcdef";
    for (key, 0..) |b, i| {
        out[i * 2] = chars[(b >> 4) & 0xF];
        out[i * 2 + 1] = chars[b & 0xF];
    }
    return out;
}

const testing = std.testing;

test "admin list" {
    const gpa = testing.allocator;
    const id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();

    var admin = AdminSocket.init(gpa, &core);
    const result = try admin.handleRequest("{\"request\":\"list\"}");
    defer gpa.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "success") != null);
}

test "admin getself" {
    const gpa = testing.allocator;
    const id = ironwood.Crypto.generate();
    const cfg = ironwood.Config.default();
    var core = try Core.init(gpa, id, cfg, "");
    defer core.deinit();

    var admin = AdminSocket.init(gpa, &core);
    const result = try admin.handleRequest("{\"request\":\"getself\"}");
    defer gpa.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "yggdrasil-zig") != null);
}
