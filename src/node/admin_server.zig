//! Admin socket listener.
//!
//! The wire protocol itself lives in `admin.zig`; this file only moves
//! newline-delimited JSON between a socket and that handler. It runs entirely on
//! the event loop thread, which is what lets admin handlers call into
//! `NetworkManager` (`addPeer`/`removePeer` mutate the dial table and arm libxev
//! timers, neither of which is safe from another thread).
//!
//! One connection is handled per `xev` read/write pair, and a connection stays
//! open exactly as long as the reference implementation keeps it: after a reply
//! whose request did not set `"keepalive": true`, the socket is closed.
//!
//! `unix://` addresses are not served yet (`tcp://` is what every config in the
//! wild uses), so such a URI is refused and the node starts without an admin
//! socket, the way it does for other optional subsystems.

const std = @import("std");
const xev = @import("xev");
const node = @import("node.zig");
const dns = @import("dns.zig");
const unix_socket = @import("unix_socket.zig");

const admin = node.admin;
const log = std.log.scoped(.admin);

/// Longest request line buffered before the connection is dropped. A client sends
/// one compact JSON object per line, so anything past this is not a request the
/// node would answer; the reference has no bound at all, which is worse.
const MAX_LINE: usize = 64 * 1024;
/// Concurrent admin clients. `yggdrasilctl` uses one at a time; the cap exists so
/// a stuck keepalive client cannot exhaust the process' file descriptors.
const MAX_CLIENTS: usize = 16;
const READ_BUF: usize = 16 * 1024;

const Target = union(enum) {
    tcp: struct { host: []const u8, port: u16 },
    unix: []const u8,
};

/// Split an admin listen address. `parsePeerURI` is deliberately not reused: it
/// insists on `host:port`, which a `unix://` path has no, and that gap also means
/// the peer layer cannot listen on a unix socket yet (see the note on
/// `NetworkManager.addListener`).
const ParseUriError = error{ BadAdminURI, UnsupportedScheme };

fn parseAdminUri(uri: []const u8) ParseUriError!Target {
    const sep = std.mem.indexOf(u8, uri, "://") orelse return error.BadAdminURI;
    const scheme = uri[0..sep];
    const rest = uri[sep + 3 ..];
    if (std.mem.eql(u8, scheme, "unix")) {
        if (rest.len == 0) return error.BadAdminURI;
        return .{ .unix = rest };
    }
    if (!std.mem.eql(u8, scheme, "tcp")) return error.UnsupportedScheme;
    // `host:port`, with the bracket form for IPv6 literals: `[::1]:9001`.
    var host = rest;
    var port: u16 = 0;
    if (host.len > 0 and host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return error.BadAdminURI;
        const after = host[close + 1 ..];
        if (after.len == 0 or after[0] != ':') return error.BadAdminURI;
        host = host[1..close];
        port = std.fmt.parseInt(u16, after[1..], 10) catch return error.BadAdminURI;
    } else {
        const colon = std.mem.lastIndexOfScalar(u8, host, ':') orelse return error.BadAdminURI;
        port = std.fmt.parseInt(u16, host[colon + 1 ..], 10) catch return error.BadAdminURI;
        host = host[0..colon];
    }
    if (host.len == 0) return error.BadAdminURI;
    return .{ .tcp = .{ .host = host, .port = port } };
}

/// Close a socket without submitting a completion. `xev` has no synchronous
/// close, so this is only for paths where the loop is already stopped (shutdown)
/// or the object never got one; elsewhere `Client.close` is used instead.
fn closeSocket(tcp: xev.TCP) void {
    // Portable close: `std.posix.system.close` resolves to libc's `close` on
    // every POSIX target (the node always links libc), and to the raw Linux
    // syscall on a no-libc Linux build. The previous `std.os.linux.close`
    // was Linux-only and silently leaked the descriptor on macOS/*BSD.
    _ = std.posix.system.close(tcp.fd);
}

pub const Server = struct {
    gpa: std.mem.Allocator,
    loop: *xev.Loop,
    admin: *admin.AdminSocket,
    tcp: xev.TCP = undefined,
    accept_completion: xev.Completion = .{},
    clients: std.ArrayListUnmanaged(*Client) = .empty,
    listening: bool = false,
    /// Set for a `unix://` listener so the socket file can be unlinked on
    /// shutdown. Null for `tcp://` (and for abstract unix sockets, which have
    /// no filesystem entry to clean up).
    unix_path: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, loop: *xev.Loop, adm: *admin.AdminSocket) Server {
        return .{ .gpa = gpa, .loop = loop, .admin = adm };
    }

    /// Bind `uri` (e.g. `tcp://localhost:9001` or `unix:///var/run/yggdrasil.sock`)
    /// and start accepting. The error set is inferred: besides the URI-level
    /// refusals of `parseAdminUri`, binding and listening fail with whatever the
    /// platform and libxev report, and `main` only ever logs that.
    pub fn start(self: *Server, uri: []const u8) !void {
        const target = parseAdminUri(uri) catch |err| switch (err) {
            error.UnsupportedScheme => return err,
            else => return error.BadAdminURI,
        };
        switch (target) {
            .unix => |path| try self.startUnix(path),
            .tcp => |host_port| try self.startTcp(host_port),
        }
    }

    fn startUnix(self: *Server, path: []const u8) !void {
        const addr = unix_socket.Address.init(path) catch return error.BadAdminURI;
        // A leftover socket file from a previous run is removed, but only if
        // nothing is listening on it (mirrors yggdrasil-go's behaviour).
        unix_socket.cleanupStale(addr);
        self.tcp = unix_socket.listener(addr, 128) catch |err| {
            log.warn("unix admin socket listen failed: {}", .{err});
            return switch (err) {
                error.AddressInUse => error.AddressInUse,
                error.NameTooLong => error.BadAdminURI,
                else => error.SystemResources,
            };
        };
        errdefer closeSocket(self.tcp);
        if (!addr.abstract) {
            self.unix_path = try self.gpa.dupe(u8, addr.path);
            // Restrict the socket file like yggdrasil-go does (0660): only the
            // owner and group may talk to the admin socket.
            var buf: [108]u8 = undefined;
            if (std.fmt.bufPrintZ(&buf, "{s}", .{addr.path})) |z| {
                _ = std.posix.system.chmod(z.ptr, 0o660);
            } else |_| {}
        }
        self.tcp.accept(self.loop, &self.accept_completion, Server, self, onAccept);
        self.listening = true;
        log.info("unix admin socket listening on {s}", .{path});
    }

    fn startTcp(self: *Server, host_port: anytype) !void {
        const addrs = dns.resolve(self.gpa, host_port.host, host_port.port) catch return error.ResolveFailed;
        defer self.gpa.free(addrs);
        if (addrs.len == 0) return error.NoSuitableIPs;
        const addr = addrs[0];

        self.tcp = xev.TCP.init(addr) catch return error.SystemResources;
        errdefer closeSocket(self.tcp);
        // `xev.TCP.bind` sets `SO_REUSEADDR`, so restarting the node while an old
        // client connection is in `TIME_WAIT` still works.
        self.tcp.bind(addr) catch return error.AddressInUse;
        try self.tcp.listen(128);
        self.tcp.accept(self.loop, &self.accept_completion, Server, self, onAccept);
        self.listening = true;
        log.info("admin socket listening on {f}", .{addr});
    }

    /// Release the descriptors. Called after the loop has stopped, so no
    /// completion is submitted -- the process is on its way out.
    pub fn deinit(self: *Server) void {
        for (self.clients.items) |client| {
            closeSocket(client.tcp);
            client.destroy();
        }
        self.clients.deinit(self.gpa);
        if (self.listening) closeSocket(self.tcp);
        self.listening = false;
        if (self.unix_path) |p| {
            // Remove the socket file so the next run can bind again.
            var buf: [108]u8 = undefined;
            if (std.fmt.bufPrintZ(&buf, "{s}", .{p})) |z| {
                _ = std.posix.system.unlink(z.ptr);
            } else |_| {}
            self.gpa.free(p);
            self.unix_path = null;
        }
    }

    fn onAccept(ud: ?*Server, loop: *xev.Loop, c: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
        _ = c;
        const self = ud.?;
        const tcp = r catch |err| {
            log.warn("accept failed: {}", .{err});
            self.tcp.accept(loop, &self.accept_completion, Server, self, onAccept);
            return .disarm;
        };
        if (Client.create(self, tcp)) |client| {
            if (self.clients.items.len > MAX_CLIENTS) {
                // Over the limit: hand the socket to the client object and close
                // it through the loop, which is the only portable way to release a
                // descriptor here (and it lets the peer see a clean FIN).
                log.warn("too many admin clients, dropping one", .{});
                client.close(loop);
            } else {
                client.readMore(loop);
            }
        } else |err| {
            log.warn("admin client setup failed: {}", .{err});
            closeSocket(tcp);
        }
        // Always re-arm: a single accept per completion would otherwise stall
        // after a client hung up mid-burst.
        self.tcp.accept(loop, &self.accept_completion, Server, self, onAccept);
        return .disarm;
    }

    fn removeClient(self: *Server, client: *Client) void {
        for (self.clients.items, 0..) |c, i| {
            if (c != client) continue;
            _ = self.clients.orderedRemove(i);
            return;
        }
    }
};

const Client = struct {
    server: *Server,
    tcp: xev.TCP,
    read_completion: xev.Completion = .{},
    write_completion: xev.Completion = .{},
    close_completion: xev.Completion = .{},
    read_buf: [READ_BUF]u8 = undefined,
    /// Bytes of the request line not yet terminated by a newline.
    pending: std.ArrayListUnmanaged(u8) = .empty,
    /// Replies queued but not yet fully written. Each element is an allocation
    /// owned by this client: the bytes handed to a pending `write` must not be
    /// reallocated or cleared underneath it, so nothing is ever appended into a
    /// shared buffer here -- the head of the queue is freed once it is written.
    out: std.ArrayListUnmanaged([]u8) = .empty,
    /// Bytes of `out.items[0]` already written.
    out_written: usize = 0,
    writing: bool = false,
    /// Reads and writes asked for but not yet completed. Their completions live
    /// inside this struct, so the object may not be freed -- nor the socket closed
    /// -- while the count is non-zero.
    inflight: usize = 0,
    /// Set once the close operation has been submitted, so it is submitted once.
    close_submitted: bool = false,
    /// Set once the connection must not be read again: either the peer closed or
    /// the last reply answered a request without `keepalive`.
    closing: bool = false,
    dead: bool = false,

    fn create(server: *Server, tcp: xev.TCP) !*Client {
        const gpa = server.gpa;
        const self = try gpa.create(Client);
        errdefer gpa.destroy(self);
        self.* = .{ .server = server, .tcp = tcp };
        try server.clients.append(gpa, self);
        return self;
    }

    fn destroy(self: *Client) void {
        const gpa = self.server.gpa;
        for (self.out.items) |reply| gpa.free(reply);
        self.out.deinit(gpa);
        self.pending.deinit(gpa);
        gpa.destroy(self);
    }

    fn readMore(self: *Client, loop: *xev.Loop) void {
        if (self.dead or self.closing) return;
        self.inflight += 1;
        self.tcp.read(loop, &self.read_completion, .{ .slice = &self.read_buf }, Client, self, onRead);
    }

    fn onRead(ud: ?*Client, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, buf: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
        _ = c;
        _ = tcp;
        const self = ud.?;
        self.inflight -= 1;
        if (self.dead) {
            self.maybeClose(loop);
            return .disarm;
        }
        // libxev reports a peer that hung up as `error.EOF`, not as a zero-length
        // read, so both mean the client is done.
        const n = r catch |err| {
            if (err != error.EOF) log.debug("admin read failed: {}", .{err});
            self.close(loop);
            return .disarm;
        };
        if (n == 0) {
            self.close(loop);
            return .disarm;
        }
        self.consume(loop, buf.slice[0..n]) catch |err| {
            log.debug("admin request rejected: {}", .{err});
            self.close(loop);
            return .disarm;
        };
        // Only `readMore` may re-arm: it is the one place that knows whether the
        // connection has been told to close after its last reply.
        self.readMore(loop);
        return .disarm;
    }

    fn consume(self: *Client, loop: *xev.Loop, data: []const u8) !void {
        const gpa = self.server.gpa;
        for (data) |ch| {
            if (ch == '\n') {
                try self.handleLine(gpa, loop);
                // A request that ends the connection stops the parse here, the way
                // the reference's read-one-request-per-iteration loop does; bytes the
                // client pipelined after it are never answered.
                if (self.closing) return;
                continue;
            }
            if (ch == '\r') continue;
            if (self.pending.items.len >= MAX_LINE) return error.LineTooLong;
            try self.pending.append(gpa, ch);
        }
    }

    fn handleLine(self: *Client, gpa: std.mem.Allocator, loop: *xev.Loop) !void {
        const line = self.pending.items;
        // `handleRequest` borrows `line` (the echoed `arguments` are a span of it),
        // so the buffer may only be cleared afterwards: `clearRetainingCapacity`
        // overwrites the elements with `undefined`.
        const reply = try self.server.admin.handleRequest(line);
        errdefer gpa.free(reply);
        if (!self.server.admin.isKeepalive(line)) self.closing = true;
        try self.out.append(gpa, reply);
        self.pending.clearRetainingCapacity();
        self.flush(loop);
    }

    /// Hand the oldest queued reply to the loop, or close the connection once the
    /// queue is empty and the client is not waiting for anything.
    fn flush(self: *Client, loop: *xev.Loop) void {
        const gpa = self.server.gpa;
        if (self.dead or self.writing) return;
        while (self.out.items.len > 0) {
            const reply = self.out.items[0];
            if (self.out_written >= reply.len) {
                gpa.free(reply);
                _ = self.out.orderedRemove(0);
                self.out_written = 0;
                continue;
            }
            self.writing = true;
            self.inflight += 1;
            self.tcp.write(loop, &self.write_completion, .{ .slice = reply[self.out_written..] }, Client, self, onWrite);
            return;
        }
        if (self.closing) self.close(loop);
    }

    fn onWrite(ud: ?*Client, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, buf: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
        _ = c;
        _ = tcp;
        const self = ud.?;
        self.inflight -= 1;
        if (self.dead) {
            self.maybeClose(loop);
            return .disarm;
        }
        self.writing = false;
        const n = r catch |err| {
            log.debug("admin write failed: {}", .{err});
            self.close(loop);
            return .disarm;
        };
        if (n == 0 or n > buf.slice.len) {
            self.close(loop);
            return .disarm;
        }
        self.out_written += n;
        self.flush(loop);
        return .disarm;
    }

    /// Stop using this connection and release its socket. Replies still queued are
    /// dropped: every caller that gets here does so because the connection can no
    /// longer carry them (the peer hung up, or a read/write failed). A reply that
    /// merely has not been asked for yet is never dropped -- `flush` closes the
    /// connection itself once the queue drains, which is what answers a request
    /// without `keepalive` and then hangs up, as the reference does.
    fn close(self: *Client, loop: *xev.Loop) void {
        if (self.dead) return;
        self.dead = true;
        self.closing = true;
        self.maybeClose(loop);
    }

    /// Submit the close, but not before every outstanding read/write has been
    /// completed: those operations write their results into completions owned by
    /// this client, so freeing it first makes the backend touch freed memory when
    /// the cancellation arrives.
    fn maybeClose(self: *Client, loop: *xev.Loop) void {
        if (!self.dead or self.close_submitted or self.inflight != 0) return;
        self.close_submitted = true;
        self.tcp.close(loop, &self.close_completion, Client, self, onClose);
    }

    fn onClose(ud: ?*Client, loop: *xev.Loop, c: *xev.Completion, tcp: xev.TCP, r: xev.CloseError!void) xev.CallbackAction {
        _ = loop;
        _ = c;
        _ = tcp;
        const self = ud.?;
        if (r) |_| {} else |err| log.debug("admin close failed: {}", .{err});
        std.debug.assert(self.inflight == 0);
        self.server.removeClient(self);
        self.destroy();
        return .disarm;
    }
};

test "admin server refuses a URI it cannot serve" {
    const testing = std.testing;
    var heap = std.heap.DebugAllocator(.{}).init;
    defer _ = heap.deinit();
    const gpa = heap.allocator();

    const id = @import("ironwood").Crypto.generate();
    var core = try node.Core.init(gpa, id, @import("ironwood").Config.default(), "");
    defer core.deinit();
    var adm = admin.AdminSocket.init(gpa, &core);
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var server = Server.init(gpa, &loop, &adm);
    defer server.deinit();
    try testing.expectError(error.BadAdminURI, server.start("not a uri"));
    try testing.expectError(error.UnsupportedScheme, server.start("quic://127.0.0.1:1"));
    try testing.expectError(error.BadAdminURI, server.start("tcp://127.0.0.1:notaport"));
    // `unix://` is served: a listener is created on the path and cleaned up in
    // `deinit` (the socket file is unlinked), so binding the same path twice in
    // a row succeeds.
    try server.start("unix:///tmp/ygg-admin-test.sock");

    // Address parsing, including the bracketed IPv6 form `yggdrasilctl` uses.
    const cases = [_]struct { uri: []const u8, host: []const u8, port: u16 }{
        .{ .uri = "tcp://localhost:9001", .host = "localhost", .port = 9001 },
        .{ .uri = "tcp://[::1]:9113", .host = "::1", .port = 9113 },
        .{ .uri = "tcp://0.0.0.0:0", .host = "0.0.0.0", .port = 0 },
    };
    for (cases) |c| {
        const target = try parseAdminUri(c.uri);
        try testing.expectEqualStrings(c.host, target.tcp.host);
        try testing.expectEqual(c.port, target.tcp.port);
    }
    // A host that cannot be resolved is reported as a resolution failure rather
    // than panicking inside the listener setup.
    try testing.expectError(error.ResolveFailed, server.start("tcp://no-such-host.invalid:9001"));
}
