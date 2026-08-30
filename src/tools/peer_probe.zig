//! Peer probe: Ironwood handshake + RTT measurement over every transport the
//! network speaks: `tcp://`, `tls://`, `ws://`, `wss://` and `quic://`.
//!
//! Usage: peer_probe <uri> [password]
//!
//! Each transport wraps a plaintext byte stream (`read`/`writeAll`) so the
//! ironwood metadata handshake + RTT reporting is shared. TLS uses the same
//! wolfSSL memory-BIO bridge as the node (tls_wolfssl.zig) but driven
//! synchronously; WebSocket uses ws.zig's RFC 6455 framing; QUIC uses the
//! zquic client in raw-application-stream mode, exactly like node/quic.zig.

const std = @import("std");
const builtin = @import("builtin");
const ironwood = @import("ironwood");
const node = @import("node");
const c = std.c;
const timemod = @import("util").time;
const is_windows = builtin.os.tag == .windows;

const Metadata = node.version.Metadata;
const Crypto = ironwood.Crypto;

// Raw sockaddr_in for IPv4 -- identical layout on every target this probes
// (2-byte family  2-byte port  4-byte addr  8 bytes of padding), so no
// platform branch is needed for the struct itself, only for socket I/O.
const sockaddr_in = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8 = [_]u8{0} ** 8,
};

// ---------------------------------------------------------------------------
// Winsock2 fallbacks: `std.c.close` calls the CRT's file-handle `close`,
// which is *not* valid on a Winsock `SOCKET` (must use `closesocket`); values
// for AF/SOCK also differ from `std.c`'s POSIX-oriented definitions there.
// ---------------------------------------------------------------------------

const win = struct {
    const ws2_32 = std.os.windows.ws2_32;
    const SOCKET = usize;
    const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);
    extern "ws2_32" fn socket(af: c_int, socktype: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    extern "ws2_32" fn connect(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn send(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
    const WSAPOLLFD = extern struct { fd: SOCKET, events: i16, revents: i16 };
    extern "ws2_32" fn WSAPoll(fds: [*]WSAPOLLFD, nfds: c_ulong, timeout: c_int) callconv(.winapi) c_int;
};

/// Unified socket handle (CRT `c_int` on POSIX, `SOCKET` on Windows).
const Fd = if (is_windows) win.SOCKET else c_int;

const READ_TIMEOUT_MS: i32 = 10_000; // per-read (and per handshake pump) timeout

fn monotonicNanos() u64 {
    return timemod.monotonicNanos();
}

fn netSocket() !Fd {
    if (is_windows) {
        const s = win.socket(win.ws2_32.AF.INET, win.ws2_32.SOCK.STREAM, 0);
        if (s == win.INVALID_SOCKET) return error.SocketFailed;
        return s;
    }
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0);
    if (fd < 0) return error.SocketFailed;
    return fd;
}

fn netConnect(fd: Fd, sa: *const sockaddr_in) !void {
    if (is_windows) {
        if (win.connect(fd, @ptrCast(sa), @sizeOf(sockaddr_in)) != 0) return error.ConnectFailed;
        return;
    }
    if (c.connect(fd, @ptrCast(sa), @sizeOf(sockaddr_in)) < 0) return error.ConnectFailed;
}

fn netRead(fd: Fd, buf: []u8) isize {
    if (is_windows) return win.recv(fd, buf.ptr, @intCast(buf.len), 0);
    return c.read(fd, buf.ptr, buf.len);
}

fn netWrite(fd: Fd, buf: []const u8) isize {
    if (is_windows) return win.send(fd, buf.ptr, @intCast(buf.len), 0);
    return c.write(fd, buf.ptr, buf.len);
}

fn netClose(fd: Fd) void {
    if (is_windows) {
        _ = win.closesocket(fd);
        return;
    }
    _ = c.close(fd);
}

/// Block (up to `timeout_ms`) for the socket to become readable.
fn waitReadable(fd: Fd, timeout_ms: i32) bool {
    if (is_windows) {
        var pfd = [_]win.WSAPOLLFD{.{ .fd = fd, .events = 0x0100, .revents = 0 }}; // POLLRDNORM
        return win.WSAPoll(&pfd, 1, timeout_ms) > 0;
    }
    var pfd = [_]c.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = c.poll(&pfd, 1, timeout_ms);
    return n > 0 and (pfd[0].revents & std.posix.POLL.IN != 0);
}

// ---------------------------------------------------------------------------
// Plaintext byte streams (read/writeAll), one per transport stack.
// ---------------------------------------------------------------------------

/// Raw TCP socket stream.
const RawStream = struct {
    fd: Fd,

    fn read(self: *RawStream, buf: []u8) !usize {
        if (!waitReadable(self.fd, READ_TIMEOUT_MS)) return error.Timeout;
        const n = netRead(self.fd, buf);
        if (n < 0) return error.ReadFailed;
        if (n == 0) return 0; // EOF
        return @intCast(n);
    }

    fn writeAll(self: *RawStream, buf: []const u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = netWrite(self.fd, buf[off..]);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    fn close(self: *RawStream) void {
        netClose(self.fd);
    }
};

/// wolfSSL TLS 1.3 stream over a `RawStream`, driven synchronously.
const TlsStream = struct {
    raw: *RawStream,
    tls: *node.tls_wolfssl.TlsConn,
    gpa: std.mem.Allocator,
    scratch: [16384]u8 = undefined,

    fn flushOutgoing(self: *TlsStream) !void {
        if (self.tls.hasPendingCiphertext()) {
            const bytes = try self.tls.drainCiphertext();
            defer self.gpa.free(bytes);
            try self.raw.writeAll(bytes);
        }
    }

    fn read(self: *TlsStream, buf: []u8) !usize {
        while (true) {
            switch (self.tls.readPlaintext(buf)) {
                .data => |n| {
                    if (n > 0) return n;
                    // A zero-length record is a keepalive; keep reading.
                },
                .result => |r| switch (r) {
                    .want_read => {
                        const n = try self.raw.read(&self.scratch);
                        if (n == 0) return 0; // EOF at TLS layer
                        try self.tls.feedCiphertext(self.scratch[0..n]);
                    },
                    .want_write => try self.flushOutgoing(),
                    .closed => return 0,
                    .fatal => return error.TlsFatal,
                    .ok => {},
                },
            }
        }
    }

    fn writeAll(self: *TlsStream, buf: []const u8) !void {
        var written: usize = 0;
        while (written < buf.len) {
            const r = self.tls.writePlaintext(buf[written..]);
            try self.flushOutgoing();
            switch (r) {
                // wolfSSL_write consumes the whole buffer on success (the
                // ironwood handshake message is far smaller than the write
                // buffer); on want_write it buffered the input and we retry
                // with the same slice after flushing.
                .ok => written = buf.len,
                .want_write, .want_read => {},
                .closed, .fatal => return error.TlsFatal,
            }
        }
    }
};

/// WebSocket (RFC 6455) framing over an arbitrary inner plaintext stream.
/// The probe is a WS *client*, so outbound frames are masked and inbound
/// (server) frames are not; ws.zig's encodeFrame/decodeFrame handle both.
fn WsStream(comptime Inner: type) type {
    return struct {
        inner: *Inner,
        gpa: std.mem.Allocator,
        /// Raw (post-TLS, pre-frame-decode) bytes not yet parsed.
        raw: std.ArrayListUnmanaged(u8) = .empty,
        /// Decoded payload of the current data frame.
        payload: std.ArrayListUnmanaged(u8) = .empty,
        payload_off: usize = 0,
        scratch: [16384]u8 = undefined,

        fn consume(self: *@This(), n: usize) void {
            const remaining = self.raw.items[n..];
            std.mem.copyForwards(u8, self.raw.items[0..remaining.len], remaining);
            self.raw.shrinkRetainingCapacity(remaining.len);
        }

        fn read(self: *@This(), buf: []u8) !usize {
            // Serve any leftover payload from the previous frame first.
            if (self.payload_off < self.payload.items.len) {
                const n = @min(buf.len, self.payload.items.len - self.payload_off);
                @memcpy(buf[0..n], self.payload.items[self.payload_off..][0..n]);
                self.payload_off += n;
                return n;
            }
            while (true) {
                const decoded = node.ws.decodeFrame(self.raw.items) catch |err| switch (err) {
                    error.Incomplete => {
                        const n = try self.inner.read(&self.scratch);
                        if (n == 0) return 0;
                        try self.raw.appendSlice(self.gpa, self.scratch[0..n]);
                        continue;
                    },
                    error.Close => return 0,
                    error.InvalidFrame => return error.WsInvalid,
                };
                switch (decoded.frame.opcode) {
                    .binary, .text, .continuation => {
                        // Copy the payload out before we mutate `raw`.
                        self.payload.clearRetainingCapacity();
                        try self.payload.appendSlice(self.gpa, decoded.frame.payload);
                        self.consume(decoded.consumed);
                        const n = @min(buf.len, self.payload.items.len);
                        @memcpy(buf[0..n], self.payload.items[0..n]);
                        self.payload_off = n;
                        return n;
                    },
                    .ping => {
                        const pong = try node.ws.encodeFrame(self.gpa, .pong, decoded.frame.payload);
                        defer self.gpa.free(pong);
                        try self.inner.writeAll(pong);
                        self.consume(decoded.consumed);
                    },
                    .pong => self.consume(decoded.consumed),
                    .close => return 0,
                }
            }
        }

        fn writeAll(self: *@This(), buf: []const u8) !void {
            const framed = try node.ws.encodeFrame(self.gpa, .binary, buf);
            defer self.gpa.free(framed);
            try self.inner.writeAll(framed);
        }

        fn deinit(self: *@This()) void {
            self.raw.deinit(self.gpa);
            self.payload.deinit(self.gpa);
        }
    };
}

/// QUIC stream over zquic's raw-application-stream client.
const QuicStream = struct {
    gpa: std.mem.Allocator,
    client: *node.quic.io.Client,
    stream_id: u64,
    recv_off: usize = 0,
    scratch: [2048]u8 = undefined,

    fn pump(self: *QuicStream) void {
        while (true) {
            const n: isize = std.posix.system.recvfrom(
                self.client.sock,
                self.scratch[0..].ptr,
                self.scratch.len,
                std.posix.MSG.DONTWAIT,
                null,
                null,
            );
            if (n <= 0) break;
            self.client.feedPacket(self.scratch[0..@intCast(n)]);
        }
        self.client.processPendingWork(self.client.conn.peer);
        self.client.flushDeferredAck();
    }

    fn read(self: *QuicStream, buf: []u8) !usize {
        while (true) {
            self.pump();
            if (self.client.rawAppRecvBuffer(self.stream_id)) |got| {
                if (got.len > self.recv_off) {
                    const fresh = got[self.recv_off..];
                    const n = @min(buf.len, fresh.len);
                    @memcpy(buf[0..n], fresh[0..n]);
                    self.recv_off += n;
                    return n;
                }
            }
            if (!waitReadable(self.client.sock, 2000)) return error.Timeout;
        }
    }

    fn writeAll(self: *QuicStream, buf: []const u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            self.pump();
            const n = self.client.sendRawStreamData(self.stream_id, off, buf[off..], false);
            if (n == 0) {
                if (!waitReadable(self.client.sock, 2000)) return error.Timeout;
                continue;
            }
            off += n;
        }
        self.client.processPendingWork(self.client.conn.peer);
        self.client.flushDeferredAck();
    }

    fn deinit(self: *QuicStream) void {
        node.quic.destroyClient(self.gpa, self.client);
    }
};

// ---------------------------------------------------------------------------
// Handshake + reporting (shared across transports)
// ---------------------------------------------------------------------------

fn readExact(stream: anytype, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try stream.read(buf[off..]);
        if (n == 0) return error.Eof;
        off += n;
    }
}

fn probeHandshake(stream: anytype, our_id: *const Crypto, password: []const u8, gpa: std.mem.Allocator, t0: u64, t1: u64) !void {
    const our_meta = Metadata.init(our_id.public_key, 0);
    const our_msg = try our_meta.encode(our_id, password, gpa);
    defer gpa.free(our_msg);

    try stream.writeAll(our_msg);

    var header: [6]u8 = undefined;
    try readExact(stream, &header);
    const body_len = std.mem.readInt(u16, header[4..6], .big);
    if (body_len > 8192) return error.OversizedMessage;

    const body = try gpa.alloc(u8, body_len);
    defer gpa.free(body);
    try readExact(stream, body);

    const t2 = monotonicNanos();
    try report(gpa, &header, body, password, t0, t1, t2);
}

fn report(gpa: std.mem.Allocator, header: *const [6]u8, body: []const u8, password: []const u8, t0: u64, t1: u64, t2: u64) !void {
    const rtt_us = (t2 - t0) / 1000;
    const connect_us = (t1 - t0) / 1000;
    var full = std.ArrayListUnmanaged(u8).empty;
    defer full.deinit(gpa);
    full.appendSlice(gpa, header) catch return error.Oom;
    full.appendSlice(gpa, body) catch return error.Oom;

    const peer_meta = Metadata.decode(full.items, password, gpa) catch |e| {
        std.debug.print("FAIL|decode|{s}\n", .{@errorName(e)});
        return;
    };

    var key_hex: [64]u8 = undefined;
    const hx = "0123456789abcdef";
    for (peer_meta.public_key, 0..) |b, i| {
        key_hex[i * 2] = hx[(b >> 4) & 0xF];
        key_hex[i * 2 + 1] = hx[b & 0xF];
    }

    std.debug.print("OK|rtt_us={d}|connect_us={d}|key={s}|ver={}.{}\n", .{
        rtt_us, connect_us, key_hex, peer_meta.major_ver, peer_meta.minor_ver,
    });
}

// ---------------------------------------------------------------------------
// Transport setup
// ---------------------------------------------------------------------------

const TlsClient = struct {
    ctx: *node.tls_wolfssl.WOLFSSL_CTX,
    tls: *node.tls_wolfssl.TlsConn,
    ident: node.tls_wolfssl.IdentityCert,

    fn deinit(self: *TlsClient, gpa: std.mem.Allocator) void {
        self.tls.deinit();
        node.tls_wolfssl.freeCtx(self.ctx);
        self.ident.deinit(gpa);
        node.tls_wolfssl.globalDeinit();
    }
};

fn initTls(gpa: std.mem.Allocator, our_id: *const Crypto, sni: []const u8) !TlsClient {
    try node.tls_wolfssl.globalInit();
    errdefer node.tls_wolfssl.globalDeinit();

    var key_hex_buf: [64]u8 = undefined;
    const key_hex = std.fmt.bufPrint(&key_hex_buf, "{x}", .{our_id.public_key}) catch unreachable;

    var ident = try node.tls_wolfssl.generateIdentityCert(gpa, our_id.key_pair.secret_key.seed(), key_hex);
    errdefer ident.deinit(gpa);

    const ctx = try node.tls_wolfssl.newClientCtx();
    errdefer node.tls_wolfssl.freeCtx(ctx);
    try node.tls_wolfssl.configureIdentity(ctx, ident.cert_der, ident.key_der);
    node.tls_wolfssl.installMemoryIO(ctx);

    const tls = try node.tls_wolfssl.TlsConn.init(gpa, ctx, sni);
    errdefer tls.deinit();

    return .{ .ctx = ctx, .tls = tls, .ident = ident };
}

/// Drive the wolfSSL client handshake to completion over `raw`.
fn tlsConnect(raw: *RawStream, tls: *node.tls_wolfssl.TlsConn, gpa: std.mem.Allocator) !void {
    var scratch: [16384]u8 = undefined;
    var rounds: usize = 0;
    while (!tls.isHandshakeDone()) {
        rounds += 1;
        if (rounds > 1000) return error.TlsHandshakeTimeout;

        const r = tls.pumpHandshake(false);
        if (tls.hasPendingCiphertext()) {
            const bytes = try tls.drainCiphertext();
            defer gpa.free(bytes);
            try raw.writeAll(bytes);
        }
        // The pump may have just finished the handshake (TLS 1.2 has no
        // post-handshake flight); check before blocking on a read that will
        // never complete.
        if (tls.isHandshakeDone()) break;
        switch (r) {
            .want_read => {
                const n = try raw.read(&scratch);
                if (n == 0) return error.TlsClosed;
                try tls.feedCiphertext(scratch[0..n]);
            },
            .want_write => {}, // flushed above; retry
            .ok => {}, // handshake done; loop condition will exit
            .closed, .fatal => return error.TlsFatal,
        }
    }
}

/// Perform the RFC 6455 client upgrade over `inner`, returning the bytes read
/// past the end of the HTTP response (caller owns; seeds the WsStream buffer).
fn wsUpgrade(inner: anytype, host: []const u8, port: u16, path: []const u8, key_b64: *const [24]u8, accept_b64: *const [28]u8, gpa: std.mem.Allocator) ![]u8 {
    const req = try node.ws.buildClientUpgrade(gpa, host, port, path, key_b64);
    defer gpa.free(req);
    try inner.writeAll(req);

    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(gpa);
    var scratch: [4096]u8 = undefined;
    while (std.mem.indexOf(u8, buf.items, "\r\n\r\n") == null) {
        const n = try inner.read(&scratch);
        if (n == 0) return error.Eof;
        try buf.appendSlice(gpa, scratch[0..n]);
    }
    const parsed = node.ws.parseServerUpgrade(buf.items, accept_b64) orelse return error.Eof;
    if (!parsed.ok) return error.BadWsUpgrade;
    const leftover = try gpa.dupe(u8, buf.items[parsed.consumed..]);
    return leftover;
}

// ---------------------------------------------------------------------------
// Per-scheme probe entry points
// ---------------------------------------------------------------------------

fn probeTcp(raw: *RawStream, our_id: *const Crypto, password: []const u8, gpa: std.mem.Allocator, t0: u64) !void {
    try probeHandshake(raw, our_id, password, gpa, t0, monotonicNanos());
}

fn probeTls(raw: *RawStream, tls_client: *TlsClient, our_id: *const Crypto, password: []const u8, gpa: std.mem.Allocator, t0: u64) !void {
    try tlsConnect(raw, tls_client.tls, gpa);
    var stream = TlsStream{ .raw = raw, .tls = tls_client.tls, .gpa = gpa };
    try probeHandshake(&stream, our_id, password, gpa, t0, monotonicNanos());
}

fn probeWs(comptime Inner: type, inner: *Inner, host: []const u8, port: u16, path: []const u8, our_id: *const Crypto, password: []const u8, gpa: std.mem.Allocator, t0: u64) !void {
    var key_b64: [24]u8 = undefined;
    var accept_b64: [28]u8 = undefined;
    node.ws.generateKey(&key_b64);
    node.ws.acceptKey(&key_b64, &accept_b64);

    const leftover = try wsUpgrade(inner, host, port, path, &key_b64, &accept_b64, gpa);
    defer gpa.free(leftover);

    var stream = WsStream(Inner){ .inner = inner, .gpa = gpa };
    defer stream.deinit();
    try stream.raw.appendSlice(gpa, leftover);

    try probeHandshake(&stream, our_id, password, gpa, t0, monotonicNanos());
}

fn probeQuic(stream: *QuicStream, our_id: *const Crypto, password: []const u8, gpa: std.mem.Allocator, t0: u64) !void {
    try probeHandshake(stream, our_id, password, gpa, t0, monotonicNanos());
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const args = init.minimal.args;
    var args_iter = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer args_iter.deinit();
    _ = args_iter.next();

    const uri = args_iter.next() orelse {
        std.debug.print("Usage: peer_probe <uri> [password]\n", .{});
        return;
    };
    const password = args_iter.next() orelse "";

    const parsed = node.links.parsePeerURI(uri) catch |e| {
        std.debug.print("FAIL|uri|{s}\n", .{@errorName(e)});
        return;
    };

    const scheme = parsed.scheme;
    const is_scheme = struct {
        fn eq(s: []const u8, want: []const u8) bool {
            return std.ascii.eqlIgnoreCase(s, want);
        }
    }.eq;

    const our_id = Crypto.generate();

    // Resolve the peer (IP literals pass straight through; hostnames go via
    // getaddrinfo) and take the first IPv4 address.
    const addrs = node.dns.resolve(gpa, parsed.host, parsed.port) catch |e| {
        std.debug.print("FAIL|resolve|{s}\n", .{@errorName(e)});
        return;
    };
    defer gpa.free(addrs);
    var ip4: ?std.Io.net.Ip4Address = null;
    for (addrs) |a| switch (a) {
        .ip4 => |v| {
            ip4 = v;
            break;
        },
        else => {},
    };
    const ipv4 = ip4 orelse {
        std.debug.print("FAIL|no_ipv4\n", .{});
        return;
    };

    const t0 = monotonicNanos();

    if (is_scheme(scheme, "quic")) {
        try runQuic(gpa, &our_id, password, parsed.host, ipv4.bytes, ipv4.port, t0);
        return;
    }

    // tcp / tls / ws / wss all start from a TCP connection.
    const ip_be: u32 = (@as(u32, ipv4.bytes[0]) << 0) |
        (@as(u32, ipv4.bytes[1]) << 8) |
        (@as(u32, ipv4.bytes[2]) << 16) |
        (@as(u32, ipv4.bytes[3]) << 24);
    const family: u16 = if (is_windows) win.ws2_32.AF.INET else @intCast(c.AF.INET);
    var sa: sockaddr_in = .{ .family = family, .port = std.mem.nativeToBig(u16, ipv4.port), .addr = ip_be };

    const fd = netSocket() catch |e| {
        std.debug.print("FAIL|socket|{s}\n", .{@errorName(e)});
        return;
    };
    var raw = RawStream{ .fd = fd };
    defer raw.close();

    netConnect(fd, &sa) catch |e| {
        std.debug.print("FAIL|connect|{s}\n", .{@errorName(e)});
        return;
    };

    if (is_scheme(scheme, "tls") or is_scheme(scheme, "wss")) {
        var tls_client = initTls(gpa, &our_id, parsed.host) catch |e| {
            std.debug.print("FAIL|tls_init|{s}\n", .{@errorName(e)});
            return;
        };
        defer tls_client.deinit(gpa);

        if (is_scheme(scheme, "tls")) {
            probeTls(&raw, &tls_client, &our_id, password, gpa, t0) catch |e| {
                std.debug.print("FAIL|tls|{s}\n", .{@errorName(e)});
                return;
            };
        } else {
            // wss: TLS then the WebSocket upgrade.
            tlsConnect(&raw, tls_client.tls, gpa) catch |e| {
                std.debug.print("FAIL|tls|{s}\n", .{@errorName(e)});
                return;
            };
            var tls_stream = TlsStream{ .raw = &raw, .tls = tls_client.tls, .gpa = gpa };
            probeWs(TlsStream, &tls_stream, parsed.host, ipv4.port, parsed.path, &our_id, password, gpa, t0) catch |e| {
                std.debug.print("FAIL|wss|{s}\n", .{@errorName(e)});
                return;
            };
        }
    } else if (is_scheme(scheme, "ws")) {
        probeWs(RawStream, &raw, parsed.host, ipv4.port, parsed.path, &our_id, password, gpa, t0) catch |e| {
            std.debug.print("FAIL|ws|{s}\n", .{@errorName(e)});
            return;
        };
    } else {
        // tcp (and anything else that parses) falls through to plain TCP.
        probeTcp(&raw, &our_id, password, gpa, t0) catch |e| {
            std.debug.print("FAIL|tcp|{s}\n", .{@errorName(e)});
            return;
        };
    }
}

fn runQuic(gpa: std.mem.Allocator, our_id: *const Crypto, password: []const u8, host: []const u8, ip: [4]u8, port: u16, t0: u64) !void {
    const client = node.quic.createClient(gpa, host, port) catch |e| {
        std.debug.print("FAIL|quic_create|{s}\n", .{@errorName(e)});
        return;
    };
    node.quic.setPeerIpv4(client, ip, port);
    node.quic.startHandshake(client) catch |e| {
        std.debug.print("FAIL|quic_start|{s}\n", .{@errorName(e)});
        node.quic.destroyClient(gpa, client);
        return;
    };

    var stream = QuicStream{ .gpa = gpa, .client = client, .stream_id = 0 };

    const deadline = monotonicNanos() + 15 * std.time.ns_per_s;
    while (!node.quic.isConnected(client)) {
        stream.pump();
        if (monotonicNanos() > deadline) {
            std.debug.print("FAIL|quic_connect|Timeout\n", .{});
            stream.deinit();
            return;
        }
        if (!waitReadable(client.sock, 100)) continue;
    }

    const sid = client.tryOpenLocalBidiStream() catch |e| {
        std.debug.print("FAIL|quic_stream|{s}\n", .{@errorName(e)});
        stream.deinit();
        return;
    };
    stream.stream_id = sid;
    defer stream.deinit();

    probeQuic(&stream, our_id, password, gpa, t0) catch |e| {
        std.debug.print("FAIL|quic|{s}\n", .{@errorName(e)});
        return;
    };
}
