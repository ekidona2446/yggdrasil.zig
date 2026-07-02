//! Wire protocol: message types, encoding, and decoding.
//!
//! Frame format: `length(uvarint) | type(u8) | payload`
//! All variable-length integers use unsigned LEB128 (uvarint), compatible
//! with Go's `encoding/binary` uvarint.
//! Paths are sequences of uvarint port numbers terminated by a 0.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged(u8);

const types = @import("types.zig");
const Error = types.Error;
const cryptomod = @import("crypto.zig");
const PublicKey = cryptomod.PublicKey;
const Sig = cryptomod.Sig;
const PUBLIC_KEY_SIZE = cryptomod.PUBLIC_KEY_SIZE;
const SIGNATURE_SIZE = cryptomod.SIGNATURE_SIZE;

/// Port identifier for a peer link on the spanning tree.
pub const PeerPort = u64;

// ---------------------------------------------------------------------------
// Packet types
// ---------------------------------------------------------------------------

pub const PacketType = enum(u8) {
    dummy = 0,
    keep_alive = 1,
    proto_sig_req = 2,
    proto_sig_res = 3,
    proto_announce = 4,
    proto_bloom_filter = 5,
    proto_path_lookup = 6,
    proto_path_notify = 7,
    proto_path_broken = 8,
    traffic = 9,

    pub fn fromByte(v: u8) Error!PacketType {
        return switch (v) {
            0...9 => @enumFromInt(v),
            else => Error.UnrecognizedMessage,
        };
    }
};

// ---------------------------------------------------------------------------
// Uvarint helpers (unsigned LEB128)
// ---------------------------------------------------------------------------

pub fn encodeUvarint(out: *ArrayList, gpa: Allocator, value_in: u64) Allocator.Error!void {
    var value = value_in;
    while (true) {
        var byte: u8 = @intCast(value & 0x7F);
        value >>= 7;
        if (value != 0) byte |= 0x80;
        try out.append(gpa, byte);
        if (value == 0) break;
    }
}

/// Decode a uvarint from the front of `data`.
/// Returns the value and number of bytes consumed, or an error.
pub const Uvarint = struct { value: u64, len: usize };

pub fn decodeUvarint(data: []const u8) Error!Uvarint {
    var value: u64 = 0;
    var shift: u6 = 0;
    for (data, 0..) |byte, i| {
        if (shift >= 63 and byte > 1) return Error.Decode; // overflow
        value |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return .{ .value = value, .len = i + 1 };
        shift += 7;
        if (i >= 9) return Error.Decode; // too many bytes
    }
    return Error.Decode; // incomplete
}

pub fn uvarintSize(value_in: u64) usize {
    var value = value_in;
    var size: usize = 1;
    while (value >= 0x80) : (size += 1) value >>= 7;
    return size;
}

// ---------------------------------------------------------------------------
// Path helpers (zero-terminated uvarint sequences)
// ---------------------------------------------------------------------------

pub fn encodePath(out: *ArrayList, gpa: Allocator, path: []const PeerPort) Allocator.Error!void {
    for (path) |port| try encodeUvarint(out, gpa, port);
    try encodeUvarint(out, gpa, 0); // terminator
}

pub fn pathSize(path: []const PeerPort) usize {
    var size: usize = 0;
    for (path) |port| size += uvarintSize(port);
    size += uvarintSize(0);
    return size;
}

pub const DecodedPath = struct { path: []PeerPort, len: usize };

/// Decode a zero-terminated path. Caller owns the returned slice.
pub fn decodePath(gpa: Allocator, data: []const u8) Error!DecodedPath {
    var path = std.ArrayListUnmanaged(PeerPort).empty;
    errdefer path.deinit(gpa);
    var offset: usize = 0;
    while (true) {
        const v = try decodeUvarint(data[offset..]);
        offset += v.len;
        if (v.value == 0) break;
        try path.append(gpa, v.value);
    }
    return .{ .path = try path.toOwnedSlice(gpa), .len = offset };
}

// ---------------------------------------------------------------------------
// WireReader: cursor over a byte slice
// ---------------------------------------------------------------------------

pub const WireReader = struct {
    data: []const u8,

    pub fn init(data: []const u8) WireReader {
        return .{ .data = data };
    }

    pub fn isEmpty(self: *const WireReader) bool {
        return self.data.len == 0;
    }

    pub fn rest(self: *const WireReader) []const u8 {
        return self.data;
    }

    pub fn readUvarint(self: *WireReader) Error!u64 {
        const v = try decodeUvarint(self.data);
        self.data = self.data[v.len..];
        return v.value;
    }

    pub fn readFixed(self: *WireReader, comptime N: usize) Error![N]u8 {
        if (self.data.len < N) return Error.Decode;
        var out: [N]u8 = undefined;
        @memcpy(&out, self.data[0..N]);
        self.data = self.data[N..];
        return out;
    }

    pub fn readPublicKey(self: *WireReader) Error!PublicKey {
        return self.readFixed(PUBLIC_KEY_SIZE);
    }

    pub fn readSignature(self: *WireReader) Error!Sig {
        return self.readFixed(SIGNATURE_SIZE);
    }

    /// Caller owns the returned path slice.
    pub fn readPath(self: *WireReader, gpa: Allocator) Error![]PeerPort {
        const dp = try decodePath(gpa, self.data);
        self.data = self.data[dp.len..];
        return dp.path;
    }
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

pub const SigReq = struct {
    seq: u64,
    nonce: u64,

    pub fn encode(self: *const SigReq, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try encodeUvarint(out, gpa, self.seq);
        try encodeUvarint(out, gpa, self.nonce);
    }

    pub fn decode(r: *WireReader) Error!SigReq {
        const seq = try r.readUvarint();
        const nonce = try r.readUvarint();
        return .{ .seq = seq, .nonce = nonce };
    }
};

pub const SigRes = struct {
    seq: u64,
    nonce: u64,
    port: PeerPort,
    psig: Sig,

    pub fn encode(self: *const SigRes, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try encodeUvarint(out, gpa, self.seq);
        try encodeUvarint(out, gpa, self.nonce);
        try encodeUvarint(out, gpa, self.port);
        try out.appendSlice(gpa, &self.psig);
    }

    pub fn decode(r: *WireReader) Error!SigRes {
        const seq = try r.readUvarint();
        const nonce = try r.readUvarint();
        const port = try r.readUvarint();
        const psig = try r.readSignature();
        return .{ .seq = seq, .nonce = nonce, .port = port, .psig = psig };
    }
};

pub const Announce = struct {
    key: PublicKey,
    parent: PublicKey,
    sig_res: SigRes,
    sig: Sig,

    pub fn encode(self: *const Announce, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try out.appendSlice(gpa, &self.key);
        try out.appendSlice(gpa, &self.parent);
        try self.sig_res.encode(out, gpa);
        try out.appendSlice(gpa, &self.sig);
    }

    pub fn decode(data: []const u8) Error!Announce {
        var r = WireReader.init(data);
        const key = try r.readPublicKey();
        const parent = try r.readPublicKey();
        const sig_res = try SigRes.decode(&r);
        const sig = try r.readSignature();
        if (!r.isEmpty()) return Error.Decode;
        return .{ .key = key, .parent = parent, .sig_res = sig_res, .sig = sig };
    }
};

/// Path lookup request.
///
/// Owns the `from` path slice; call `deinit` to free it.
pub const PathLookup = struct {
    source: PublicKey,
    dest: PublicKey,
    from: []PeerPort,

    pub fn deinit(self: *PathLookup, gpa: Allocator) void {
        gpa.free(self.from);
        self.from = &.{};
    }

    pub fn encode(self: *const PathLookup, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try out.appendSlice(gpa, &self.source);
        try out.appendSlice(gpa, &self.dest);
        try encodePath(out, gpa, self.from);
    }

    pub fn decode(gpa: Allocator, data: []const u8) Error!PathLookup {
        var r = WireReader.init(data);
        const source = try r.readPublicKey();
        const dest = try r.readPublicKey();
        const from = try r.readPath(gpa);
        errdefer gpa.free(from);
        if (!r.isEmpty()) return Error.Decode;
        return .{ .source = source, .dest = dest, .from = from };
    }
};

/// Signed path info (part of PathNotify).
///
/// Owns the `path` slice; call `deinit` to free it.
pub const PathNotifyInfo = struct {
    seq: u64,
    path: []PeerPort,
    sig: Sig,

    pub fn deinit(self: *PathNotifyInfo, gpa: Allocator) void {
        gpa.free(self.path);
        self.path = &.{};
    }

    pub fn encode(self: *const PathNotifyInfo, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try encodeUvarint(out, gpa, self.seq);
        try encodePath(out, gpa, self.path);
        try out.appendSlice(gpa, &self.sig);
    }

    pub fn decode(gpa: Allocator, r: *WireReader) Error!PathNotifyInfo {
        const seq = try r.readUvarint();
        const path = try r.readPath(gpa);
        errdefer gpa.free(path);
        const sig = try r.readSignature();
        return .{ .seq = seq, .path = path, .sig = sig };
    }
};

/// Path notification (response to PathLookup).
///
/// Owns the `path` slice and `info.path`; call `deinit` to free both.
pub const PathNotify = struct {
    path: []PeerPort,
    watermark: u64,
    source: PublicKey,
    dest: PublicKey,
    info: PathNotifyInfo,

    pub fn deinit(self: *PathNotify, gpa: Allocator) void {
        gpa.free(self.path);
        self.path = &.{};
        self.info.deinit(gpa);
    }

    pub fn encode(self: *const PathNotify, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try encodePath(out, gpa, self.path);
        try encodeUvarint(out, gpa, self.watermark);
        try out.appendSlice(gpa, &self.source);
        try out.appendSlice(gpa, &self.dest);
        try self.info.encode(out, gpa);
    }

    pub fn decode(gpa: Allocator, data: []const u8) Error!PathNotify {
        var r = WireReader.init(data);
        const path = try r.readPath(gpa);
        errdefer gpa.free(path);
        const watermark = try r.readUvarint();
        const source = try r.readPublicKey();
        const dest = try r.readPublicKey();
        var info = try PathNotifyInfo.decode(gpa, &r);
        errdefer info.deinit(gpa);
        if (!r.isEmpty()) return Error.Decode;
        return .{ .path = path, .watermark = watermark, .source = source, .dest = dest, .info = info };
    }
};

/// Path broken notification.
///
/// Owns the `path` slice; call `deinit` to free it.
pub const PathBroken = struct {
    path: []PeerPort,
    watermark: u64,
    source: PublicKey,
    dest: PublicKey,

    pub fn deinit(self: *PathBroken, gpa: Allocator) void {
        gpa.free(self.path);
        self.path = &.{};
    }

    pub fn encode(self: *const PathBroken, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try encodePath(out, gpa, self.path);
        try encodeUvarint(out, gpa, self.watermark);
        try out.appendSlice(gpa, &self.source);
        try out.appendSlice(gpa, &self.dest);
    }

    pub fn decode(gpa: Allocator, data: []const u8) Error!PathBroken {
        var r = WireReader.init(data);
        const path = try r.readPath(gpa);
        errdefer gpa.free(path);
        const watermark = try r.readUvarint();
        const source = try r.readPublicKey();
        const dest = try r.readPublicKey();
        if (!r.isEmpty()) return Error.Decode;
        return .{ .path = path, .watermark = watermark, .source = source, .dest = dest };
    }
};

/// User traffic packet.
///
/// Owns `path`, `from`, and `payload`; call `deinit` to free all three.
pub const Traffic = struct {
    path: []PeerPort,
    from: []PeerPort,
    source: PublicKey,
    dest: PublicKey,
    watermark: u64,
    payload: []u8,

    pub fn deinit(self: *Traffic, gpa: Allocator) void {
        gpa.free(self.path);
        gpa.free(self.from);
        gpa.free(self.payload);
        self.path = &.{};
        self.from = &.{};
        self.payload = &.{};
    }

    pub fn size(self: *const Traffic) usize {
        return pathSize(self.path) + pathSize(self.from) +
            PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE +
            uvarintSize(self.watermark) + self.payload.len;
    }

    pub fn encode(self: *const Traffic, out: *ArrayList, gpa: Allocator) Allocator.Error!void {
        try encodePath(out, gpa, self.path);
        try encodePath(out, gpa, self.from);
        try out.appendSlice(gpa, &self.source);
        try out.appendSlice(gpa, &self.dest);
        try encodeUvarint(out, gpa, self.watermark);
        try out.appendSlice(gpa, self.payload);
    }

    pub fn decode(gpa: Allocator, data: []const u8) Error!Traffic {
        var r = WireReader.init(data);
        const path = try r.readPath(gpa);
        errdefer gpa.free(path);
        const from = try r.readPath(gpa);
        errdefer gpa.free(from);
        const source = try r.readPublicKey();
        const dest = try r.readPublicKey();
        const watermark = try r.readUvarint();
        const payload = try gpa.dupe(u8, r.rest());
        return .{
            .path = path,
            .from = from,
            .source = source,
            .dest = dest,
            .watermark = watermark,
            .payload = payload,
        };
    }
};

// ---------------------------------------------------------------------------
// Bloom filter wire encoding (compatible with Go bits-and-blooms/bloom)
// ---------------------------------------------------------------------------

/// Number of bytes for the zero/one flag bitmaps (BLOOM_FILTER_U64S / 8).
pub const BLOOM_FILTER_FLAGS: usize = 16;
/// Number of u64 words in the bloom filter backing array.
pub const BLOOM_FILTER_U64S: usize = 128;

/// Encode a bloom filter's backing u64 array with run-length compression of
/// all-zero and all-ones chunks.
/// Format: [16 bytes flags0 (zero chunks)][16 bytes flags1 (ones chunks)][remaining u64s big-endian]
pub fn encodeBloom(out: *ArrayList, gpa: Allocator, data: *const [BLOOM_FILTER_U64S]u64) Allocator.Error!void {
    var flags0 = [_]u8{0} ** BLOOM_FILTER_FLAGS;
    var flags1 = [_]u8{0} ** BLOOM_FILTER_FLAGS;

    for (data, 0..) |u, idx| {
        if (u == 0) {
            flags0[idx / 8] |= @as(u8, 0x80) >> @intCast(idx % 8);
        } else if (u == std.math.maxInt(u64)) {
            flags1[idx / 8] |= @as(u8, 0x80) >> @intCast(idx % 8);
        }
    }

    try out.appendSlice(gpa, &flags0);
    try out.appendSlice(gpa, &flags1);
    for (data) |u| {
        if (u != 0 and u != std.math.maxInt(u64)) {
            var be: [8]u8 = undefined;
            std.mem.writeInt(u64, &be, u, .big);
            try out.appendSlice(gpa, &be);
        }
    }
}

/// Decode a bloom filter from wire format into a fixed u64 array.
pub fn decodeBloom(data: []const u8) Error![BLOOM_FILTER_U64S]u64 {
    var r = WireReader.init(data);
    const flags0 = try r.readFixed(BLOOM_FILTER_FLAGS);
    const flags1 = try r.readFixed(BLOOM_FILTER_FLAGS);

    var result = [_]u64{0} ** BLOOM_FILTER_U64S;
    for (0..BLOOM_FILTER_U64S) |idx| {
        const mask = @as(u8, 0x80) >> @intCast(idx % 8);
        const f0 = flags0[idx / 8] & mask;
        const f1 = flags1[idx / 8] & mask;
        if (f0 != 0 and f1 != 0) {
            return Error.Decode; // can't be both zero and all-ones
        } else if (f0 != 0) {
            result[idx] = 0;
        } else if (f1 != 0) {
            result[idx] = std.math.maxInt(u64);
        } else {
            const be = try r.readFixed(8);
            result[idx] = std.mem.readInt(u64, &be, .big);
        }
    }

    if (!r.isEmpty()) return Error.Decode;
    return result;
}

/// Compute the wire size of an encoded bloom filter.
pub fn bloomWireSize(data: *const [BLOOM_FILTER_U64S]u64) usize {
    var size: usize = BLOOM_FILTER_FLAGS * 2;
    for (data) |u| {
        if (u != 0 and u != std.math.maxInt(u64)) size += 8;
    }
    return size;
}

// ---------------------------------------------------------------------------
// Frame-level encode/decode
// ---------------------------------------------------------------------------

/// Encode a complete wire frame: length(uvarint) | type(u8) | payload.
/// Caller owns the returned slice.
pub fn encodeFrame(gpa: Allocator, packet_type: PacketType, payload: []const u8) Allocator.Error![]u8 {
    const content_len = 1 + payload.len;
    var frame = ArrayList.empty;
    errdefer frame.deinit(gpa);
    try frame.ensureTotalCapacity(gpa, uvarintSize(content_len) + content_len);
    try encodeUvarint(&frame, gpa, content_len);
    try frame.append(gpa, @intFromEnum(packet_type));
    try frame.appendSlice(gpa, payload);
    return frame.toOwnedSlice(gpa);
}

/// Encode a traffic packet directly into a single wire frame in one allocation,
/// avoiding the intermediate `Traffic` struct + payload copy.
///
/// Format: `[uvarint content_len][0x09 Traffic][path][from][source][dest][watermark][payload]`
/// Caller owns the returned slice.
pub fn encodeTrafficFrame(
    gpa: Allocator,
    path: []const PeerPort,
    from: []const PeerPort,
    source: *const PublicKey,
    dest: *const PublicKey,
    watermark: u64,
    payload: []const u8,
) Allocator.Error![]u8 {
    const content_len = 1 // type byte
        + pathSize(path) + pathSize(from) +
        PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE +
        uvarintSize(watermark) + payload.len;
    var frame = ArrayList.empty;
    errdefer frame.deinit(gpa);
    try frame.ensureTotalCapacity(gpa, uvarintSize(content_len) + content_len);
    try encodeUvarint(&frame, gpa, content_len);
    try frame.append(gpa, @intFromEnum(PacketType.traffic));
    try encodePath(&frame, gpa, path);
    try encodePath(&frame, gpa, from);
    try frame.appendSlice(gpa, source);
    try frame.appendSlice(gpa, dest);
    try encodeUvarint(&frame, gpa, watermark);
    try frame.appendSlice(gpa, payload);
    return frame.toOwnedSlice(gpa);
}

pub const DecodedFrame = struct {
    packet_type: PacketType,
    payload: []const u8,
    consumed: usize,
};

/// Decode a frame header from the front of `data`.
pub fn decodeFrame(data: []const u8) Error!DecodedFrame {
    const len = try decodeUvarint(data);
    const length: usize = @intCast(len.value);
    if (data.len < len.len + length) return Error.Decode;
    const content = data[len.len .. len.len + length];
    if (content.len == 0) return Error.Decode;
    const packet_type = try PacketType.fromByte(content[0]);
    return .{
        .packet_type = packet_type,
        .payload = content[1..],
        .consumed = len.len + length,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "uvarint roundtrip" {
    const vals = [_]u64{ 0, 1, 127, 128, 255, 256, 16383, 16384, std.math.maxInt(u64) >> 1 };
    for (vals) |val| {
        var buf = ArrayList.empty;
        defer buf.deinit(testing.allocator);
        try encodeUvarint(&buf, testing.allocator, val);
        const dec = try decodeUvarint(buf.items);
        try testing.expectEqual(val, dec.value);
        try testing.expectEqual(buf.items.len, dec.len);
        try testing.expectEqual(buf.items.len, uvarintSize(val));
    }
}

test "path roundtrip" {
    const path = [_]PeerPort{ 1, 2, 300, 65535 };
    var buf = ArrayList.empty;
    defer buf.deinit(testing.allocator);
    try encodePath(&buf, testing.allocator, &path);
    try testing.expectEqual(pathSize(&path), buf.items.len);
    const dec = try decodePath(testing.allocator, buf.items);
    defer testing.allocator.free(dec.path);
    try testing.expectEqualSlices(PeerPort, &path, dec.path);
    try testing.expectEqual(buf.items.len, dec.len);
}

test "empty path roundtrip" {
    const path = [_]PeerPort{};
    var buf = ArrayList.empty;
    defer buf.deinit(testing.allocator);
    try encodePath(&buf, testing.allocator, &path);
    const dec = try decodePath(testing.allocator, buf.items);
    defer testing.allocator.free(dec.path);
    try testing.expectEqual(@as(usize, 0), dec.path.len);
}

test "sig_req roundtrip" {
    const req = SigReq{ .seq = 42, .nonce = 123456789 };
    var buf = ArrayList.empty;
    defer buf.deinit(testing.allocator);
    try req.encode(&buf, testing.allocator);
    var r = WireReader.init(buf.items);
    const dec = try SigReq.decode(&r);
    try testing.expectEqual(@as(u64, 42), dec.seq);
    try testing.expectEqual(@as(u64, 123456789), dec.nonce);
    try testing.expect(r.isEmpty());
}

test "sig_res roundtrip" {
    const res = SigRes{ .seq = 1, .nonce = 2, .port = 5, .psig = [_]u8{0xAB} ** 64 };
    var buf = ArrayList.empty;
    defer buf.deinit(testing.allocator);
    try res.encode(&buf, testing.allocator);
    var r = WireReader.init(buf.items);
    const dec = try SigRes.decode(&r);
    try testing.expectEqual(@as(u64, 1), dec.seq);
    try testing.expectEqual(@as(u64, 2), dec.nonce);
    try testing.expectEqual(@as(PeerPort, 5), dec.port);
    try testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 64), &dec.psig);
    try testing.expect(r.isEmpty());
}

test "announce roundtrip" {
    const ann = Announce{
        .key = [_]u8{1} ** 32,
        .parent = [_]u8{2} ** 32,
        .sig_res = .{ .seq = 10, .nonce = 20, .port = 3, .psig = [_]u8{0xCC} ** 64 },
        .sig = [_]u8{0xDD} ** 64,
    };
    var buf = ArrayList.empty;
    defer buf.deinit(testing.allocator);
    try ann.encode(&buf, testing.allocator);
    const dec = try Announce.decode(buf.items);
    try testing.expectEqualSlices(u8, &([_]u8{1} ** 32), &dec.key);
    try testing.expectEqualSlices(u8, &([_]u8{2} ** 32), &dec.parent);
    try testing.expectEqual(@as(u64, 10), dec.sig_res.seq);
    try testing.expectEqualSlices(u8, &([_]u8{0xDD} ** 64), &dec.sig);
}

test "frame roundtrip" {
    const payload = "test payload";
    const frame = try encodeFrame(testing.allocator, .traffic, payload);
    defer testing.allocator.free(frame);
    const dec = try decodeFrame(frame);
    try testing.expectEqual(PacketType.traffic, dec.packet_type);
    try testing.expectEqualSlices(u8, payload, dec.payload);
    try testing.expectEqual(frame.len, dec.consumed);
}

test "packet type from byte" {
    try testing.expectEqual(PacketType.traffic, try PacketType.fromByte(9));
    try testing.expectError(Error.UnrecognizedMessage, PacketType.fromByte(10));
}

test "traffic roundtrip" {
    const gpa = testing.allocator;
    var tr = Traffic{
        .path = try gpa.dupe(PeerPort, &[_]PeerPort{ 1, 2, 3 }),
        .from = try gpa.dupe(PeerPort, &[_]PeerPort{ 4, 5 }),
        .source = [_]u8{0x11} ** 32,
        .dest = [_]u8{0x22} ** 32,
        .watermark = 99,
        .payload = try gpa.dupe(u8, "hello world"),
    };
    defer tr.deinit(gpa);

    var buf = ArrayList.empty;
    defer buf.deinit(gpa);
    try tr.encode(&buf, gpa);
    try testing.expectEqual(tr.size(), buf.items.len);

    var dec = try Traffic.decode(gpa, buf.items);
    defer dec.deinit(gpa);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 1, 2, 3 }, dec.path);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 4, 5 }, dec.from);
    try testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), &dec.source);
    try testing.expectEqualSlices(u8, &([_]u8{0x22} ** 32), &dec.dest);
    try testing.expectEqual(@as(u64, 99), dec.watermark);
    try testing.expectEqualSlices(u8, "hello world", dec.payload);
}

test "encodeTrafficFrame matches Traffic.encode wrapped in a frame" {
    const gpa = testing.allocator;
    const path = [_]PeerPort{ 1, 2, 3 };
    const from = [_]PeerPort{ 4, 5 };
    const source = [_]u8{0x11} ** 32;
    const dest = [_]u8{0x22} ** 32;
    const payload = "hello world";

    // Optimized one-shot frame.
    const frame_fast = try encodeTrafficFrame(gpa, &path, &from, &source, &dest, 99, payload);
    defer gpa.free(frame_fast);

    // Reference path: build Traffic, encode payload, wrap in frame.
    var inner = ArrayList.empty;
    defer inner.deinit(gpa);
    const tr = Traffic{
        .path = @constCast(&path),
        .from = @constCast(&from),
        .source = source,
        .dest = dest,
        .watermark = 99,
        .payload = @constCast(payload),
    };
    try tr.encode(&inner, gpa);
    const frame_ref = try encodeFrame(gpa, .traffic, inner.items);
    defer gpa.free(frame_ref);

    try testing.expectEqualSlices(u8, frame_ref, frame_fast);

    // And it must decode back to the same Traffic.
    const df = try decodeFrame(frame_fast);
    try testing.expectEqual(PacketType.traffic, df.packet_type);
    var dec = try Traffic.decode(gpa, df.payload);
    defer dec.deinit(gpa);
    try testing.expectEqualSlices(u8, payload, dec.payload);
}

test "path lookup roundtrip" {
    const gpa = testing.allocator;
    var lookup = PathLookup{
        .source = [_]u8{0xAA} ** 32,
        .dest = [_]u8{0xBB} ** 32,
        .from = try gpa.dupe(PeerPort, &[_]PeerPort{ 10, 20, 30 }),
    };
    defer lookup.deinit(gpa);

    var buf = ArrayList.empty;
    defer buf.deinit(gpa);
    try lookup.encode(&buf, gpa);
    var dec = try PathLookup.decode(gpa, buf.items);
    defer dec.deinit(gpa);
    try testing.expectEqualSlices(u8, &([_]u8{0xAA} ** 32), &dec.source);
    try testing.expectEqualSlices(u8, &([_]u8{0xBB} ** 32), &dec.dest);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 10, 20, 30 }, dec.from);
}

test "path notify roundtrip" {
    const gpa = testing.allocator;
    var notify = PathNotify{
        .path = try gpa.dupe(PeerPort, &[_]PeerPort{ 1, 2 }),
        .watermark = 7,
        .source = [_]u8{0x11} ** 32,
        .dest = [_]u8{0x22} ** 32,
        .info = .{
            .seq = 42,
            .path = try gpa.dupe(PeerPort, &[_]PeerPort{ 3, 4, 5 }),
            .sig = [_]u8{0xFF} ** 64,
        },
    };
    defer notify.deinit(gpa);

    var buf = ArrayList.empty;
    defer buf.deinit(gpa);
    try notify.encode(&buf, gpa);
    var dec = try PathNotify.decode(gpa, buf.items);
    defer dec.deinit(gpa);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 1, 2 }, dec.path);
    try testing.expectEqual(@as(u64, 7), dec.watermark);
    try testing.expectEqual(@as(u64, 42), dec.info.seq);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{ 3, 4, 5 }, dec.info.path);
}

test "path broken roundtrip" {
    const gpa = testing.allocator;
    var broken = PathBroken{
        .path = try gpa.dupe(PeerPort, &[_]PeerPort{1}),
        .watermark = 0,
        .source = [_]u8{0x33} ** 32,
        .dest = [_]u8{0x44} ** 32,
    };
    defer broken.deinit(gpa);

    var buf = ArrayList.empty;
    defer buf.deinit(gpa);
    try broken.encode(&buf, gpa);
    var dec = try PathBroken.decode(gpa, buf.items);
    defer dec.deinit(gpa);
    try testing.expectEqualSlices(PeerPort, &[_]PeerPort{1}, dec.path);
    try testing.expectEqualSlices(u8, &([_]u8{0x33} ** 32), &dec.source);
}

test "bloom wire roundtrip" {
    const gpa = testing.allocator;
    var data = [_]u64{0} ** BLOOM_FILTER_U64S;
    data[0] = 0;
    data[1] = std.math.maxInt(u64);
    data[2] = 0xDEADBEEFCAFEBABE;
    data[127] = 42;

    var buf = ArrayList.empty;
    defer buf.deinit(gpa);
    try encodeBloom(&buf, gpa, &data);
    try testing.expectEqual(bloomWireSize(&data), buf.items.len);
    const dec = try decodeBloom(buf.items);
    try testing.expectEqualSlices(u64, &data, &dec);
}

test "bloom wire all-zero and all-ones compress to flags only" {
    const gpa = testing.allocator;
    const zeros = [_]u64{0} ** BLOOM_FILTER_U64S;
    var buf = ArrayList.empty;
    defer buf.deinit(gpa);
    try encodeBloom(&buf, gpa, &zeros);
    try testing.expectEqual(@as(usize, BLOOM_FILTER_FLAGS * 2), buf.items.len);
    const dec = try decodeBloom(buf.items);
    try testing.expectEqualSlices(u64, &zeros, &dec);
}
