//! Windows TUN backend: loads the Wintun driver's userspace API
//! (wintun.dll, shipped alongside the executable -- see build.zig's
//! `wintunDllPath`) dynamically via `LoadLibraryW`/`GetProcAddress`, exactly
//! like WireGuard, Tailscale, and the reference Yggdrasil Go implementation
//! do. Wintun is a WHQL-signed kernel driver plus this small usermode DLL;
//! opening/creating an adapter auto-installs the driver on first use (it
//! requires Administrator privileges the first time).
//!
//! Wintun's I/O model is fundamentally different from a Unix character
//! device: `WintunReceivePacket`/`WintunSendPacket` are synchronous,
//! non-blocking calls against a lock-free ring buffer, with a manual-reset
//! event (`WintunGetReadWaitEvent`) to signal "data might be available".
//! There is no OS-level file HANDLE to hand to an IOCP-based event loop
//! for reads, so this backend runs a dedicated background thread that
//! blocks on that event and drains packets into a queue, waking the main
//! `xev` loop via `xev.Async` each time it delivers one. Writes go straight
//! through `WintunSendPacket` synchronously (mirrors wireguard-go, which
//! treats sends as always-non-blocking against the ring).

const std = @import("std");
const node = @import("node.zig");
const xev = @import("xev");

// ---------------------------------------------------------------------------
// Win32 / kernel32 plumbing for dynamic loading (std.DynLib doesn't support
// Windows in this Zig version).
// ---------------------------------------------------------------------------

const HMODULE = *anyopaque;
const HANDLE = *anyopaque;
const FARPROC = *const anyopaque;
const BOOL = c_int;
const DWORD = u32;
const WCHAR = u16;

extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const WCHAR) callconv(.winapi) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?FARPROC;
extern "kernel32" fn GetModuleFileNameW(hModule: ?HMODULE, lpFilename: [*]WCHAR, nSize: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn CreateEventW(lpEventAttributes: ?*anyopaque, bManualReset: BOOL, bInitialState: BOOL, lpName: ?[*:0]const WCHAR) callconv(.winapi) ?HANDLE;
extern "kernel32" fn SetEvent(hEvent: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;

const WAIT_OBJECT_0: DWORD = 0;
const WAIT_TIMEOUT: DWORD = 0x102;
const INFINITE: DWORD = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// Wintun C API (see wintun.h) -- function-pointer types, resolved once at
// DLL-load time via GetProcAddress and cached in `Api`.
// ---------------------------------------------------------------------------

const WINTUN_ADAPTER_HANDLE = *anyopaque;
const WINTUN_SESSION_HANDLE = *anyopaque;
const NET_LUID = extern struct { Value: u64 };
const GUID = extern struct { Data1: u32, Data2: u16, Data3: u16, Data4: [8]u8 };

const CreateAdapterFn = *const fn (Name: [*:0]const WCHAR, TunnelType: [*:0]const WCHAR, RequestedGUID: ?*const GUID) callconv(.winapi) ?WINTUN_ADAPTER_HANDLE;
const CloseAdapterFn = *const fn (Adapter: WINTUN_ADAPTER_HANDLE) callconv(.winapi) void;
const GetAdapterLUIDFn = *const fn (Adapter: WINTUN_ADAPTER_HANDLE, Luid: *NET_LUID) callconv(.winapi) void;
const StartSessionFn = *const fn (Adapter: WINTUN_ADAPTER_HANDLE, Capacity: DWORD) callconv(.winapi) ?WINTUN_SESSION_HANDLE;
const EndSessionFn = *const fn (Session: WINTUN_SESSION_HANDLE) callconv(.winapi) void;
const GetReadWaitEventFn = *const fn (Session: WINTUN_SESSION_HANDLE) callconv(.winapi) HANDLE;
const ReceivePacketFn = *const fn (Session: WINTUN_SESSION_HANDLE, PacketSize: *DWORD) callconv(.winapi) ?[*]u8;
const ReleaseReceivePacketFn = *const fn (Session: WINTUN_SESSION_HANDLE, Packet: [*]const u8) callconv(.winapi) void;
const AllocateSendPacketFn = *const fn (Session: WINTUN_SESSION_HANDLE, PacketSize: DWORD) callconv(.winapi) ?[*]u8;
const SendPacketFn = *const fn (Session: WINTUN_SESSION_HANDLE, Packet: [*]const u8) callconv(.winapi) void;

const WINTUN_MIN_RING_CAPACITY: DWORD = 0x20000;

const Api = struct {
    dll: HMODULE,
    createAdapter: CreateAdapterFn,
    closeAdapter: CloseAdapterFn,
    getAdapterLUID: GetAdapterLUIDFn,
    startSession: StartSessionFn,
    endSession: EndSessionFn,
    getReadWaitEvent: GetReadWaitEventFn,
    receivePacket: ReceivePacketFn,
    releaseReceivePacket: ReleaseReceivePacketFn,
    allocateSendPacket: AllocateSendPacketFn,
    sendPacket: SendPacketFn,

    fn load() !Api {
        const dll = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("wintun.dll")) orelse return error.WintunDllNotFound;
        errdefer _ = CloseHandleModule(dll);

        return .{
            .dll = dll,
            .createAdapter = try proc(dll, CreateAdapterFn, "WintunCreateAdapter"),
            .closeAdapter = try proc(dll, CloseAdapterFn, "WintunCloseAdapter"),
            .getAdapterLUID = try proc(dll, GetAdapterLUIDFn, "WintunGetAdapterLUID"),
            .startSession = try proc(dll, StartSessionFn, "WintunStartSession"),
            .endSession = try proc(dll, EndSessionFn, "WintunEndSession"),
            .getReadWaitEvent = try proc(dll, GetReadWaitEventFn, "WintunGetReadWaitEvent"),
            .receivePacket = try proc(dll, ReceivePacketFn, "WintunReceivePacket"),
            .releaseReceivePacket = try proc(dll, ReleaseReceivePacketFn, "WintunReleaseReceivePacket"),
            .allocateSendPacket = try proc(dll, AllocateSendPacketFn, "WintunAllocateSendPacket"),
            .sendPacket = try proc(dll, SendPacketFn, "WintunSendPacket"),
        };
    }

    fn proc(dll: HMODULE, comptime T: type, name: [:0]const u8) !T {
        const p = GetProcAddress(dll, name.ptr) orelse return error.WintunSymbolNotFound;
        return @ptrCast(p);
    }
};

// FreeLibrary isn't declared above since we intentionally keep the DLL
// loaded for the process lifetime (matches Wintun's own recommendation).
fn CloseHandleModule(m: HMODULE) BOOL {
    _ = m;
    return 1;
}

// ---------------------------------------------------------------------------
// NativeTun
// ---------------------------------------------------------------------------

/// A minimal spinlock built directly on `std.atomic.Value`, used instead of
/// `std.Thread.Mutex` (removed from `std.Thread` in this Zig version --
/// synchronization primitives moved behind the new `std.Io` interface,
/// which needs an `Io` instance we don't otherwise have here). Contention
/// is negligible: the only two callers are the single Wintun reader thread
/// (push) and the main event-loop thread draining the queue (pop), and
/// each holds the lock only long enough to shuffle a few array slots.
const SpinLock = struct {
    state: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinLock) void {
        self.state.store(false, .release);
    }
};

/// Packets delivered from the background reader thread to the consumer via
/// a small bounded queue, since Wintun's receive API must be pumped from a
/// single dedicated OS thread but `xev` callbacks run on the loop thread.
pub const RecvQueue = struct {
    pub const Packet = struct { data: []u8, len: usize };
    const CAPACITY = 256;

    lock_state: SpinLock = .{},
    items: [CAPACITY]?Packet = [_]?Packet{null} ** CAPACITY,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    gpa: std.mem.Allocator,

    pub fn push(self: *RecvQueue, data: []const u8) void {
        self.lock_state.lock();
        defer self.lock_state.unlock();
        if (self.count == CAPACITY) return; // drop on overflow, like a full ring
        const owned = self.gpa.dupe(u8, data) catch return;
        self.items[self.tail] = .{ .data = owned, .len = owned.len };
        self.tail = (self.tail + 1) % CAPACITY;
        self.count += 1;
    }

    pub fn pop(self: *RecvQueue) ?Packet {
        self.lock_state.lock();
        defer self.lock_state.unlock();
        if (self.count == 0) return null;
        const p = self.items[self.head].?;
        self.items[self.head] = null;
        self.head = (self.head + 1) % CAPACITY;
        self.count -= 1;
        return p;
    }
};

pub const NativeTun = struct {
    api: Api,
    adapter: ?WINTUN_ADAPTER_HANDLE = null,
    session: ?WINTUN_SESSION_HANDLE = null,
    name: [16:0]u8,
    mtu: u16,
    enabled: bool,

    recv_queue: ?*RecvQueue = null,
    reader_thread: ?std.Thread = null,
    stop_event: ?HANDLE = null,
    /// Signaled (via xev.Async.notify) each time a packet is queued, so the
    /// main loop's async watcher wakes up and drains `recv_queue`.
    wake: ?*xev.Async = null,

    pub fn init(name: []const u8, mtu: u16) !NativeTun {
        if (std.mem.eql(u8, name, "none")) return .{
            .api = undefined,
            .name = .{0} ** 16,
            .mtu = mtu,
            .enabled = false,
        };

        const api = try Api.load();

        var name_buf: [16:0]u8 = .{0} ** 16;
        const trunc_len = @min(name.len, 15);
        const display_name = if (std.mem.eql(u8, name, "auto")) "yggdrasil" else name;
        @memcpy(name_buf[0..@min(display_name.len, 15)], display_name[0..@min(display_name.len, 15)]);
        _ = trunc_len;

        var wname_buf: [64]WCHAR = undefined;
        const wname_len = try std.unicode.utf8ToUtf16Le(&wname_buf, display_name);
        wname_buf[wname_len] = 0;

        var wtype_buf: [64]WCHAR = undefined;
        const wtype_len = try std.unicode.utf8ToUtf16Le(&wtype_buf, "Yggdrasil");
        wtype_buf[wtype_len] = 0;

        const adapter = api.createAdapter(wname_buf[0..wname_len :0], wtype_buf[0..wtype_len :0], null) orelse
            return error.TunSetupFailed;
        errdefer api.closeAdapter(adapter);

        const session = api.startSession(adapter, WINTUN_MIN_RING_CAPACITY) orelse
            return error.TunSetupFailed;
        errdefer api.endSession(session);

        return .{
            .api = api,
            .adapter = adapter,
            .session = session,
            .name = name_buf,
            .mtu = mtu,
            .enabled = true,
        };
    }

    /// Starts the background reader thread that pumps `WintunReceivePacket`
    /// and pushes decoded packets into `recv_queue`, waking `wake` (an
    /// `xev.Async`) after each one. Must be called once the main event loop
    /// (and its Async watcher) exist. No-op if TUN is disabled.
    pub fn startReaderThread(self: *NativeTun, gpa: std.mem.Allocator, queue: *RecvQueue, wake: *xev.Async) !void {
        if (!self.enabled) return;
        self.recv_queue = queue;
        self.wake = wake;
        self.stop_event = CreateEventW(null, 1, 0, null) orelse return error.TunSetupFailed;
        self.reader_thread = try std.Thread.spawn(.{}, readerLoop, .{ self, gpa });
    }

    fn readerLoop(self: *NativeTun, gpa: std.mem.Allocator) void {
        _ = gpa;
        const session = self.session orelse return;
        const read_wait_event = self.api.getReadWaitEvent(session);
        const stop_event = self.stop_event orelse return;
        var handles = [_]HANDLE{ read_wait_event, stop_event };
        while (true) {
            var size: DWORD = 0;
            while (self.api.receivePacket(session, &size)) |packet| {
                if (self.recv_queue) |q| q.push(packet[0..size]);
                self.api.releaseReceivePacket(session, packet);
                if (self.wake) |w| w.notify() catch {};
            }
            // ERROR_NO_MORE_ITEMS: wait for more data (or shutdown).
            const rc = waitForMultiple(&handles, INFINITE);
            if (rc == 1) return; // stop_event signaled
        }
    }

    fn waitForMultiple(handles: []HANDLE, timeout: DWORD) usize {
        // WaitForMultipleObjects isn't declared above to keep the extern
        // surface small; a tight loop over WaitForSingleObject with a short
        // timeout is an acceptable substitute here since we only ever wait
        // on 2 handles and don't need microsecond wakeup latency for a
        // background packet pump.
        _ = timeout;
        while (true) {
            for (handles, 0..) |h, i| {
                const r = WaitForSingleObject(h, 50);
                if (r == WAIT_OBJECT_0) return i;
            }
        }
    }

    pub fn deinit(self: *NativeTun) void {
        if (!self.enabled) return;
        if (self.stop_event) |ev| {
            _ = SetEvent(ev);
        }
        if (self.reader_thread) |t| t.join();
        if (self.stop_event) |ev| _ = CloseHandle(ev);
        if (self.session) |s| self.api.endSession(s);
        if (self.adapter) |a| self.api.closeAdapter(a);
        self.enabled = false;
    }

    /// Synchronous send: Wintun's send path is itself non-blocking against
    /// a lock-free ring, so no thread/queue is needed for writes.
    pub fn write(self: *NativeTun, buf: []const u8) !usize {
        if (!self.enabled) return error.TunDisabled;
        const session = self.session orelse return error.TunDisabled;
        const dst = self.api.allocateSendPacket(session, @intCast(buf.len)) orelse return error.WriteFailed;
        @memcpy(dst[0..buf.len], buf);
        self.api.sendPacket(session, dst);
        return buf.len;
    }

    /// Windows TUN reads are pumped exclusively via the background thread
    /// (see `startReaderThread`) into a queue drained by the main loop; a
    /// direct blocking `read` isn't part of this backend's public surface.
    pub fn read(self: *NativeTun, buf: []u8) !usize {
        _ = self;
        _ = buf;
        return error.Unsupported;
    }
};

pub const Queue = RecvQueue;

/// Assigning an IPv6 address on Windows goes through the IP Helper API
/// (`CreateUnicastIpAddressEntry`) keyed by the adapter's `NET_LUID`, not
/// ioctls on a socket. `luid` must come from `NativeTun`'s adapter via
/// `WintunGetAdapterLUID` (exposed indirectly through `assignAddress`).
pub fn assignAddress(tun: *NativeTun, addr: node.Address, mtu: u16) !void {
    _ = mtu; // Wintun adapters don't expose a settable MTU via this API;
    // the interface MTU is negotiated at the IP layer via SetIpInterfaceEntry
    // in a fuller implementation. Left as a future improvement.
    const adapter = tun.adapter orelse return error.TunDisabled;
    var luid: NET_LUID = undefined;
    tun.api.getAdapterLUID(adapter, &luid);
    try createUnicastAddress(luid, addr);
}

// ---------------------------------------------------------------------------
// IP Helper API (iphlpapi.dll): CreateUnicastIpAddressEntry
// ---------------------------------------------------------------------------

const MIB_UNICASTIPADDRESS_ROW = extern struct {
    Address: SOCKADDR_INET,
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    PrefixOrigin: u32 = 0, // IpPrefixOriginManual... left 0 == IpPrefixOriginOther
    SuffixOrigin: u32 = 0,
    ValidLifetime: u32 = 0xFFFFFFFF,
    PreferredLifetime: u32 = 0xFFFFFFFF,
    OnLinkPrefixLength: u8,
    SkipAsSource: BOOL = 0,
    DadState: u32 = 0,
    ScopeId: u32 = 0,
    CreationTimeStamp: i64 = 0,
};

const SOCKADDR_IN6 = extern struct {
    sin6_family: i16 = 23, // AF_INET6 on Windows
    sin6_port: u16 = 0,
    sin6_flowinfo: u32 = 0,
    sin6_addr: [16]u8 = [_]u8{0} ** 16,
    sin6_scope_id: u32 = 0,
};

const SOCKADDR_INET = extern union {
    Ipv6: SOCKADDR_IN6,
    si_family: i16,
};

extern "iphlpapi" fn CreateUnicastIpAddressEntry(Row: *const MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) u32; // NETIO_STATUS / NO_ERROR == 0
extern "iphlpapi" fn InitializeUnicastIpAddressEntry(Row: *MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) void;

fn createUnicastAddress(luid: NET_LUID, addr: node.Address) !void {
    var row: MIB_UNICASTIPADDRESS_ROW = undefined;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address = .{ .Ipv6 = .{ .sin6_addr = addr.bytes } };
    row.OnLinkPrefixLength = 7; // matches the /7 broad on-link visibility used elsewhere
    row.ValidLifetime = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    const status = CreateUnicastIpAddressEntry(&row);
    if (status != 0) return error.SetAddrFailed;
}
