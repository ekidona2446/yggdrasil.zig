//! WolfSSL TLS bindings for Yggdrasil peer links.
//!
//! Links statically against wolfSSL (built with --enable-tls13 --enable-sni
//! --enable-quic --enable-opensslextra --enable-ed25519 --enable-curve25519
//! --enable-certgen --enable-keygen --enable-altcertchains) for TLS 1.3
//! transport between peers.
//!
//! Design: wolfSSL's synchronous `wolfSSL_read`/`wolfSSL_write` API is
//! bridged onto our libxev-driven async TCP sockets via custom "memory BIO"
//! I/O callbacks (`wolfSSL_CTX_SetIORecv` / `wolfSSL_CTX_SetIOSend`) that
//! read from / write to plain in-memory ring buffers instead of a socket
//! directly. The caller (network.zig) pumps bytes between those buffers and
//! the actual xev.TCP connection, and drives `wolfSSL_connect` /
//! `wolfSSL_accept` / `wolfSSL_read` / `wolfSSL_write` in a non-blocking
//! loop, treating `WANT_READ`/`WANT_WRITE` as "wait for more xev I/O".
//!
//! Authentication is *not* delegated to X.509 chain-of-trust: like the
//! reference implementation, every node presents a self-signed certificate
//! bound to its own Ed25519 identity key (never expires, similar to Go's
//! `crypto/tls` + `InsecureSkipVerify: true` + `VerifyConnection` hook).
//! Actual peer authentication happens one layer up, in the ironwood
//! handshake (`node/version.zig` `Metadata`), which is itself signed by the
//! same Ed25519 key -- so TLS here provides transport confidentiality /
//! integrity (and, notably, protocol-level indistinguishability + SNI for
//! traversing SNI-based proxies), while Yggdrasil's own crypto still does
//! the actual peer authentication end-to-end.

const std = @import("std");

// ---------------------------------------------------------------------------
// Opaque types
// ---------------------------------------------------------------------------

pub const WOLFSSL = opaque {};
pub const WOLFSSL_CTX = opaque {};
pub const WOLFSSL_METHOD = opaque {};

// ---------------------------------------------------------------------------
// Extern declarations: core lifecycle
// ---------------------------------------------------------------------------

pub extern "c" fn wolfSSL_Init() c_int;
pub extern "c" fn wolfSSL_Cleanup() c_int;
pub extern "c" fn wolfTLSv1_3_server_method() ?*WOLFSSL_METHOD;
pub extern "c" fn wolfTLSv1_3_client_method() ?*WOLFSSL_METHOD;
pub extern "c" fn wolfSSL_CTX_new(m: ?*WOLFSSL_METHOD) ?*WOLFSSL_CTX;
pub extern "c" fn wolfSSL_CTX_free(ctx: ?*WOLFSSL_CTX) void;
pub extern "c" fn wolfSSL_new(ctx: ?*WOLFSSL_CTX) ?*WOLFSSL;
pub extern "c" fn wolfSSL_free(ssl: ?*WOLFSSL) void;
pub extern "c" fn wolfSSL_connect(ssl: ?*WOLFSSL) c_int;
pub extern "c" fn wolfSSL_accept(ssl: ?*WOLFSSL) c_int;
pub extern "c" fn wolfSSL_read(ssl: ?*WOLFSSL, buf: [*]u8, sz: c_int) c_int;
pub extern "c" fn wolfSSL_write(ssl: ?*WOLFSSL, buf: [*]const u8, sz: c_int) c_int;
pub extern "c" fn wolfSSL_shutdown(ssl: ?*WOLFSSL) c_int;
pub extern "c" fn wolfSSL_get_error(ssl: ?*WOLFSSL, ret: c_int) c_int;
pub extern "c" fn wolfSSL_pending(ssl: ?*WOLFSSL) c_int;
pub extern "c" fn wolfSSL_is_init_finished(ssl: ?*const WOLFSSL) c_int;

pub const WOLFSSL_ERROR_WANT_READ: c_int = 2;
pub const WOLFSSL_ERROR_WANT_WRITE: c_int = 3;
pub const WOLFSSL_ERROR_ZERO_RETURN: c_int = 6;
pub const WOLFSSL_SUCCESS: c_int = 1;
pub const WOLFSSL_FATAL_ERROR: c_int = -1;

// ---------------------------------------------------------------------------
// Certificate / key loading (in-memory DER buffers, generated at startup)
// ---------------------------------------------------------------------------

pub const WOLFSSL_FILETYPE_ASN1: c_int = 2;
pub const WOLFSSL_FILETYPE_PEM: c_int = 1;

pub extern "c" fn wolfSSL_CTX_use_certificate_buffer(ctx: ?*WOLFSSL_CTX, in: [*]const u8, sz: c_long, format: c_int) c_int;
pub extern "c" fn wolfSSL_CTX_use_PrivateKey_buffer(ctx: ?*WOLFSSL_CTX, in: [*]const u8, sz: c_long, format: c_int) c_int;
pub extern "c" fn wolfSSL_CTX_set_verify(ctx: ?*WOLFSSL_CTX, mode: c_int, cb: ?*anyopaque) void;
pub extern "c" fn wolfSSL_CTX_set_min_proto_version(ctx: ?*WOLFSSL_CTX, version: c_int) c_int;

pub const WOLFSSL_VERIFY_NONE: c_int = 0;

// ---------------------------------------------------------------------------
// SNI (Server Name Indication)
// ---------------------------------------------------------------------------

pub const WOLFSSL_SNI_HOST_NAME: u8 = 0;

pub extern "c" fn wolfSSL_UseSNI(ssl: ?*WOLFSSL, sni_type: u8, data: ?*const anyopaque, size: u16) c_int;
pub extern "c" fn wolfSSL_CTX_UseSNI(ctx: ?*WOLFSSL_CTX, sni_type: u8, data: ?*const anyopaque, size: u16) c_int;

// ---------------------------------------------------------------------------
// Custom memory-backed I/O callbacks
// ---------------------------------------------------------------------------
//
// wolfSSL treats these exactly like a socket read()/write(): return the
// number of bytes moved, or a negative WOLFSSL_CBIO_ERR_* code. We use them
// to bridge into caller-managed ring buffers rather than a real fd, so the
// actual network I/O can stay on libxev's async TCP watcher.

pub const CallbackIORecv = *const fn (ssl: ?*WOLFSSL, buf: [*]u8, sz: c_int, ctx: ?*anyopaque) callconv(.c) c_int;
pub const CallbackIOSend = *const fn (ssl: ?*WOLFSSL, buf: [*]const u8, sz: c_int, ctx: ?*anyopaque) callconv(.c) c_int;

pub extern "c" fn wolfSSL_CTX_SetIORecv(ctx: ?*WOLFSSL_CTX, cb: CallbackIORecv) void;
pub extern "c" fn wolfSSL_CTX_SetIOSend(ctx: ?*WOLFSSL_CTX, cb: CallbackIOSend) void;
pub extern "c" fn wolfSSL_SetIOReadCtx(ssl: ?*WOLFSSL, ctx: ?*anyopaque) void;
pub extern "c" fn wolfSSL_SetIOWriteCtx(ssl: ?*WOLFSSL, ctx: ?*anyopaque) void;

pub const WOLFSSL_CBIO_ERR_WANT_READ: c_int = -2;
pub const WOLFSSL_CBIO_ERR_WANT_WRITE: c_int = -2;
pub const WOLFSSL_CBIO_ERR_CONN_CLOSE: c_int = -5;
pub const WOLFSSL_CBIO_ERR_GENERAL: c_int = -1;

// ---------------------------------------------------------------------------
// wolfCrypt: Ed25519 + certificate generation (WOLFSSL_CERT_GEN)
// ---------------------------------------------------------------------------

const CTC_NAME_SIZE: usize = 64;
const CTC_SERIAL_SIZE: usize = 20;
const CTC_DATE_SIZE: usize = 32;
const ED25519_KEY_SIZE: usize = 32;
const ED25519_PUB_KEY_SIZE: usize = 32;
const ED25519_SIG_SIZE: usize = 64;
const ED25519_TYPE: c_int = 19; // wolfssl/wolfcrypt/asn_public.h enum CertType
// wolfssl/wolfcrypt/oid_sum.h defines CTC_ED25519 twice under different
// build configs (256 vs. 0x7f8f65d4 / 2140104148); our build (with
// WOLFSSL_ASN_TEMPLATE, confirmed via a throwaway C offsetof/value probe
// against the actual installed headers) resolves to the latter.
const CTC_ED25519: c_int = @bitCast(@as(u32, 0x7f8f65d4));

/// Mirrors wolfssl/wolfcrypt/ed25519.h `ed25519_key`. We only need it to be
/// large enough / correctly aligned for wolfSSL's internal use; we never
/// touch its fields directly other than via the wc_ed25519_* API.
/// wolfSSL_lib_version-gated opaque blob sized generously (the real struct
/// is well under 512 bytes on all supported platforms as of the versions
/// tested here).
pub const ed25519_key = extern struct {
    _opaque: [512]u8 align(16) = undefined,
};

pub extern "c" fn wc_ed25519_init(key: *ed25519_key) c_int;
pub extern "c" fn wc_ed25519_free(key: *ed25519_key) void;
pub extern "c" fn wc_ed25519_make_key(rng: *WC_RNG, keysize: c_int, key: *ed25519_key) c_int;
pub extern "c" fn wc_ed25519_import_private_key(priv: [*]const u8, priv_sz: u32, pub_: [*]const u8, pub_sz: u32, key: *ed25519_key) c_int;

pub const WC_RNG = extern struct {
    _opaque: [256]u8 align(16) = undefined,
};

pub extern "c" fn wc_InitRng(rng: *WC_RNG) c_int;
pub extern "c" fn wc_FreeRng(rng: *WC_RNG) c_int;

/// Mirrors wolfssl/wolfcrypt/asn_public.h `CertName` (only used via
/// XMEMCPY-style whole-struct copy by our code, so exact per-field layout
/// doesn't matter as long as the size matches).
const CertName = extern struct {
    country: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    country_enc: u8 = 0,
    state: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    state_enc: u8 = 0,
    street: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    street_enc: u8 = 0,
    locality: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    locality_enc: u8 = 0,
    sur: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    sur_enc: u8 = 0,
    // NOTE: WOLFSSL_CERT_NAME_ALL (givenName/initials/dnQualifier/dnName)
    // is *not* enabled in our wolfSSL build, so `org` immediately follows
    // `sur`/`surEnc` here -- matches wolfssl/wolfcrypt/asn_public.h exactly
    // for the flags this build was configured with.
    org: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    org_enc: u8 = 0,
    unit: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    unit_enc: u8 = 0,
    common_name: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    common_name_enc: u8 = 0,
    serial_dev: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    serial_dev_enc: u8 = 0,
    user_id: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    user_id_enc: u8 = 0,
    postal_code: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    postal_code_enc: u8 = 0,
    // WOLFSSL_CERT_EXT (busCat/joiC/joiSt) is likewise not enabled.
    /// Must be last of the "simple" fields, per wolfSSL's own struct comment.
    email: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
    // WOLFSSL_MULTI_ATTRIB *is* enabled transitively via OPENSSL_EXTRA in
    // our build, so a trailing NameAttrib[CTC_MAX_ATTRIB] array follows
    // `email` -- confirmed against the real struct layout via a throwaway
    // C offsetof() probe against our built wolfssl/options.h.
    name: [4]NameAttrib = std.mem.zeroes([4]NameAttrib),
};

const NameAttrib = extern struct {
    sz: c_int = 0,
    id: c_int = 0,
    attr_type: c_int = 0,
    value: [CTC_NAME_SIZE]u8 = std.mem.zeroes([CTC_NAME_SIZE]u8),
};

/// Opaque `Cert` struct (wolfssl/wolfcrypt/asn_public.h). It's fairly large
/// (has CertName issuer/subject inline plus assorted fixed buffers); we
/// over-allocate generously and only touch the handful of leading fields we
/// need directly, matching the real struct's layout for those fields.
const Cert = extern struct {
    version: c_int = 0,
    serial: [CTC_SERIAL_SIZE]u8 = std.mem.zeroes([CTC_SERIAL_SIZE]u8),
    serial_sz: c_int = 0,
    sig_type: c_int = 0,
    issuer: CertName = .{},
    subject: CertName = .{},
    days_valid: c_int = 0,
    self_signed: c_int = 0,
    is_ca: c_int = 0,
    path_len: u8 = 0,
    /// Set by `wc_MakeCert_ex` to the pre-signature body size; must be
    /// passed back into `wc_SignCert_ex` as `request_sz`. C struct layout
    /// inserts padding before this `int` after the preceding `byte`.
    body_sz: c_int = 0,
    key_type: c_int = 0,
    _rest: [8192]u8 align(16) = undefined,
};

pub extern "c" fn wc_InitCert(cert: *Cert) c_int;
pub extern "c" fn wc_MakeCert_ex(cert: *Cert, der_buffer: [*]u8, der_sz: u32, key_type: c_int, key: *anyopaque, rng: *WC_RNG) c_int;
pub extern "c" fn wc_SignCert_ex(request_sz: c_int, s_type: c_int, buf: [*]u8, buf_sz: u32, key_type: c_int, key: *anyopaque, rng: *WC_RNG) c_int;
pub extern "c" fn wc_DerToPem(der: [*]const u8, der_sz: u32, output: [*]u8, output_sz: u32, cert_type: c_int) c_int;

const CERT_TYPE: c_int = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub const TlsError = error{
    InitFailed,
    CleanupFailed,
    CtxCreateFailed,
    SslCreateFailed,
    CertGenFailed,
    KeyGenFailed,
    RngFailed,
    LoadCertFailed,
    LoadKeyFailed,
    ConnectFailed,
    AcceptFailed,
    WantRead,
    WantWrite,
    Closed,
    Fatal,
};

pub fn globalInit() !void {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) return TlsError.InitFailed;
}

pub fn globalDeinit() void {
    _ = wolfSSL_Cleanup();
}

pub fn newServerCtx() !*WOLFSSL_CTX {
    const method = wolfTLSv1_3_server_method() orelse return TlsError.CtxCreateFailed;
    const ctx = wolfSSL_CTX_new(method) orelse return TlsError.CtxCreateFailed;
    return ctx;
}

pub fn newClientCtx() !*WOLFSSL_CTX {
    const method = wolfTLSv1_3_client_method() orelse return TlsError.CtxCreateFailed;
    const ctx = wolfSSL_CTX_new(method) orelse return TlsError.CtxCreateFailed;
    return ctx;
}

pub fn freeCtx(ctx: *WOLFSSL_CTX) void {
    wolfSSL_CTX_free(ctx);
}

/// Load the DER certificate + PKCS8 private key generated by
/// `generateIdentityCert` into a freshly created context, and configure it
/// to skip X.509 chain verification (authentication happens one layer up,
/// in the signed ironwood handshake -- exactly like the reference Go/Rust
/// implementations' `InsecureSkipVerify` + application-level verification).
pub fn configureIdentity(ctx: *WOLFSSL_CTX, cert_der: []const u8, key_der: []const u8) !void {
    if (wolfSSL_CTX_use_certificate_buffer(ctx, cert_der.ptr, @intCast(cert_der.len), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        return TlsError.LoadCertFailed;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_der.ptr, @intCast(key_der.len), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        return TlsError.LoadKeyFailed;
    }
    // We authenticate peers via the signed ironwood metadata handshake
    // layered on top of TLS, not via X.509 trust chains -- every node's
    // certificate is self-signed and bound only to its own identity key.
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, null);
}

pub fn newSsl(ctx: *WOLFSSL_CTX) !*WOLFSSL {
    return wolfSSL_new(ctx) orelse TlsError.SslCreateFailed;
}

pub fn freeSsl(ssl: *WOLFSSL) void {
    wolfSSL_free(ssl);
}

pub fn setSNI(ssl: *WOLFSSL, hostname: []const u8) void {
    _ = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, hostname.ptr, @intCast(hostname.len));
}

/// Wraps `wolfSSL_get_error` into a small enum the caller can switch on.
pub const IoResult = enum { ok, want_read, want_write, closed, fatal };

pub fn classifyResult(ssl: *WOLFSSL, ret: c_int) IoResult {
    if (ret > 0) return .ok;
    const err = wolfSSL_get_error(ssl, ret);
    return switch (err) {
        WOLFSSL_ERROR_WANT_READ => .want_read,
        WOLFSSL_ERROR_WANT_WRITE => .want_write,
        WOLFSSL_ERROR_ZERO_RETURN => .closed,
        else => .fatal,
    };
}

// ---------------------------------------------------------------------------
// Ed25519 self-signed certificate generation
// ---------------------------------------------------------------------------

pub const IdentityCert = struct {
    /// DER-encoded X.509 certificate.
    cert_der: []u8,
    /// DER-encoded PKCS8 private key (wraps the raw Ed25519 seed).
    key_der: []u8,

    pub fn deinit(self: *IdentityCert, gpa: std.mem.Allocator) void {
        gpa.free(self.cert_der);
        gpa.free(self.key_der);
    }
};

const PKCS8_HEADER_ED25519 = [_]u8{
    0x30, 0x2e, // SEQUENCE, len 46
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    0x30, 0x05, // SEQUENCE, len 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING, len 34
    0x04, 0x20, // inner OCTET STRING, len 32 (the raw seed follows)
};

/// Wraps a raw 32-byte Ed25519 seed in a minimal PKCS8 `PrivateKeyInfo` DER
/// envelope (RFC 8410 sec. 7), which is the format wolfSSL's
/// `wolfSSL_CTX_use_PrivateKey_buffer(..., WOLFSSL_FILETYPE_ASN1)` expects
/// for Ed25519 keys.
fn wrapEd25519Pkcs8(gpa: std.mem.Allocator, seed: [32]u8) ![]u8 {
    var out = try gpa.alloc(u8, PKCS8_HEADER_ED25519.len + seed.len);
    @memcpy(out[0..PKCS8_HEADER_ED25519.len], &PKCS8_HEADER_ED25519);
    @memcpy(out[PKCS8_HEADER_ED25519.len..], &seed);
    return out;
}

/// Generate a self-signed, never-expiring X.509 certificate bound to
/// `ed25519_seed` (the node's Ed25519 identity secret key seed) using
/// wolfCrypt's certificate generation API directly (WOLFSSL_CERT_GEN +
/// HAVE_ED25519 + WOLFSSL_KEY_GEN, all enabled in our wolfSSL build).
///
/// The certificate's CommonName is the hex-encoded public key, mirroring
/// the reference Go implementation so that the identity is recoverable
/// from the certificate alone if ever needed for debugging.
pub fn generateIdentityCert(gpa: std.mem.Allocator, ed25519_seed: [32]u8, public_key_hex: []const u8) !IdentityCert {
    var rng: WC_RNG = .{};
    if (wc_InitRng(&rng) != 0) return TlsError.RngFailed;
    defer _ = wc_FreeRng(&rng);

    var key: ed25519_key = .{};
    if (wc_ed25519_init(&key) != 0) return TlsError.KeyGenFailed;
    defer wc_ed25519_free(&key);

    // Re-derive the wolfCrypt key object from our existing Ed25519 seed +
    // public key, rather than generating a fresh one, so the TLS identity
    // matches the ironwood identity exactly.
    var pub_buf: [ED25519_PUB_KEY_SIZE]u8 = undefined;
    {
        // Recompute the public key from the seed via std.crypto (matches
        // Zig's own Ed25519 keypair derivation) since we don't have direct
        // access to the already-derived ironwood public key bytes here.
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(ed25519_seed) catch return TlsError.KeyGenFailed;
        pub_buf = kp.public_key.toBytes();
    }
    if (wc_ed25519_import_private_key(&ed25519_seed, ED25519_KEY_SIZE, &pub_buf, ED25519_PUB_KEY_SIZE, &key) != 0) {
        return TlsError.KeyGenFailed;
    }

    var cert: Cert = .{};
    if (wc_InitCert(&cert) != 0) return TlsError.CertGenFailed;

    // RFC5280 4.1.2.5: "99991231235959Z" represents "no well-defined
    // expiration date" -- but wolfSSL's Cert.daysValid is simpler to use
    // and we don't have direct access to set notAfter arbitrarily here, so
    // use a very long validity window (100 years) instead, which is
    // effectively the same in practice for a mesh identity certificate.
    cert.days_valid = 365 * 100;
    cert.self_signed = 1;
    cert.is_ca = 0;
    cert.sig_type = CTC_ED25519;

    setCommonName(&cert.subject, public_key_hex);
    cert.issuer = cert.subject;

    const der_buf = try gpa.alloc(u8, 4096);
    defer gpa.free(der_buf);

    const make_ret = wc_MakeCert_ex(&cert, der_buf.ptr, @intCast(der_buf.len), ED25519_TYPE, @ptrCast(&key), &rng);
    if (make_ret < 0) return TlsError.CertGenFailed;

    const sign_ret = wc_SignCert_ex(cert.body_sz, cert.sig_type, der_buf.ptr, @intCast(der_buf.len), ED25519_TYPE, @ptrCast(&key), &rng);
    if (sign_ret < 0) return TlsError.CertGenFailed;

    const cert_der = try gpa.dupe(u8, der_buf[0..@intCast(sign_ret)]);
    errdefer gpa.free(cert_der);

    const key_der = try wrapEd25519Pkcs8(gpa, ed25519_seed);
    errdefer gpa.free(key_der);

    return .{ .cert_der = cert_der, .key_der = key_der };
}

fn setCommonName(name: *CertName, hex: []const u8) void {
    const n = @min(hex.len, CTC_NAME_SIZE - 1);
    @memcpy(name.common_name[0..n], hex[0..n]);
    name.common_name[n] = 0;
    name.common_name_enc = 0x0c; // CTC_UTF8
}

// ---------------------------------------------------------------------------
// TlsConn: bridges wolfSSL's synchronous read()/write()-style API onto
// caller-managed byte buffers, so the real network I/O can stay on
// libxev's async TCP watcher (see network.zig).
// ---------------------------------------------------------------------------
//
// Usage pattern from the caller (network.zig):
//   1. Create with `TlsConn.init(ctx, is_server, sni_hostname)`.
//   2. Call `pumpHandshake()`. If it returns `.want_read`, wait for more
//      bytes from the raw socket and call `feedCiphertext()` then retry;
//      if `.want_write`, call `drainCiphertext()` and write those bytes to
//      the raw socket, then retry. Repeat until `.ok` (handshake done) or
//      `.fatal`/`.closed`.
//   3. To send application data: `writePlaintext(data)`, then
//      `drainCiphertext()` + write to the socket (same want_write dance).
//   4. On raw socket readability: `feedCiphertext(bytes)`, then
///     `readPlaintext(buf)` in a loop until it reports `.want_read` (no
//      more decrypted data available right now).

pub const TlsConn = struct {
    ssl: *WOLFSSL,
    /// Ciphertext bytes received from the raw socket, not yet consumed by
    /// wolfSSL's recv callback.
    incoming: std.ArrayListUnmanaged(u8) = .empty,
    incoming_pos: usize = 0,
    /// Ciphertext bytes wolfSSL wants sent out; caller drains and writes
    /// these to the raw socket.
    outgoing: std.ArrayListUnmanaged(u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, ctx: *WOLFSSL_CTX, sni_hostname: ?[]const u8) !*TlsConn {
        const self = try gpa.create(TlsConn);
        errdefer gpa.destroy(self);
        const ssl = try newSsl(ctx);
        errdefer freeSsl(ssl);

        self.* = .{ .ssl = ssl, .gpa = gpa };

        wolfSSL_SetIOReadCtx(ssl, self);
        wolfSSL_SetIOWriteCtx(ssl, self);
        if (sni_hostname) |h| setSNI(ssl, h);

        return self;
    }

    pub fn deinit(self: *TlsConn) void {
        freeSsl(self.ssl);
        self.incoming.deinit(self.gpa);
        self.outgoing.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    /// Append raw bytes just read from the socket, to be consumed by
    /// wolfSSL on the next pump/read call.
    pub fn feedCiphertext(self: *TlsConn, data: []const u8) !void {
        // Compact already-consumed bytes before growing, so a long-lived
        // connection doesn't accumulate an ever-growing dead prefix.
        if (self.incoming_pos > 0) {
            const remaining = self.incoming.items[self.incoming_pos..];
            std.mem.copyForwards(u8, self.incoming.items[0..remaining.len], remaining);
            self.incoming.shrinkRetainingCapacity(remaining.len);
            self.incoming_pos = 0;
        }
        try self.incoming.appendSlice(self.gpa, data);
    }

    /// Take ownership of any pending outgoing ciphertext (caller must write
    /// it to the raw socket, then free it once the write completes).
    pub fn drainCiphertext(self: *TlsConn) ![]u8 {
        const out = try self.outgoing.toOwnedSlice(self.gpa);
        return out;
    }

    pub fn hasPendingCiphertext(self: *const TlsConn) bool {
        return self.outgoing.items.len > 0;
    }

    /// Drive the TLS handshake. Call repeatedly per the state machine
    /// described above until it returns something other than
    /// `.want_read`/`.want_write`.
    pub fn pumpHandshake(self: *TlsConn, is_server: bool) IoResult {
        const ret = if (is_server) wolfSSL_accept(self.ssl) else wolfSSL_connect(self.ssl);
        return classifyResult(self.ssl, ret);
    }

    pub fn isHandshakeDone(self: *const TlsConn) bool {
        return wolfSSL_is_init_finished(self.ssl) == 1;
    }

    /// Encrypt `data` as application traffic; resulting ciphertext is
    /// appended to `outgoing` (drain + send it). Returns `.ok` once all of
    /// `data` has been consumed by wolfSSL (may require multiple calls if
    /// wolfSSL reports `.want_write` mid-way -- caller should drain+flush
    /// then retry with the *same* `data` per wolfSSL's own re-entry rules).
    pub fn writePlaintext(self: *TlsConn, data: []const u8) IoResult {
        const ret = wolfSSL_write(self.ssl, data.ptr, @intCast(data.len));
        return classifyResult(self.ssl, ret);
    }

    /// Decrypt as much application traffic as is available into `buf`,
    /// returning the number of bytes written, or an IoResult indicating
    /// why nothing more is available right now.
    pub const ReadOutcome = union(enum) { data: usize, result: IoResult };

    pub fn readPlaintext(self: *TlsConn, buf: []u8) ReadOutcome {
        const ret = wolfSSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (ret > 0) return .{ .data = @intCast(ret) };
        return .{ .result = classifyResult(self.ssl, ret) };
    }
};

/// wolfSSL recv callback: pull ciphertext out of `TlsConn.incoming`.
fn ioRecvCallback(ssl: ?*WOLFSSL, buf: [*]u8, sz: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    _ = ssl;
    const self: *TlsConn = @ptrCast(@alignCast(ctx orelse return WOLFSSL_CBIO_ERR_GENERAL));
    const available = self.incoming.items.len - self.incoming_pos;
    if (available == 0) return WOLFSSL_CBIO_ERR_WANT_READ;
    const n = @min(available, @as(usize, @intCast(sz)));
    @memcpy(buf[0..n], self.incoming.items[self.incoming_pos .. self.incoming_pos + n]);
    self.incoming_pos += n;
    return @intCast(n);
}

/// wolfSSL send callback: append ciphertext to `TlsConn.outgoing` (always
/// "succeeds" from wolfSSL's point of view -- we buffer unboundedly rather
/// than applying backpressure here, which is acceptable for the modest
/// per-peer traffic volumes ironwood mesh links see in practice).
fn ioSendCallback(ssl: ?*WOLFSSL, buf: [*]const u8, sz: c_int, ctx: ?*anyopaque) callconv(.c) c_int {
    _ = ssl;
    const self: *TlsConn = @ptrCast(@alignCast(ctx orelse return WOLFSSL_CBIO_ERR_GENERAL));
    if (sz <= 0) return 0;
    self.outgoing.appendSlice(self.gpa, buf[0..@intCast(sz)]) catch return WOLFSSL_CBIO_ERR_GENERAL;
    return sz;
}

/// Install the custom memory-backed I/O callbacks on a context. Must be
/// called once per CTX before creating any `TlsConn`s from it.
pub fn installMemoryIO(ctx: *WOLFSSL_CTX) void {
    wolfSSL_CTX_SetIORecv(ctx, ioRecvCallback);
    wolfSSL_CTX_SetIOSend(ctx, ioSendCallback);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "wrapEd25519Pkcs8 produces expected DER length" {
    const seed = [_]u8{0x42} ** 32;
    const wrapped = try wrapEd25519Pkcs8(testing.allocator, seed);
    defer testing.allocator.free(wrapped);
    try testing.expectEqual(@as(usize, PKCS8_HEADER_ED25519.len + 32), wrapped.len);
    // OID 1.3.101.112 bytes should be present.
    try testing.expect(std.mem.indexOf(u8, wrapped, &[_]u8{ 0x06, 0x03, 0x2b, 0x65, 0x70 }) != null);
}

test "global init/deinit roundtrip" {
    try globalInit();
    globalDeinit();
}

test "generate identity cert from seed" {
    try globalInit();
    defer globalDeinit();

    const seed = [_]u8{0x11} ** 32;
    var ident = try generateIdentityCert(testing.allocator, seed, "deadbeef");
    defer ident.deinit(testing.allocator);

    try testing.expect(ident.cert_der.len > 0);
    try testing.expectEqual(@as(usize, PKCS8_HEADER_ED25519.len + 32), ident.key_der.len);

    // Round-trip through a real CTX to make sure wolfSSL itself accepts the
    // generated cert + key (this is the strongest correctness check we can
    // do without a full handshake).
    const ctx = try newServerCtx();
    defer freeCtx(ctx);
    try configureIdentity(ctx, ident.cert_der, ident.key_der);
}

/// Pumps ciphertext between two in-memory `TlsConn`s until both sides
/// report the handshake is finished (or a bounded number of rounds elapses,
/// to fail loudly instead of hanging if something regresses).
fn pumpHandshakeToCompletion(client: *TlsConn, server: *TlsConn) !void {
    var rounds: usize = 0;
    while (!(client.isHandshakeDone() and server.isHandshakeDone())) {
        rounds += 1;
        if (rounds > 50) return error.HandshakeDidNotConverge;

        const c_result = client.pumpHandshake(false);
        if (client.hasPendingCiphertext()) {
            const bytes = try client.drainCiphertext();
            defer testing.allocator.free(bytes);
            try server.feedCiphertext(bytes);
        }
        if (c_result == .fatal) return error.ClientHandshakeFatal;

        const s_result = server.pumpHandshake(true);
        if (server.hasPendingCiphertext()) {
            const bytes = try server.drainCiphertext();
            defer testing.allocator.free(bytes);
            try client.feedCiphertext(bytes);
        }
        if (s_result == .fatal) return error.ServerHandshakeFatal;
    }
}

test "full TLS 1.3 handshake + app data roundtrip over in-memory buffers" {
    try globalInit();
    defer globalDeinit();

    const client_seed = [_]u8{0xAA} ** 32;
    const server_seed = [_]u8{0xBB} ** 32;

    var client_ident = try generateIdentityCert(testing.allocator, client_seed, "client-key");
    defer client_ident.deinit(testing.allocator);
    var server_ident = try generateIdentityCert(testing.allocator, server_seed, "server-key");
    defer server_ident.deinit(testing.allocator);

    const client_ctx = try newClientCtx();
    defer freeCtx(client_ctx);
    try configureIdentity(client_ctx, client_ident.cert_der, client_ident.key_der);
    installMemoryIO(client_ctx);

    const server_ctx = try newServerCtx();
    defer freeCtx(server_ctx);
    try configureIdentity(server_ctx, server_ident.cert_der, server_ident.key_der);
    installMemoryIO(server_ctx);

    const client = try TlsConn.init(testing.allocator, client_ctx, "peer.example");
    defer client.deinit();
    const server = try TlsConn.init(testing.allocator, server_ctx, null);
    defer server.deinit();

    try pumpHandshakeToCompletion(client, server);
    try testing.expect(client.isHandshakeDone());
    try testing.expect(server.isHandshakeDone());

    // Application data: client -> server.
    const msg = "hello over wolfssl tls1.3";
    const w_result = client.writePlaintext(msg);
    try testing.expectEqual(IoResult.ok, w_result);
    {
        const bytes = try client.drainCiphertext();
        defer testing.allocator.free(bytes);
        try testing.expect(bytes.len > 0);
        try server.feedCiphertext(bytes);
    }

    var read_buf: [256]u8 = undefined;
    const outcome = server.readPlaintext(&read_buf);
    switch (outcome) {
        .data => |n| try testing.expectEqualStrings(msg, read_buf[0..n]),
        .result => return error.UnexpectedNoData,
    }

    // And the reverse direction: server -> client.
    const reply = "reply from server";
    const w2 = server.writePlaintext(reply);
    try testing.expectEqual(IoResult.ok, w2);
    {
        const bytes = try server.drainCiphertext();
        defer testing.allocator.free(bytes);
        try client.feedCiphertext(bytes);
    }
    const outcome2 = client.readPlaintext(&read_buf);
    switch (outcome2) {
        .data => |n| try testing.expectEqualStrings(reply, read_buf[0..n]),
        .result => return error.UnexpectedNoData,
    }
}
