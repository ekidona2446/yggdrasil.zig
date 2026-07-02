//! WolfSSL TLS bindings for Yggdrasil.
//!
//! Links statically against wolfSSL for TLS 1.3 transport.
//! Ed25519 signing/verification is handled via Yggdrasil's own
//! crypto (ironwood.crypto), wired into wolfSSL callbacks.

const std = @import("std");

// ---------------------------------------------------------------------------
// Opaque types
// ---------------------------------------------------------------------------

pub const WOLFSSL = opaque {};
pub const WOLFSSL_CTX = opaque {};
pub const WOLFSSL_METHOD = opaque {};

// ---------------------------------------------------------------------------
// Extern declarations
// ---------------------------------------------------------------------------

pub extern "c" fn wolfSSL_Init() c_int;
pub extern "c" fn wolfSSL_Cleanup() c_int;
pub extern "c" fn wolfTLSv1_3_server_method() *WOLFSSL_METHOD;
pub extern "c" fn wolfTLSv1_3_client_method() *WOLFSSL_METHOD;
pub extern "c" fn wolfSSL_CTX_new(m: *WOLFSSL_METHOD) ?*WOLFSSL_CTX;
pub extern "c" fn wolfSSL_CTX_free(ctx: ?*WOLFSSL_CTX) void;
pub extern "c" fn wolfSSL_new(ctx: *WOLFSSL_CTX) ?*WOLFSSL;
pub extern "c" fn wolfSSL_free(ssl: ?*WOLFSSL) void;
pub extern "c" fn wolfSSL_set_fd(ssl: *WOLFSSL, fd: c_int) c_int;
pub extern "c" fn wolfSSL_connect(ssl: *WOLFSSL) c_int;
pub extern "c" fn wolfSSL_accept(ssl: *WOLFSSL) c_int;
pub extern "c" fn wolfSSL_read(ssl: *WOLFSSL, buf: [*]u8, sz: c_int) c_int;
pub extern "c" fn wolfSSL_write(ssl: *WOLFSSL, buf: [*]const u8, sz: c_int) c_int;
pub extern "c" fn wolfSSL_shutdown(ssl: *WOLFSSL) c_int;

pub const WOLFSSL_ERROR_WANT_READ: c_int = 2;
pub const WOLFSSL_ERROR_WANT_WRITE: c_int = 3;

// ---------------------------------------------------------------------------
// Callback types for Ed25519
// ---------------------------------------------------------------------------

pub const CallbackEd25519Sign = *const fn (ssl: ?*WOLFSSL, in: [*]const u8, inLen: c_uint, out: [*]u8, outLen: *c_uint, keyDer: [*]const u8, keyDerLen: c_uint, ctx: ?*anyopaque) c_int;
pub const CallbackEd25519Verify = *const fn (ssl: ?*WOLFSSL, sig: [*]const u8, sigLen: c_uint, msg: [*]const u8, msgLen: c_uint, keyDer: [*]const u8, keyDerLen: c_uint, ctx: ?*anyopaque) c_int;

pub extern "c" fn wolfSSL_CTX_SetEd25519SignCb(ctx: *WOLFSSL_CTX, cb: ?CallbackEd25519Sign) void;
pub extern "c" fn wolfSSL_CTX_SetEd25519VerifyCb(ctx: *WOLFSSL_CTX, cb: ?CallbackEd25519Verify) void;
pub extern "c" fn wolfSSL_SetEd25519SignCtx(ssl: *WOLFSSL, sign_ctx: ?*anyopaque) void;
pub extern "c" fn wolfSSL_SetEd25519VerifyCtx(ssl: *WOLFSSL, verify_ctx: ?*anyopaque) void;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub const WOLFSSL_SUCCESS: c_int = 1;

pub fn init() !void {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) return error.InitFailed;
}

pub fn deinit() !void {
    if (wolfSSL_Cleanup() != WOLFSSL_SUCCESS) return error.CleanupFailed;
}

pub fn newServerCtx() !*WOLFSSL_CTX {
    const method = wolfTLSv1_3_server_method();
    const ctx = wolfSSL_CTX_new(method) orelse return error.CtxCreateFailed;
    return ctx;
}

pub fn newClientCtx() !*WOLFSSL_CTX {
    const method = wolfTLSv1_3_client_method();
    const ctx = wolfSSL_CTX_new(method) orelse return error.CtxCreateFailed;
    return ctx;
}

pub fn freeCtx(ctx: *WOLFSSL_CTX) void {
    wolfSSL_CTX_free(ctx);
}

pub const TlsError = error{ Tls };
