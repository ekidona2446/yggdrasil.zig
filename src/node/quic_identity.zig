//! QUIC listener identity, generated at runtime by WolfSSL.
//!
//! Why this file exists
//!
//! The previous `quic.zig` carried a self-signed P-256 certificate and its
//! private key as base64 string literals in the source tree. That was wrong on
//! two counts: every build of `yggdrasil.zig` presented *the same* certificate
//! to every peer, and the private key shipped inside the binary. This module
//! replaces it with a key pair that WolfSSL generates when the listener
//! starts, so nothing secret is in the repository and every node has its own
//! identity.
//!
//! Why the QUIC key is ECDSA and not the node's Ed25519 key
//!
//! `tls://` links present a self-signed certificate over the node's Ed25519
//! identity key (see `tls_wolfssl.generateIdentityCert`), and that is what
//! yggdrasil-go does too — `linkQUIC` in the reference reuses
//! `l.core.config.tls.Clone()`, i.e. literally the same `tls.Config`. It would
//! be ideal for `quic://` to do the same here. It is not possible with upstream
//! zquic, and the reason is narrow and verifiable:
//!
//!   - zquic builds the whole TLS 1.3 server flight in one call,
//!     `ServerHandshake.buildServerFlight(cert_der, private_key, ...)`
//!     (`src/tls/handshake.zig`), invoked from inside `Server.handleInitial`
//!     (`src/transport/io.zig`). There is no seam between "build flight" and
//!     "send flight" for an embedder to hook.
//!   - Inside that call, `buildCertificateVerifyWithContext` switches on
//!     `private_key.signature_scheme` and implements exactly two arms —
//!     `.ecdsa_secp256r1_sha256` and `.ecdsa_secp384r1_sha384` — both of which
//!     sign via `std.crypto.sign.ecdsa`. Every other scheme, including
//!     `.ed25519`, falls through to `error.UnsupportedSignatureScheme`.
//!   - `vendor/tls/src/PrivateKey.zig` cannot even *load* an Ed25519 key:
//!     `parseDer` handles only `rsaEncryption` and `X9_62_id_ecPublicKey` and
//!     ends in `else => unreachable`, and `signatureScheme()` covers only the
//!     three NIST curves. Feeding it the node's PKCS8 Ed25519 key is a panic.
//!   - The signing algorithm is therefore hardcoded to ECDSA in zquic. It is
//!     not reachable through the public `Server` fields (`cert_der`,
//!     `private_key`), through the `tls` module import, or through any config
//!     option — only by editing zquic, which is out of scope by design.
//!
//! WolfSSL's own QUIC bindings (`--enable-quic`, `wolfSSL_set_quic_method`)
//! would allow a WolfSSL-driven handshake, but they require owning the QUIC
//! packet layer, i.e. replacing zquic rather than embedding it.
//!
//! Why this is still interoperable and still identity-bearing
//!
//! TLS is not Yggdrasil's trust anchor — ironwood is. The reference sets
//! `InsecureSkipVerify: true` and both `VerifyPeerCertificate` and
//! `VerifyConnection` return `nil` unconditionally (`src/core/tls.go`), so no
//! peer ever validates the certificate chain. What peers *do* validate is the
//! CertificateVerify signature against the leaf's public key, which is why the
//! presented certificate and the signing key must agree.
//!
//! Accordingly this module:
//!
//!   - generates an ECDSA P-256 key pair with WolfSSL (`wc_ecc_make_key`),
//!     which zquic can both parse and sign with;
//!   - self-signs an X.509 certificate over it, never-expiring in practice
//!     (100 years, mirroring `generateIdentityCert`), with the
//!     **CommonName set to the hex-encoded Ed25519 node public key** — the
//!     same CN convention yggdrasil-go uses (`config.MarshalPEMCertificate`),
//!     so the node's real identity is still recoverable from the certificate
//!     a peer receives;
//!   - hands zquic PEM blobs, because `ServerConfig.cert_pem` / `key_pem` are
//!     the supported in-memory inputs.
//!
//! The client side needs no identity at all: yggdrasil-go dials with
//! `ClientAuth: tls.NoClientCert`, so no client certificate is requested, and
//! we deliberately pass none (passing the Ed25519 PEM would panic zquic's key
//! parser, per the third bullet above).

const std = @import("std");
const tls_wolfssl = @import("tls_wolfssl.zig");

const WC_RNG = tls_wolfssl.WC_RNG;
const ecc_key = tls_wolfssl.ecc_key;

pub const QuicIdentityError = error{
    RngFailed,
    KeyGenFailed,
    CertGenFailed,
    PemEncodeFailed,
};

/// A self-signed certificate plus its key, ready to hand to a zquic `Server`.
pub const QuicIdentity = struct {
    /// `-----BEGIN CERTIFICATE-----` … — `ServerConfig.cert_pem`.
    cert_pem: []u8,
    /// `-----BEGIN EC PRIVATE KEY-----` … (RFC 5915 SEC1) — `ServerConfig.key_pem`.
    /// zquic's `PrivateKey.parsePem` takes the SEC1 marker path and extracts
    /// the raw P-256 scalar, which is what its CertificateVerify signer needs.
    key_pem: []u8,
    /// The node's Ed25519 public key, hex-encoded — the value embedded as the
    /// certificate CommonName. Not owned; borrowed from the caller.
    node_key_hex: []const u8,

    pub fn deinit(self: *QuicIdentity, gpa: std.mem.Allocator) void {
        gpa.free(self.cert_pem);
        gpa.free(self.key_pem);
    }
};

/// P-256 is the smallest NIST curve zquic's CertificateVerify signer supports,
/// and it is what the vast majority of TLS 1.3 deployments use.
const ECC_KEYSIZE_BYTES: c_int = 32;

/// Validity window for the self-signed leaf. Yggdrasil identity certificates
/// are effectively immortal (the reference uses a "never expires" sentinel);
/// WolfSSL's `Cert.daysValid` only takes a day count, so we use a century,
/// matching `tls_wolfssl.generateIdentityCert`.
const CERT_DAYS_VALID: c_int = 365 * 100;

/// Generate the listener identity. `node_public_key_hex` must be the
/// hex-encoded Ed25519 public key of this node (64 chars); it is only recorded
/// in the CommonName.
pub fn generate(gpa: std.mem.Allocator, node_public_key_hex: []const u8) !QuicIdentity {
    var rng: WC_RNG = .{};
    if (tls_wolfssl.wc_InitRng(&rng) != 0) return QuicIdentityError.RngFailed;
    defer _ = tls_wolfssl.wc_FreeRng(&rng);

    var key: ecc_key = .{};
    if (tls_wolfssl.wc_ecc_init(&key) != 0) return QuicIdentityError.KeyGenFailed;
    defer tls_wolfssl.wc_ecc_free(&key);

    if (tls_wolfssl.wc_ecc_make_key(&rng, ECC_KEYSIZE_BYTES, &key) != 0) {
        return QuicIdentityError.KeyGenFailed;
    }

    // ── self-signed X.509 leaf ────────────────────────────────────────────
    var cert: tls_wolfssl.Cert = .{};
    if (tls_wolfssl.wc_InitCert(&cert) != 0) return QuicIdentityError.CertGenFailed;

    cert.days_valid = CERT_DAYS_VALID;
    cert.self_signed = 1;
    cert.is_ca = 0;
    cert.sig_type = tls_wolfssl.CTC_SHA256W_ECDSA;
    tls_wolfssl.setCommonName(&cert.subject, node_public_key_hex);
    cert.issuer = cert.subject;

    const der_buf = try gpa.alloc(u8, 4096);
    defer gpa.free(der_buf);

    const made = tls_wolfssl.wc_MakeCert_ex(
        &cert,
        der_buf.ptr,
        @intCast(der_buf.len),
        tls_wolfssl.KEY_TYPE_ECC,
        @ptrCast(&key),
        &rng,
    );
    if (made < 0) return QuicIdentityError.CertGenFailed;

    const signed = tls_wolfssl.wc_SignCert_ex(
        cert.body_sz,
        cert.sig_type,
        der_buf.ptr,
        @intCast(der_buf.len),
        tls_wolfssl.KEY_TYPE_ECC,
        @ptrCast(&key),
        &rng,
    );
    if (signed < 0) return QuicIdentityError.CertGenFailed;
    const cert_der = der_buf[0..@intCast(signed)];

    // ── SEC1 private key DER ──────────────────────────────────────────────
    const key_der_buf = try gpa.alloc(u8, 256);
    defer gpa.free(key_der_buf);
    const key_der_len = tls_wolfssl.wc_EccKeyToDer(&key, key_der_buf.ptr, @intCast(key_der_buf.len));
    if (key_der_len <= 0) return QuicIdentityError.KeyGenFailed;
    const key_der = key_der_buf[0..@intCast(key_der_len)];

    return .{
        .cert_pem = try derToPemAlloc(gpa, cert_der, tls_wolfssl.CERT_TYPE),
        .key_pem = try derToPemAlloc(gpa, key_der, tls_wolfssl.CERT_FILE_TYPE_ECC_PRIVATEKEY),
        .node_key_hex = node_public_key_hex,
    };
}

/// Wrap DER in a PEM block of the given WolfSSL file type.
fn derToPemAlloc(gpa: std.mem.Allocator, der: []const u8, pem_type: c_int) ![]u8 {
    // PEM inflates by 4/3 plus header/footer/newlines; 4x is ample.
    const out_buf = try gpa.alloc(u8, der.len * 4 + 128);
    defer gpa.free(out_buf);
    const n = tls_wolfssl.wc_DerToPem(der.ptr, @intCast(der.len), out_buf.ptr, @intCast(out_buf.len), pem_type);
    if (n <= 0) return QuicIdentityError.PemEncodeFailed;
    return gpa.dupe(u8, out_buf[0..@intCast(n)]);
}

const testing = std.testing;

test "quic_identity: generates PEM blocks WolfSSL produced, with the node CN" {
    // End-to-end against the real linked WolfSSL: no mocks, no fixtures.
    try tls_wolfssl.globalInit();
    defer tls_wolfssl.globalDeinit();

    const hex = "ab" ** 32; // 64 hex chars, like a real Ed25519 public key
    var ident = try generate(testing.allocator, hex);
    defer ident.deinit(testing.allocator);

    try testing.expect(std.mem.startsWith(u8, ident.cert_pem, "-----BEGIN CERTIFICATE-----"));
    try testing.expect(std.mem.endsWith(u8, ident.cert_pem, "-----END CERTIFICATE-----\n") or
        std.mem.endsWith(u8, ident.cert_pem, "-----END CERTIFICATE-----"));

    // The SEC1 marker is what routes zquic's PrivateKey.parsePem down
    // parseEcDer(), the only path that yields the raw P-256 scalar.
    try testing.expect(std.mem.indexOf(u8, ident.key_pem, "-----BEGIN EC PRIVATE KEY-----") != null);

    // Two calls must not reuse a key pair — each listener gets its own.
    var other = try generate(testing.allocator, hex);
    defer other.deinit(testing.allocator);
    try testing.expect(!std.mem.eql(u8, ident.key_pem, other.key_pem));
}
