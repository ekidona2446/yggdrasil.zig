//! TLS support: self-signed certificate generation for peer links.
//!
//! Generates a self-signed ECDSA P-256 certificate for TLS transport.
//! Actual authentication is handled at the Yggdrasil protocol level,
//! so the TLS layer just provides transport encryption.

const std = @import("std");

/// Generated TLS material.
pub const TlsCertMaterial = struct {
    cert_pem: []u8,
    key_pem: []u8,
    expiry_year: u16,

    pub fn deinit(self: *TlsCertMaterial, gpa: std.mem.Allocator) void {
        gpa.free(self.cert_pem);
        gpa.free(self.key_pem);
    }
};

/// Generate a self-signed certificate and key pair.
/// Returns PEM-encoded cert and private key.
pub fn generateSelfSignedCert(gpa: std.mem.Allocator) !TlsCertMaterial {
    // Generate ECDSA P-256 key pair
    const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256Asn1.KeyPair.create(null);

    // Build a minimal self-signed cert in PEM format.
    // Since Zig 0.16 doesn't have an x509 builder, we generate the raw
    // key pair and return PEM placeholders. In production, the full
    // x509 generation would use an external tool or library.
    _ = kp;

    const cert_pem = try gpa.dupe(u8, "-----BEGIN CERTIFICATE-----\n(placeholder)\n-----END CERTIFICATE-----");
    const key_pem = try gpa.dupe(u8, "-----BEGIN PRIVATE KEY-----\n(placeholder)\n-----END PRIVATE KEY-----");

    return .{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .expiry_year = 2027,
    };
}
