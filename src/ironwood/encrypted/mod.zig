//! Encrypted PacketConn layer.
//!
//! Provides end-to-end XSalsa20-Poly1305 encryption, session management,
//! and key ratcheting for forward secrecy. Wire-compatible with Go Ironwood.

pub const crypto = @import("crypto.zig");
pub const session = @import("session.zig");

pub const GroupAuth = crypto.GroupAuth;
pub const CurvePublicKey = crypto.CurvePublicKey;
pub const CurvePrivateKey = crypto.CurvePrivateKey;
pub const SESSION_TRAFFIC_OVERHEAD = session.SESSION_TRAFFIC_OVERHEAD;
pub const SESSION_INIT_SIZE = session.SESSION_INIT_SIZE;
pub const SessionInit = session.SessionInit;
pub const SessionInfo = session.SessionInfo;
pub const SessionManager = session.SessionManager;
pub const SessionSnapshot = session.SessionSnapshot;
pub const OutAction = session.OutAction;
pub const deinitActions = session.deinitActions;

test {
    _ = crypto;
    _ = session;
}
