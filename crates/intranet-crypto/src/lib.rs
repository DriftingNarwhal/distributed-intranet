//! Shared cryptographic primitives for the distributed intranet protocol.
//!
//! This crate deliberately holds only primitives that *every* layer needs, and no
//! protocol logic of its own. Three things live here:
//!
//! - [`enc`] — canonical, length-prefixed byte encoding. Every hash and every
//!   signature in this protocol is computed over bytes produced here, because
//!   several core guarantees require that independent nodes derive *byte-identical*
//!   representations of the same value (Core Protocol Spec §2.7's independently
//!   replayable governance log, §2.7.1's lower-entry-hash tie-break, Storage Spec
//!   §5.3's requirement that concurrent re-wraps collide byte-for-byte).
//! - [`hash`] — BLAKE3 content and entry hashing.
//! - [`sign`] — Ed25519 signing/verifying keys, chosen because libp2p derives a
//!   PeerId directly from an Ed25519 public key, which is what lets Core Protocol
//!   Spec §1.2 get a distinct-PeerId-per-network for free from the per-network
//!   identity keypair rather than needing a second mechanism.
//! - [`time`] — protocol timestamps, which never read the system clock. Every
//!   caller passes "now" in, because the harness must drive finality and ballot
//!   close boundaries on a virtual clock.

pub mod enc;
pub mod hash;
pub mod sign;
pub mod time;

pub use enc::Enc;
pub use hash::{Hash, hash_bytes, hash_enc, keyed_hash, merkle_root};
pub use sign::{SecretKey, Signature, VerifyingKey};
pub use time::Timestamp;

/// Errors produced by primitives in this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A byte slice was not the exact length required for the target type.
    #[error("expected {expected} bytes for {what}, got {got}")]
    BadLength {
        /// Type the bytes were being parsed into.
        what: &'static str,
        /// Required length.
        expected: usize,
        /// Provided length.
        got: usize,
    },

    /// A public key was structurally invalid (e.g. not a valid curve point).
    #[error("malformed public key")]
    MalformedPublicKey,

    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,

    /// The operating system entropy source failed.
    #[error("could not obtain entropy from the operating system: {0}")]
    Entropy(String),
}

/// Fills `buf` with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|e| CryptoError::Entropy(e.to_string()))
}

/// Renders bytes as lowercase hex.
///
/// Used for human-facing identifiers in logs and CLI output only — never as an
/// input to a hash or signature, which always consume raw bytes via [`enc`].
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parses lowercase or uppercase hex into bytes.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x0f, 0xff, 0xa7];
        assert_eq!(to_hex(&bytes), "000fffa7");
        assert_eq!(from_hex("000fffa7").unwrap(), bytes);
        assert_eq!(from_hex("abc"), None, "odd length must be rejected");
        assert_eq!(from_hex("zz"), None, "non-hex must be rejected");
    }

    #[test]
    fn random_bytes_fills() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a).unwrap();
        random_bytes(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
