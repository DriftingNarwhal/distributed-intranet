//! Ed25519 signing and verification.
//!
//! Ed25519 is not an arbitrary choice: libp2p derives a PeerId directly from an
//! Ed25519 public key, which is what lets Core Protocol Spec §1.2 obtain a
//! distinct PeerId per network for free from the per-network identity keypair,
//! rather than needing a separate transport-identity mechanism to keep
//! memberships unlinkable at the transport layer.

use crate::{CryptoError, enc::Enc};
use ed25519_dalek::{Signer as _, Verifier as _};

/// A 32-byte Ed25519 public key.
///
/// This is the on-the-wire identity of a per-network identity or a device key.
/// `Ord` is derived so that keys can be used in the ordered collections that
/// governance state relies on for deterministic encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    /// Wraps raw public key bytes, checking that they form a valid curve point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| CryptoError::MalformedPublicKey)?;
        Ok(Self(bytes))
    }

    /// Borrows the raw public key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verifies a signature over a canonical encoding.
    ///
    /// Fails closed: any parse failure of the stored key material is reported as
    /// a verification failure rather than panicking or being treated as valid.
    pub fn verify(&self, message: &Enc, signature: &Signature) -> Result<(), CryptoError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::MalformedPublicKey)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        key.verify(&message.finish(), &sig)
            .map_err(|_| CryptoError::BadSignature)
    }

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        crate::to_hex(&self.0[..4])
    }
}

impl std::fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::to_hex(&self.0))
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wraps raw signature bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}…)", crate::to_hex(&self.0[..4]))
    }
}

/// An Ed25519 secret key.
///
/// Deliberately does not implement `Debug`, `Display`, `Clone`, or serialization:
/// per-network identity private keys are derived transiently in memory when
/// needed (Core Protocol Spec §1.3) and should be hard to accidentally log,
/// copy, or persist.
pub struct SecretKey(ed25519_dalek::SigningKey);

impl SecretKey {
    /// Builds a secret key from 32 bytes of key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&bytes))
    }

    /// Generates a fresh random secret key.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        crate::random_bytes(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Returns the corresponding public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().to_bytes())
    }

    /// Signs a canonical encoding.
    pub fn sign(&self, message: &Enc) -> Signature {
        Signature(self.0.sign(&message.finish()).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(s: &str) -> Enc {
        let mut e = Enc::domain("test");
        e.str(s);
        e
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = SecretKey::generate().unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(&msg("hello"));
        assert!(vk.verify(&msg("hello"), &sig).is_ok());
    }

    #[test]
    fn verification_rejects_tampered_message() {
        let sk = SecretKey::generate().unwrap();
        let sig = sk.sign(&msg("hello"));
        assert_eq!(
            sk.verifying_key().verify(&msg("hello!"), &sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn verification_rejects_wrong_signer() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        let sig = a.sign(&msg("hello"));
        assert_eq!(
            b.verifying_key().verify(&msg("hello"), &sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let a = SecretKey::from_bytes([42u8; 32]);
        let b = SecretKey::from_bytes([42u8; 32]);
        assert_eq!(a.verifying_key(), b.verifying_key());
    }

    #[test]
    fn off_curve_public_key_is_rejected_at_construction() {
        // A point not on the curve must fail when the key is built, not silently
        // pass and then fail every verification later.
        //
        // Note the bytes: this is an encoding that does not decompress to a curve
        // point at all. It is deliberately *not* `[0xff; 32]` — Ed25519
        // implementations, this one included, accept non-canonical y-coordinates
        // (y >= p) for historical compatibility, so `[0xff; 32]` is actually
        // *accepted*. Asserting otherwise would be testing a property this
        // primitive does not have.
        let mut off_curve = [0u8; 32];
        off_curve[0] = 1;
        off_curve[31] = 3;
        assert_eq!(
            VerifyingKey::from_bytes(off_curve),
            Err(CryptoError::MalformedPublicKey)
        );
    }

    #[test]
    fn non_canonical_encodings_are_accepted_and_that_is_documented_not_assumed() {
        // Pinning the actual behaviour so a future primitive swap that changes it
        // shows up as a failing test rather than as silently different validation.
        assert!(VerifyingKey::from_bytes([0xff; 32]).is_ok());
    }
}
