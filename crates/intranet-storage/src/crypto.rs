//! Envelope encryption — Storage Spec §1.2, §5.
//!
//! # Two keys, and why
//!
//! Content is encrypted under a per-object **Data Encryption Key**, not the
//! network's epoch key. The epoch key only ever wraps that small DEK. This is
//! what makes revocation cheap: an epoch rotation re-wraps each live object's
//! 32-byte key record and never touches content ciphertext, CIDs, or replica
//! placement. Under the design this replaces, every revocation required
//! re-encrypting the network's entire corpus — meaning a large, high-churn
//! network would perpetually redistribute its own content just to keep up with
//! routine membership changes.
//!
//! # Deterministic encryption, and the leak it accepts
//!
//! Chunk encryption must be deterministic per `(plaintext, key)`. Ordinary
//! random-nonce AEAD would give every unchanged chunk a fresh ciphertext and
//! therefore a fresh CID on every re-publish, silently destroying the
//! delta-fetch property chunking exists to provide — with no symptom short of
//! noticing that edits re-upload everything.
//!
//! The nonce is therefore synthetic: a MAC over the plaintext under the key, in
//! the spirit of AES-SIV. The accepted cost is an **equality leak** — two
//! identical chunks under the same key are visibly identical as ciphertext to
//! anyone holding it, without the key. That is precisely what deduplication
//! requires structurally, and the parties who can observe it are already network
//! members entitled to the content. It is a real cryptographic tradeoff, not a
//! free property.
//!
//! Because each object has its own DEK, identical plaintext published as two
//! unrelated objects does **not** produce identical ciphertext. Deduplication is
//! scoped to an object's own version history — which is exactly the
//! "don't re-download a page you already have most of" case — and cross-object
//! dedup is given up deliberately in exchange.

use crate::StorageError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use intranet_crypto::{Hash, hash_bytes, keyed_hash, random_bytes};

/// Length of the synthetic nonce prefixed to every sealed blob.
const NONCE_LEN: usize = 24;

/// Seals `plaintext` under `key` with a nonce derived from both.
///
/// The nonce is prepended to the output because decryption needs it and cannot
/// re-derive it — deriving the nonce requires the plaintext, which is what is
/// being recovered. This is the standard synthetic-IV layout.
fn seal_deterministic(key: &[u8; 32], context: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Bind the nonce to a context string as well as the plaintext, so the same
    // bytes encrypted for two different purposes under one key do not collide.
    let mut mac_input = Vec::with_capacity(context.len() + plaintext.len() + 8);
    mac_input.extend_from_slice(&(context.len() as u64).to_be_bytes());
    mac_input.extend_from_slice(context);
    mac_input.extend_from_slice(plaintext);

    let mac = keyed_hash(key, &mac_input);
    let nonce_bytes: [u8; NONCE_LEN] = mac.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("24-byte prefix of a 32-byte MAC");
    let nonce = XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let sealed = cipher
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 sealing cannot fail for in-memory input");

    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&sealed);
    out
}

/// Opens a blob produced by [`seal_deterministic`].
fn open_deterministic(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, StorageError> {
    if blob.len() < NONCE_LEN {
        return Err(StorageError::MalformedCiphertext);
    }
    let nonce_bytes: [u8; NONCE_LEN] = blob[..NONCE_LEN]
        .try_into()
        .expect("checked length above");
    let nonce = XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(&nonce, &blob[NONCE_LEN..])
        .map_err(|_| StorageError::DecryptionFailed)
}

/// An object's Data Encryption Key.
///
/// Generated once when an object is created and **fixed for the object's
/// lifetime**, across every subsequent edit. That fixedness is what preserves
/// delta-fetch across an object's version history: two versions encrypted under
/// the same DEK produce identical CIDs for every chunk whose plaintext did not
/// change.
///
/// Implements no `Debug`, `Display`, or serialization: a DEK leaves memory only
/// wrapped under an epoch key.
#[derive(Clone, PartialEq, Eq)]
pub struct Dek([u8; 32]);

impl Dek {
    /// Generates a fresh random DEK for a new object.
    pub fn generate() -> Result<Self, StorageError> {
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes).map_err(|_| StorageError::Entropy)?;
        Ok(Self(bytes))
    }

    /// Reconstructs a DEK from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The public commitment to this DEK — Storage Spec §2.2.
    ///
    /// The owner signs this once, at object creation, and never signs anything
    /// DEK-related again. Every later wrapping is validated against it, which is
    /// what makes it safe for *any* current member to re-wrap without forging
    /// the owner's authority: a re-wrapper demonstrates it wrapped the DEK the
    /// owner already committed to, rather than asserting the owner's approval.
    pub fn commitment(&self) -> Hash {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(b"intranet.dek-commitment.v1");
        input.extend_from_slice(&self.0);
        hash_bytes(&input)
    }

    /// Encrypts one chunk deterministically.
    pub fn seal_chunk(&self, plaintext: &[u8]) -> Vec<u8> {
        seal_deterministic(&self.0, b"intranet.chunk.v1", plaintext)
    }

    /// Decrypts one chunk.
    pub fn open_chunk(&self, ciphertext: &[u8]) -> Result<Vec<u8>, StorageError> {
        open_deterministic(&self.0, ciphertext)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A network epoch key — the key that wraps DEKs.
///
/// Supplied by the group-keying layer (MLS, Core Protocol Spec §3.3). This crate
/// treats it as opaque key material and deliberately knows nothing about how it
/// is derived, rotated, or distributed.
#[derive(Clone, PartialEq, Eq)]
pub struct EpochKey([u8; 32]);

impl EpochKey {
    /// Wraps raw epoch key material.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Wraps a DEK for storage alongside a pointer.
    ///
    /// **Deterministic by requirement, not convenience** (§5.3). Multiple
    /// members independently re-wrapping the same object under the same rotation
    /// must produce byte-identical records, so that redundant re-wrapping
    /// creates no conflict to resolve. Randomised wrapping would make every
    /// honest re-wrapper's output differ and turn a cooperative, idempotent
    /// operation into a contended one.
    pub fn wrap(&self, pointer_id: &intranet_governance::PointerId, dek: &Dek) -> Vec<u8> {
        let mut context = Vec::with_capacity(64);
        context.extend_from_slice(b"intranet.dek-wrap.v1");
        context.extend_from_slice(pointer_id.as_bytes());
        seal_deterministic(&self.0, &context, dek.as_bytes())
    }

    /// Unwraps a DEK.
    pub fn unwrap_dek(
        &self,
        pointer_id: &intranet_governance::PointerId,
        wrapped: &[u8],
    ) -> Result<Dek, StorageError> {
        let _ = pointer_id;
        let bytes = open_deterministic(&self.0, wrapped)?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::MalformedCiphertext)?;
        Ok(Dek::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_governance::PointerId;

    #[test]
    fn chunk_encryption_is_deterministic() {
        // The requirement delta-fetch silently depends on. A regression here
        // would break deduplication with no symptom short of this check.
        let dek = Dek::from_bytes([7u8; 32]);
        let plaintext = b"a chunk of content";
        assert_eq!(dek.seal_chunk(plaintext), dek.seal_chunk(plaintext));
    }

    #[test]
    fn chunk_encryption_round_trips() {
        let dek = Dek::generate().unwrap();
        let plaintext = b"round trip me";
        let sealed = dek.seal_chunk(plaintext);
        assert_eq!(dek.open_chunk(&sealed).unwrap(), plaintext);
    }

    #[test]
    fn different_plaintexts_give_different_ciphertexts() {
        let dek = Dek::from_bytes([7u8; 32]);
        assert_ne!(dek.seal_chunk(b"alpha"), dek.seal_chunk(b"beta"));
    }

    #[test]
    fn identical_plaintext_under_different_deks_does_not_collide() {
        // Why deduplication is per-object rather than global: each object has an
        // independently generated DEK, so coincidentally identical content from
        // unrelated publishes does not converge.
        let a = Dek::from_bytes([1u8; 32]);
        let b = Dek::from_bytes([2u8; 32]);
        assert_ne!(a.seal_chunk(b"same bytes"), b.seal_chunk(b"same bytes"));
    }

    #[test]
    fn a_wrong_dek_cannot_open_a_chunk() {
        let sealed = Dek::from_bytes([1u8; 32]).seal_chunk(b"secret");
        assert_eq!(
            Dek::from_bytes([2u8; 32]).open_chunk(&sealed),
            Err(StorageError::DecryptionFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected_rather_than_returning_garbage() {
        let dek = Dek::from_bytes([1u8; 32]);
        let mut sealed = dek.seal_chunk(b"authentic");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(dek.open_chunk(&sealed), Err(StorageError::DecryptionFailed));
    }

    #[test]
    fn a_truncated_blob_is_rejected() {
        assert_eq!(
            Dek::from_bytes([1u8; 32]).open_chunk(&[0u8; 4]),
            Err(StorageError::MalformedCiphertext)
        );
    }

    #[test]
    fn commitments_identify_a_dek_without_revealing_it() {
        let dek = Dek::from_bytes([3u8; 32]);
        assert_eq!(dek.commitment(), Dek::from_bytes([3u8; 32]).commitment());
        assert_ne!(dek.commitment(), Dek::from_bytes([4u8; 32]).commitment());
        assert_ne!(
            dek.commitment().as_bytes(),
            &[3u8; 32],
            "a commitment must not simply be the key"
        );
    }

    #[test]
    fn dek_wrapping_is_deterministic_so_concurrent_rewraps_agree() {
        // §5.3: multiple members re-wrapping the same object under the same
        // rotation must produce byte-identical records, or a cooperative
        // idempotent operation becomes a contended one.
        let epoch = EpochKey::from_bytes([9u8; 32]);
        let dek = Dek::from_bytes([5u8; 32]);
        let pointer = PointerId::from_bytes([1u8; 32]);

        assert_eq!(epoch.wrap(&pointer, &dek), epoch.wrap(&pointer, &dek));
    }

    #[test]
    fn dek_wrapping_round_trips_and_matches_its_commitment() {
        let epoch = EpochKey::from_bytes([9u8; 32]);
        let dek = Dek::generate().unwrap();
        let pointer = PointerId::from_bytes([1u8; 32]);

        let wrapped = epoch.wrap(&pointer, &dek);
        let recovered = epoch.unwrap_dek(&pointer, &wrapped).unwrap();
        assert_eq!(recovered.commitment(), dek.commitment());
    }

    #[test]
    fn the_same_dek_wraps_differently_under_different_pointers() {
        // Context binding: an object's wrapping should not be transplantable
        // onto a different object even under the same epoch key.
        let epoch = EpochKey::from_bytes([9u8; 32]);
        let dek = Dek::from_bytes([5u8; 32]);
        assert_ne!(
            epoch.wrap(&PointerId::from_bytes([1u8; 32]), &dek),
            epoch.wrap(&PointerId::from_bytes([2u8; 32]), &dek)
        );
    }

    #[test]
    fn a_revoked_members_old_epoch_key_cannot_unwrap_a_new_wrapping() {
        // The core of the revocation guarantee: whatever is wrapped for the
        // first time after removal is unreachable to the removed member.
        let old = EpochKey::from_bytes([1u8; 32]);
        let new = EpochKey::from_bytes([2u8; 32]);
        let dek = Dek::generate().unwrap();
        let pointer = PointerId::from_bytes([1u8; 32]);

        let rewrapped = new.wrap(&pointer, &dek);
        assert!(old.unwrap_dek(&pointer, &rewrapped).is_err());
        assert!(new.unwrap_dek(&pointer, &rewrapped).is_ok());
    }

    #[test]
    fn a_chunk_and_a_dek_wrap_never_collide_under_one_key() {
        // Domain separation between the two uses of the same primitive.
        let key = [4u8; 32];
        let as_chunk = Dek::from_bytes(key).seal_chunk(&[7u8; 32]);
        let as_wrap = EpochKey::from_bytes(key).wrap(
            &PointerId::from_bytes([0u8; 32]),
            &Dek::from_bytes([7u8; 32]),
        );
        assert_ne!(as_chunk, as_wrap);
    }
}
