//! Call media encryption — Real-Time Spec §1.3, §2.2.
//!
//! # Why this is what makes blind relaying possible
//!
//! Call media is end-to-end encrypted between participants, using keys derived
//! from their per-network identities and independent of whatever transport
//! security libp2p already provides. A relay forwarding this traffic is
//! *architecturally incapable* of reading it — not merely asked not to.
//!
//! That distinction is the whole reason a relay can be filled by a lower-trust
//! member. "Will forward my packets faithfully" is a much smaller ask than
//! "won't listen to my call", and the design should never require the latter.
//!
//! # Keys come from identities, not a parallel keypair
//!
//! Ed25519 and X25519 share a curve, so a participant's identity key doubles as
//! a Diffie-Hellman key. There is no separate encryption keypair to distribute,
//! rotate, or let drift out of step with identity — and a pairwise secret is
//! reachable by both sides from public information they already hold.
//!
//! The call key itself is fresh per call and delivered to each participant under
//! their pairwise secret. Deriving it from the participant set instead would
//! make every call between the same people share a key, so one recovered key
//! would open the entire history of that group's calls.

use crate::RealtimeError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use intranet_crypto::{Enc, Hash, hash_bytes, random_bytes};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// A symmetric key protecting one call's media.
///
/// Implements no `Debug` or serialization: like every other key in this system,
/// it should be awkward to print or persist by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct CallKey([u8; 32]);

impl CallKey {
    /// Generates a fresh key for a new call.
    pub fn generate() -> Result<Self, RealtimeError> {
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes).map_err(|_| RealtimeError::Entropy)?;
        Ok(Self(bytes))
    }

    /// Reconstructs a key from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A safe-to-log identifier for this key.
    pub fn fingerprint(&self) -> Hash {
        let mut e = Enc::domain("intranet.call-key-fingerprint.v1");
        e.fixed(&self.0);
        hash_bytes(&e.finish())
    }

    /// Seals one media frame.
    ///
    /// The nonce is derived from the call and the frame's sequence number rather
    /// than chosen at random. Sequence numbers are already unique within a call
    /// and already travel with the frame, so this removes a nonce from the wire
    /// and makes reuse a visible protocol error — a repeated sequence number —
    /// rather than an invisible cryptographic one.
    pub fn seal_frame(&self, call: &CallId, sequence: u64, plaintext: &[u8]) -> MediaFrame {
        let cipher = XChaCha20Poly1305::new(&Key::from(self.0));
        let ciphertext = cipher
            .encrypt(&Self::frame_nonce(call, sequence), plaintext)
            .expect("sealing cannot fail for in-memory input");
        MediaFrame {
            sequence,
            ciphertext,
        }
    }

    /// Opens one media frame.
    ///
    /// Authentication is what makes a relay unable to inject, modify, or
    /// selectively corrupt traffic undetected: tampering fails here, at the
    /// receiving participant, rather than being merely confidentiality-protected.
    pub fn open_frame(&self, call: &CallId, frame: &MediaFrame) -> Result<Vec<u8>, RealtimeError> {
        let cipher = XChaCha20Poly1305::new(&Key::from(self.0));
        cipher
            .decrypt(
                &Self::frame_nonce(call, frame.sequence),
                frame.ciphertext.as_ref(),
            )
            .map_err(|_| RealtimeError::FrameAuthenticationFailed {
                sequence: frame.sequence,
            })
    }

    fn frame_nonce(call: &CallId, sequence: u64) -> XNonce {
        let mut e = Enc::domain("intranet.call-frame-nonce.v1");
        e.fixed(call.as_bytes()).u64(sequence);
        let digest = hash_bytes(&e.finish());
        let bytes: [u8; 24] = digest.as_bytes()[..24]
            .try_into()
            .expect("24-byte prefix of a 32-byte digest");
        XNonce::from(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A call's identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct CallId([u8; 32]);

impl CallId {
    /// Generates a new call identifier.
    pub fn generate() -> Result<Self, RealtimeError> {
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes).map_err(|_| RealtimeError::Entropy)?;
        Ok(Self(bytes))
    }

    /// Wraps raw identifier bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Renders the first 8 hex characters.
    pub fn short(&self) -> String {
        intranet_crypto::to_hex(&self.0[..4])
    }
}

/// One encrypted media frame, as a relay sees it.
///
/// A relay observes exactly this: an opaque payload and a sequence number for
/// ordering. No participant identity, no timing beyond arrival, no content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFrame {
    /// Position in the call's frame sequence.
    pub sequence: u64,
    /// The sealed payload.
    pub ciphertext: Vec<u8>,
}

/// A call key delivered to one participant, sealed under a pairwise secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallKeyEnvelope {
    /// The call this key is for.
    pub call: CallId,
    /// Who sent it.
    pub sender: PerNetworkIdentityId,
    /// Who may open it.
    pub recipient: PerNetworkIdentityId,
    /// The sealed key.
    pub sealed_key: Vec<u8>,
}

impl CallKeyEnvelope {
    /// Seals a call key for one participant.
    pub fn seal(
        sender: &PerNetworkIdentity,
        recipient: &PerNetworkIdentityId,
        call: CallId,
        key: &CallKey,
    ) -> Result<Self, RealtimeError> {
        let shared = sender
            .agree(recipient)
            .map_err(|_| RealtimeError::KeyAgreementFailed)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(shared));
        let sealed_key = cipher
            .encrypt(
                &Self::envelope_nonce(&call, &sender.id(), recipient),
                key.as_bytes().as_ref(),
            )
            .map_err(|_| RealtimeError::KeyAgreementFailed)?;

        Ok(Self {
            call,
            sender: sender.id(),
            recipient: *recipient,
            sealed_key,
        })
    }

    /// Opens an envelope addressed to `recipient`.
    pub fn open(&self, recipient: &PerNetworkIdentity) -> Result<CallKey, RealtimeError> {
        if recipient.id() != self.recipient {
            return Err(RealtimeError::NotTheRecipient);
        }
        let shared = recipient
            .agree(&self.sender)
            .map_err(|_| RealtimeError::KeyAgreementFailed)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(shared));
        let opened = cipher
            .decrypt(
                &Self::envelope_nonce(&self.call, &self.sender, &self.recipient),
                self.sealed_key.as_ref(),
            )
            .map_err(|_| RealtimeError::KeyAgreementFailed)?;

        let bytes: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| RealtimeError::KeyAgreementFailed)?;
        Ok(CallKey::from_bytes(bytes))
    }

    fn envelope_nonce(
        call: &CallId,
        sender: &PerNetworkIdentityId,
        recipient: &PerNetworkIdentityId,
    ) -> XNonce {
        let mut e = Enc::domain("intranet.call-key-envelope-nonce.v1");
        e.fixed(call.as_bytes());
        sender.encode(&mut e);
        recipient.encode(&mut e);
        let digest = hash_bytes(&e.finish());
        let bytes: [u8; 24] = digest.as_bytes()[..24]
            .try_into()
            .expect("24-byte prefix of a 32-byte digest");
        XNonce::from(bytes)
    }
}
