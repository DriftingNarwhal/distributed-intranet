//! Epoch key delivery over the wire — Core Protocol Spec §3.5, §5.6.
//!
//! # What §3.5 actually asks for
//!
//! "New-member key delivery and epoch-key redistribution both require secure
//! point-to-point channels between the distributing identity and each recipient,
//! authenticated using the per-network identity keys from §1.2." That is a
//! standard authenticated key exchange, and the identity layer already supplies
//! both halves: [`PerNetworkIdentity::sign`] for authentication and
//! [`PerNetworkIdentity::agree`] — X25519 from the same Ed25519 key — for the
//! channel. Nothing new is invented here.
//!
//! # Most of the key material never travels
//!
//! The current epoch key is **not** on the wire, under any policy. A Welcome is
//! already HPKE-sealed to the joiner's own key package by MLS, and the joiner
//! derives the epoch key from the group state it unseals. So the default
//! `CurrentEpochForward` case (§3.4) ships a Welcome and nothing else — the
//! secure 1:1 channel §3.5 requires is the Welcome itself.
//!
//! Only `FullHistory` needs more, and only for *superseded* epochs, which MLS
//! cannot supply because forward secrecy has already discarded them. Those keys
//! are raw material, so they travel sealed under the agreed secret — which is
//! the one place in this protocol where an epoch key is encrypted for a specific
//! recipient rather than derived by them.
//!
//! # What the responder must check before it welcomes anyone
//!
//! Three things, and dropping any one of them breaks the guarantee:
//!
//! 1. **The request is signed by the identity it names** — verified during
//!    decode, so an unauthenticated request never reaches the gate.
//! 2. **That identity holds `read-content`.** **Flagged: §5.6 says key delivery
//!    follows admission but names no capability.** `read-content` is the
//!    fail-closed reading and the one consistent with §5.4: an epoch key is
//!    strictly more powerful than the ciphertext that gate already protects, so
//!    gating the key more loosely than the bytes would be incoherent. It also
//!    produces exactly the behaviour §2.4 demands — a waiting-room identity
//!    holds no group, therefore no `read-content`, therefore no key.
//! 3. **The key package's credential names the requester.** Without this, a
//!    member could present a key package it generated under someone else's
//!    label and be admitted to the group as them. The signature stops the
//!    converse — naming a victim while presenting your own package — and only
//!    both together close the pair.
//!
//! Binding the request to the *connection* is the transport layer's job, exactly
//! as for chunk requests: a signature proves the named identity asked, never that
//! whoever delivered it is that identity.

use crate::EpochError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use intranet_crypto::{Dec, DecodeError, Enc, Hash, Signature, hash_bytes, keyed_hash};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};
use intranet_storage::EpochKey;

/// Domain tag for the signature a requester makes over its request.
const REQUEST_SIGNATURE_DOMAIN: &str = "intranet.epoch-key-request.v1";
/// Domain tag for a request on the wire.
const REQUEST_DOMAIN: &str = "intranet.wire.epoch-key-request.v1";
/// Domain tag for a response on the wire.
const RESPONSE_DOMAIN: &str = "intranet.wire.epoch-key-response.v1";
/// Domain tag separating the sealing key from any other use of the agreed secret.
const SEAL_DOMAIN: &str = "intranet.epoch-key-seal.v1";

/// Length of the synthetic nonce prefixed to a sealed key.
const NONCE_LEN: usize = 24;

/// The largest MLS key package this build will accept.
///
/// **Flagged: the specs set no bound.** One is required because the length is
/// chosen by the requester. 64 KiB is far above a real key package — one leaf
/// node, its credential and its signature — while bounding what an unauthenticated
/// peer can make a responder allocate before the gate is even evaluated.
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;

/// The largest MLS Welcome this build will accept.
///
/// **Flagged: the specs set no bound.** A Welcome carries the group info and
/// ratchet tree (the group is configured to carry the tree inline so a joiner
/// needs no second channel), so it scales with membership rather than being
/// fixed. 4 MiB holds a very large network's tree while keeping one response
/// bounded.
pub const MAX_WELCOME_BYTES: usize = 4 * 1024 * 1024;

/// The most historical epoch keys one response will carry.
///
/// **Flagged: §3.4 sets no bound on history delivery.** A cap is needed because
/// the count follows the network's rotation history, which grows without limit
/// over a long-lived network's life. A joiner that needs more can ask again; the
/// alternative is one response whose size no participant chose.
pub const MAX_HISTORY_KEYS: usize = 1024;

/// Why a message could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in message")]
    InvalidKey,
    /// The request decoded, but its signature did not verify.
    #[error("request signature did not verify after decoding")]
    BadSignature,
    /// A field exceeded its ceiling.
    #[error("{what} is {got} bytes, over the {limit} ceiling")]
    TooLarge {
        /// Which field.
        what: &'static str,
        /// Size presented.
        got: usize,
        /// The ceiling.
        limit: usize,
    },
    /// An unknown variant tag.
    #[error("unknown {what} variant {got}")]
    UnknownVariant {
        /// Which enum.
        what: &'static str,
        /// The tag presented.
        got: u8,
    },
}

/// A request to be keyed into the network — §3.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKeyRequest {
    /// Who is asking, for the `read-content` gate.
    pub requester: PerNetworkIdentityId,
    /// The requester's MLS key package, which the responder adds to the group.
    pub key_package: Vec<u8>,
    /// The requester's signature over `(requester, key_package)`.
    pub signature: Signature,
}

impl EpochKeyRequest {
    /// Builds and signs a request.
    pub fn create(requester: &PerNetworkIdentity, key_package: Vec<u8>) -> Self {
        let requester_id = requester.id();
        Self {
            signature: requester.sign(&Self::payload(&requester_id, &key_package)),
            requester: requester_id,
            key_package,
        }
    }

    /// Verifies that the named requester really made this request.
    ///
    /// The key package is inside the signed payload, not merely alongside it: a
    /// request whose package could be swapped in flight would let an attacker
    /// have a legitimate member's admission deliver a Welcome to a package the
    /// member never generated.
    pub fn verify(&self) -> Result<(), WireError> {
        self.requester
            .verifying_key()
            .verify(
                &Self::payload(&self.requester, &self.key_package),
                &self.signature,
            )
            .map_err(|_| WireError::BadSignature)
    }

    fn payload(requester: &PerNetworkIdentityId, key_package: &[u8]) -> Enc {
        let mut e = Enc::domain(REQUEST_SIGNATURE_DOMAIN);
        requester.encode(&mut e);
        e.bytes(key_package);
        e
    }

    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(REQUEST_DOMAIN);
        self.requester.encode(&mut e);
        e.bytes(&self.key_package);
        e.fixed(self.signature.as_bytes());
        e.finish()
    }

    /// Decodes a request and verifies its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, REQUEST_DOMAIN)?;
        let requester = get_identity(&mut d)?;
        let key_package = bounded(d.bytes()?, "key package", MAX_KEY_PACKAGE_BYTES)?;
        let request = Self {
            requester,
            key_package,
            signature: Signature::from_bytes(d.fixed::<64>()?),
        };
        d.finish()?;
        request.verify()?;
        Ok(request)
    }
}

/// Why a responder would not key a requester in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDeliveryRefusal {
    /// The requester holds no `read-content` — including every waiting-room
    /// identity under explicit intake, which is the point (§2.4, §5.6).
    NoReadContent,
    /// The responder could not evaluate the gate — no governance state yet.
    ///
    /// Distinct from a refusal on the merits, because a requester that is in
    /// fact entitled should retry against a caught-up peer rather than conclude
    /// it has been rejected.
    CannotEvaluate,
    /// The key package's credential does not name the requester.
    IdentityMismatch,
    /// The responder holds no group state, so it has nothing to welcome anyone
    /// into — it is itself waiting to be keyed in.
    NoGroup,
}

impl KeyDeliveryRefusal {
    /// A short reason, for events and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoReadContent => "requester holds no read-content",
            Self::CannotEvaluate => "responder cannot evaluate governance state",
            Self::IdentityMismatch => "key package credential does not name the requester",
            Self::NoGroup => "responder holds no group state",
        }
    }
}

/// One superseded epoch key, sealed to a specific recipient — §3.4, §3.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEpochKey {
    /// The governance log entry that produced this epoch.
    pub rotation_ref: Hash,
    /// The key, sealed under the secret agreed with the recipient.
    pub sealed: Vec<u8>,
}

/// A response to a key delivery request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochKeyResponse {
    /// The requester is welcomed into the group.
    Welcome {
        /// The MLS Welcome, already sealed to the requester's key package.
        welcome: Vec<u8>,
        /// The governance entry that recorded the admitting rotation.
        ///
        /// Carried because MLS gives the joiner a key but no notion of which
        /// governance entry produced it, and every `DekWrapping` references the
        /// entry hash rather than an ordinal (Storage Spec §5.3).
        rotation_ref: Hash,
        /// Superseded epoch keys, under `FullHistory` policy only.
        ///
        /// Empty under the `CurrentEpochForward` default, where a joiner reads
        /// from its own epoch forward and there is nothing prior to deliver.
        history: Vec<SealedEpochKey>,
    },
    /// The request was refused.
    Refused {
        /// Why.
        reason: KeyDeliveryRefusal,
    },
}

impl EpochKeyResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(RESPONSE_DOMAIN);
        match self {
            Self::Welcome {
                welcome,
                rotation_ref,
                history,
            } => {
                e.variant(0);
                e.bytes(welcome);
                e.fixed(rotation_ref.as_bytes());
                e.seq(history.iter(), |e, key| {
                    e.fixed(key.rotation_ref.as_bytes());
                    e.bytes(&key.sealed);
                });
            }
            Self::Refused { reason } => {
                e.variant(1).u8(match reason {
                    KeyDeliveryRefusal::NoReadContent => 0,
                    KeyDeliveryRefusal::CannotEvaluate => 1,
                    KeyDeliveryRefusal::IdentityMismatch => 2,
                    KeyDeliveryRefusal::NoGroup => 3,
                });
            }
        }
        e.finish()
    }

    /// Decodes a response.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => {
                let welcome = bounded(d.bytes()?, "welcome", MAX_WELCOME_BYTES)?;
                let rotation_ref = Hash::from_bytes(d.fixed::<32>()?);
                let history = d.seq::<_, WireError>(|d| {
                    Ok(SealedEpochKey {
                        rotation_ref: Hash::from_bytes(d.fixed::<32>()?),
                        sealed: d.bytes()?.to_vec(),
                    })
                })?;
                if history.len() > MAX_HISTORY_KEYS {
                    return Err(WireError::TooLarge {
                        what: "history",
                        got: history.len(),
                        limit: MAX_HISTORY_KEYS,
                    });
                }
                Self::Welcome {
                    welcome,
                    rotation_ref,
                    history,
                }
            }
            1 => Self::Refused {
                reason: match d.u8()? {
                    0 => KeyDeliveryRefusal::NoReadContent,
                    1 => KeyDeliveryRefusal::CannotEvaluate,
                    2 => KeyDeliveryRefusal::IdentityMismatch,
                    3 => KeyDeliveryRefusal::NoGroup,
                    got => {
                        return Err(WireError::UnknownVariant {
                            what: "KeyDeliveryRefusal",
                            got,
                        });
                    }
                },
            },
            got => {
                return Err(WireError::UnknownVariant {
                    what: "EpochKeyResponse",
                    got,
                });
            }
        };
        d.finish()?;
        Ok(response)
    }
}

/// Seals superseded epoch keys for one recipient — §3.4, §3.5.
///
/// The sealing key is the agreed secret, domain-separated so it can never
/// collide with another use of the same agreement (call media derives keys from
/// the same primitive).
pub fn seal_history(
    sender: &PerNetworkIdentity,
    recipient: &PerNetworkIdentityId,
    keys: &[(Hash, EpochKey)],
) -> Result<Vec<SealedEpochKey>, EpochError> {
    let secret = sender
        .agree(recipient)
        .map_err(|e| EpochError::Mls(format!("key agreement: {e}")))?;
    let sealing = sealing_key(&secret);

    keys.iter()
        .map(|(rotation_ref, key)| {
            Ok(SealedEpochKey {
                rotation_ref: *rotation_ref,
                sealed: seal(&sealing, rotation_ref, key.expose_for_delivery())?,
            })
        })
        .collect()
}

/// Opens epoch keys sealed by [`seal_history`].
pub fn open_history(
    recipient: &PerNetworkIdentity,
    sender: &PerNetworkIdentityId,
    sealed: &[SealedEpochKey],
) -> Result<Vec<(Hash, EpochKey)>, EpochError> {
    let secret = recipient
        .agree(sender)
        .map_err(|e| EpochError::Mls(format!("key agreement: {e}")))?;
    let sealing = sealing_key(&secret);

    sealed
        .iter()
        .map(|entry| {
            let opened = open(&sealing, &entry.rotation_ref, &entry.sealed)?;
            let bytes: [u8; 32] = opened
                .as_slice()
                .try_into()
                .map_err(|_| EpochError::Mls("sealed epoch key was not 32 bytes".into()))?;
            Ok((entry.rotation_ref, EpochKey::from_bytes(bytes)))
        })
        .collect()
}

fn sealing_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut e = Enc::domain(SEAL_DOMAIN);
    e.fixed(secret);
    *hash_bytes(&e.finish()).as_bytes()
}

/// Seals one key, binding it to the rotation it belongs to.
///
/// The `rotation_ref` is associated data via the nonce derivation, so a sealed
/// key lifted from one rotation's slot and replayed into another's fails to
/// open rather than silently installing the wrong key under the right name.
fn seal(key: &[u8; 32], rotation_ref: &Hash, plaintext: &[u8]) -> Result<Vec<u8>, EpochError> {
    let mac = keyed_hash(key, &{
        let mut e = Enc::domain(SEAL_DOMAIN);
        e.fixed(rotation_ref.as_bytes());
        e.bytes(plaintext);
        e.finish()
    });
    let nonce_bytes: [u8; NONCE_LEN] = mac.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("24-byte prefix of a 32-byte MAC");

    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let mut sealed = cipher
        .encrypt(&XNonce::from(nonce_bytes), plaintext)
        .map_err(|_| EpochError::Mls("sealing an epoch key failed".into()))?;

    let mut out = nonce_bytes.to_vec();
    out.append(&mut sealed);
    Ok(out)
}

fn open(key: &[u8; 32], rotation_ref: &Hash, blob: &[u8]) -> Result<Vec<u8>, EpochError> {
    if blob.len() <= NONCE_LEN {
        return Err(EpochError::Mls("sealed epoch key is truncated".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("split_at guarantees the prefix length");
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let plaintext = cipher
        .decrypt(&XNonce::from(nonce), ciphertext)
        .map_err(|_| EpochError::Mls("sealed epoch key failed authentication".into()))?;

    // Re-derive the nonce and compare: the AEAD authenticates the ciphertext,
    // but only this binds the plaintext to the rotation it was sealed for.
    let expected = keyed_hash(key, &{
        let mut e = Enc::domain(SEAL_DOMAIN);
        e.fixed(rotation_ref.as_bytes());
        e.bytes(&plaintext);
        e.finish()
    });
    if expected.as_bytes()[..NONCE_LEN] != nonce {
        return Err(EpochError::Mls(
            "sealed epoch key was sealed for a different rotation".into(),
        ));
    }
    Ok(plaintext)
}

fn bounded(bytes: &[u8], what: &'static str, limit: usize) -> Result<Vec<u8>, WireError> {
    if bytes.len() > limit {
        return Err(WireError::TooLarge {
            what,
            got: bytes.len(),
            limit,
        });
    }
    Ok(bytes.to_vec())
}

fn get_identity(d: &mut Dec<'_>) -> Result<PerNetworkIdentityId, WireError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| WireError::InvalidKey)?;
    Ok(PerNetworkIdentityId::from_verifying_key(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::{MasterSeed, NetworkId};

    fn identity(seed: u8, network: u8) -> PerNetworkIdentity {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        MasterSeed::from_entropy(bytes)
            .identity_for(&NetworkId::from_bytes([network; 32]))
            .unwrap()
    }

    #[test]
    fn a_request_round_trips_and_verifies() {
        let requester = identity(1, 7);
        let request = EpochKeyRequest::create(&requester, b"key-package".to_vec());
        let decoded = EpochKeyRequest::decode(&request.encode()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn a_swapped_key_package_fails_the_signature() {
        // The package is inside the signed payload, so substituting it in flight
        // is not a valid request from anyone.
        let requester = identity(1, 7);
        let mut request = EpochKeyRequest::create(&requester, b"key-package".to_vec());
        request.key_package = b"attacker-package".to_vec();
        assert_eq!(request.verify(), Err(WireError::BadSignature));
        assert_eq!(
            EpochKeyRequest::decode(&request.encode()),
            Err(WireError::BadSignature)
        );
    }

    #[test]
    fn a_request_naming_someone_else_fails_the_signature() {
        let requester = identity(1, 7);
        let victim = identity(2, 7);
        let mut request = EpochKeyRequest::create(&requester, b"key-package".to_vec());
        request.requester = victim.id();
        assert_eq!(request.verify(), Err(WireError::BadSignature));
    }

    #[test]
    fn an_oversized_key_package_is_refused_rather_than_allocated() {
        let requester = identity(1, 7);
        let request = EpochKeyRequest::create(&requester, vec![0u8; MAX_KEY_PACKAGE_BYTES + 1]);
        assert!(matches!(
            EpochKeyRequest::decode(&request.encode()),
            Err(WireError::TooLarge { .. })
        ));
    }

    #[test]
    fn responses_round_trip() {
        let welcome = EpochKeyResponse::Welcome {
            welcome: b"welcome-bytes".to_vec(),
            rotation_ref: Hash::from_bytes([9u8; 32]),
            history: vec![SealedEpochKey {
                rotation_ref: Hash::from_bytes([3u8; 32]),
                sealed: b"sealed".to_vec(),
            }],
        };
        assert_eq!(
            EpochKeyResponse::decode(&welcome.encode()).unwrap(),
            welcome
        );

        for reason in [
            KeyDeliveryRefusal::NoReadContent,
            KeyDeliveryRefusal::CannotEvaluate,
            KeyDeliveryRefusal::IdentityMismatch,
            KeyDeliveryRefusal::NoGroup,
        ] {
            let refused = EpochKeyResponse::Refused { reason };
            assert_eq!(
                EpochKeyResponse::decode(&refused.encode()).unwrap(),
                refused
            );
        }
    }

    #[test]
    fn history_seals_to_the_intended_recipient_only() {
        let sender = identity(1, 7);
        let recipient = identity(2, 7);
        let outsider = identity(3, 7);

        let keys = vec![
            (Hash::from_bytes([1u8; 32]), EpochKey::from_bytes([11u8; 32])),
            (Hash::from_bytes([2u8; 32]), EpochKey::from_bytes([22u8; 32])),
        ];
        let sealed = seal_history(&sender, &recipient.id(), &keys).unwrap();

        let opened = open_history(&recipient, &sender.id(), &sealed).unwrap();
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[0].0, keys[0].0);
        assert_eq!(
            opened[0].1.expose_for_delivery(),
            keys[0].1.expose_for_delivery()
        );

        // An outsider holding the ciphertext agrees a different secret.
        assert!(open_history(&outsider, &sender.id(), &sealed).is_err());
    }

    #[test]
    fn a_key_replayed_into_another_rotations_slot_does_not_open() {
        // Without the rotation binding this would install a real key under the
        // wrong rotation reference, and every wrapping under it would fail to
        // unwrap for reasons pointing at the wrong layer.
        let sender = identity(1, 7);
        let recipient = identity(2, 7);
        let keys = vec![(Hash::from_bytes([1u8; 32]), EpochKey::from_bytes([11u8; 32]))];
        let mut sealed = seal_history(&sender, &recipient.id(), &keys).unwrap();

        sealed[0].rotation_ref = Hash::from_bytes([8u8; 32]);
        assert!(open_history(&recipient, &sender.id(), &sealed).is_err());
    }
}
