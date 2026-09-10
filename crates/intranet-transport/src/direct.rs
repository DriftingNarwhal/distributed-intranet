//! Direct member-to-member delivery — Core Protocol Spec §5.1.
//!
//! One member hands another a small payload over a connection they already
//! have, and nothing is stored by anybody. Every other protocol in this crate
//! moves state a partitioned node must be able to obtain *late*; this one moves
//! a message whose whole value is that it reached a particular person now.
//!
//! # Why this is generic rather than named for its first consumer
//!
//! It arrived as the Chat Application Spec's `/chat/dm-invite/1.0.0` (spec 07
//! §7, E10) — a protocol for handing somebody the invite to a conversation
//! network, inside a network the two already share. Adding it under that name
//! would have put an application's vocabulary in the platform's behaviour set,
//! which Core §0 rules out in as many words: this document describes a
//! general-purpose platform, and application design is deferred entirely.
//!
//! The same reversal has now happened three times and is worth stating as a
//! pattern rather than rediscovering a fourth. Core §2.7.2 took four
//! chat-shaped governance entries and landed **one** application entry carrying
//! a namespace and an opaque payload. Core §2.6.2 took chat's abuse limits and
//! landed an app-layer policy *map* the protocol stores without interpreting.
//! Core §2.2.1 took chat's scoped capabilities and landed namespace
//! registration. Each time the platform gained a door rather than a room.
//!
//! So this carries `(namespace, kind, payload)` and does not decode the
//! payload. `/chat/dm-invite/1.0.0` becomes namespace `chat`, kind `dm-invite`,
//! and a second consumer needs no new protocol.
//!
//! # What this layer checks, and what it deliberately does not
//!
//! It checks that the sender is who it claims to be, that the claim matches the
//! connection the bytes arrived on, and that one identity cannot flood another.
//! It does **not** check whether the payload means anything, because it cannot
//! know — the same division [`crate::sync::gossip_behaviour`] draws for live
//! delivery, and for the same reason: half a check is worse than none, since a
//! caller reads it as the whole one.
//!
//! Membership is the consumer's to enforce too. This crate holds no governance
//! state, so a node that wants "only from a current member" replays its own log
//! and refuses what it does not like — which is what [`DirectAck::Refused`]
//! carrying an opaque reason is for.

use intranet_crypto::{Dec, DecodeError, Enc, Signature};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for the request. Permanent: a change means a new tag at `.v2`.
const DIRECT_DOMAIN: &str = "intranet.wire.direct.v1";
/// Domain tag for what a sender signs.
const DIRECT_SIGNED_DOMAIN: &str = "intranet.direct-message.v1";
/// Domain tag for the acknowledgement.
const DIRECT_ACK_DOMAIN: &str = "intranet.wire.direct-ack.v1";

/// The largest payload this carrier will move.
///
/// Deliberately small. A direct message is a message, not a transfer: content
/// belongs behind a CID that an ordinary fetch can resolve, and a carrier that
/// grew to hold bulk would become a second content path with none of Storage
/// §4's swarm, backpressure or verification. 64 KiB is generous for the first
/// consumer — an invite is on the order of a kilobyte (Core §5.6) and a
/// common-ownership proof a few hundred bytes — and small enough that a peer
/// cannot spend a member's bandwidth by sending one.
pub const MAX_DIRECT_PAYLOAD_BYTES: usize = 64 * 1024;

/// The longest namespace or kind this carrier will read.
///
/// These are routing labels a consumer matches on, not content. Bounding them
/// keeps a decode from allocating on a remote's say-so before anything has been
/// checked.
pub const MAX_DIRECT_LABEL_BYTES: usize = 64;

/// Something wrong with a direct message on the wire.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DirectError {
    /// The bytes were malformed.
    #[error("malformed direct message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in direct message")]
    InvalidKey,
    /// The signature did not verify against the named sender.
    #[error("direct message signature did not verify")]
    BadSignature,
    /// A payload exceeded [`MAX_DIRECT_PAYLOAD_BYTES`].
    #[error("payload of {size} bytes exceeds the {MAX_DIRECT_PAYLOAD_BYTES} byte ceiling")]
    PayloadTooLarge {
        /// The size presented.
        size: usize,
    },
    /// A namespace or kind exceeded [`MAX_DIRECT_LABEL_BYTES`].
    #[error("label of {size} bytes exceeds the {MAX_DIRECT_LABEL_BYTES} byte ceiling")]
    LabelTooLong {
        /// The size presented.
        size: usize,
    },
    /// A namespace or kind was empty.
    ///
    /// Refused rather than tolerated: an empty namespace is a message addressed
    /// to no consumer, and accepting one would make "which consumer is this
    /// for" answerable two ways.
    #[error("a direct message carried an empty namespace or kind")]
    EmptyLabel,
}

/// A payload handed from one member to another — Core §5.1.
///
/// The signature covers the sender, the namespace, the kind and the payload
/// together, so none of them can be altered in flight and none can be lifted
/// into a message claiming a different sender or a different consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMessage {
    /// Who sent it.
    pub sender: PerNetworkIdentityId,
    /// Which consuming spec the payload belongs to — `chat`, say.
    pub namespace: String,
    /// What kind of payload it is, within that namespace.
    pub kind: String,
    /// The payload, opaque to this crate.
    pub payload: Vec<u8>,
    /// The sender's signature over all of the above.
    pub signature: Signature,
}

impl DirectMessage {
    /// Builds and signs a direct message.
    ///
    /// Returns an error rather than truncating or accepting an oversized
    /// payload, because a carrier that silently shortened one would deliver
    /// something the sender did not write and the signature would still verify
    /// over it.
    pub fn create(
        sender: &PerNetworkIdentity,
        namespace: &str,
        kind: &str,
        payload: Vec<u8>,
    ) -> Result<Self, DirectError> {
        check_label(namespace)?;
        check_label(kind)?;
        if payload.len() > MAX_DIRECT_PAYLOAD_BYTES {
            return Err(DirectError::PayloadTooLarge {
                size: payload.len(),
            });
        }
        let id = sender.id();
        let signature = sender.sign(&Self::signed(&id, namespace, kind, &payload));
        Ok(Self {
            sender: id,
            namespace: namespace.to_owned(),
            kind: kind.to_owned(),
            payload,
            signature,
        })
    }

    /// Verifies that the named sender really produced this message.
    ///
    /// This says the bytes came from the holder of that identity's key. It does
    /// **not** say the peer that delivered them is that holder — a signature
    /// proves authorship and travels, so anybody who has seen one can replay it.
    /// Binding a message to the connection it arrived on is the caller's job and
    /// is why [`crate::node::MemberNode`] reports the peer alongside the sender.
    pub fn verify(&self) -> Result<(), DirectError> {
        self.sender
            .verifying_key()
            .verify(
                &Self::signed(&self.sender, &self.namespace, &self.kind, &self.payload),
                &self.signature,
            )
            .map_err(|_| DirectError::BadSignature)
    }

    fn signed(
        sender: &PerNetworkIdentityId,
        namespace: &str,
        kind: &str,
        payload: &[u8],
    ) -> Enc {
        let mut e = Enc::domain(DIRECT_SIGNED_DOMAIN);
        sender.encode(&mut e);
        e.str(namespace);
        e.str(kind);
        e.bytes(payload);
        e
    }

    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(DIRECT_DOMAIN);
        self.sender.encode(&mut e);
        e.str(&self.namespace);
        e.str(&self.kind);
        e.bytes(&self.payload);
        e.fixed(self.signature.as_bytes());
        e.finish()
    }

    /// Decodes a message, bounds-checks it, and verifies its signature.
    ///
    /// The ceilings are applied before the signature rather than after: a
    /// message too large to accept is refused without spending a verification
    /// on it, and a sender cannot make a receiver do asymmetric work by
    /// presenting something it was always going to reject.
    pub fn decode(bytes: &[u8]) -> Result<Self, DirectError> {
        let mut d = Dec::domain(bytes, DIRECT_DOMAIN)?;
        let sender = get_identity(&mut d)?;
        let namespace = d.str()?.to_owned();
        let kind = d.str()?.to_owned();
        let payload = d.bytes()?.to_vec();
        let signature = Signature::from_bytes(d.fixed::<64>()?);
        d.finish()?;

        check_label(&namespace)?;
        check_label(&kind)?;
        if payload.len() > MAX_DIRECT_PAYLOAD_BYTES {
            return Err(DirectError::PayloadTooLarge {
                size: payload.len(),
            });
        }

        let message = Self {
            sender,
            namespace,
            kind,
            payload,
            signature,
        };
        message.verify()?;
        Ok(message)
    }
}

/// What a recipient says back — Core §5.1.
///
/// Delivery-level only. Whether a *person* accepts what the payload proposes is
/// a later act by that person, and answering it here would make the sender's
/// request block on somebody reading their screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectAck {
    /// The payload reached a consumer that understands it.
    ///
    /// It does not say the payload was liked, acted on, or shown to anybody.
    Received,
    /// It did not, and here is roughly why.
    Refused(DirectRefusal),
}

/// Why a direct message was not taken.
///
/// Coarse on purpose. A refusal is told to somebody who may be hostile, so it
/// says enough for an honest sender to stop or retry and not enough to probe
/// with — notably, [`DirectRefusal::Rejected`] covers a block list without
/// confirming one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRefusal {
    /// Nothing here consumes that namespace or kind.
    Unsupported,
    /// This sender is asking too often.
    RateLimited,
    /// The recipient declined, and does not say more.
    ///
    /// Deliberately one variant for every application-level *no*. A block list
    /// is a client-side list (spec 07 §7, E10), and a refusal that distinguished
    /// "blocked" from "not now" would turn every rejection into a disclosure the
    /// blocker did not choose to make.
    Rejected,
}

impl DirectAck {
    /// Encodes the acknowledgement.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(DIRECT_ACK_DOMAIN);
        match self {
            Self::Received => {
                e.u8(0x01);
            }
            Self::Refused(reason) => {
                e.u8(0x02);
                e.u8(match reason {
                    DirectRefusal::Unsupported => 0x01,
                    DirectRefusal::RateLimited => 0x02,
                    DirectRefusal::Rejected => 0x03,
                });
            }
        }
        e.finish()
    }

    /// Decodes an acknowledgement.
    pub fn decode(bytes: &[u8]) -> Result<Self, DirectError> {
        let mut d = Dec::domain(bytes, DIRECT_ACK_DOMAIN)?;
        let ack = match d.u8()? {
            0x01 => Self::Received,
            0x02 => Self::Refused(match d.u8()? {
                0x01 => DirectRefusal::Unsupported,
                0x02 => DirectRefusal::RateLimited,
                0x03 => DirectRefusal::Rejected,
                other => {
                    return Err(DecodeError::UnknownVariant {
                        type_name: "DirectRefusal",
                        discriminant: other,
                    }
                    .into());
                }
            }),
            other => {
                return Err(DecodeError::UnknownVariant {
                    type_name: "DirectAck",
                    discriminant: other,
                }
                .into());
            }
        };
        d.finish()?;
        Ok(ack)
    }
}

fn check_label(label: &str) -> Result<(), DirectError> {
    if label.is_empty() {
        return Err(DirectError::EmptyLabel);
    }
    if label.len() > MAX_DIRECT_LABEL_BYTES {
        return Err(DirectError::LabelTooLong { size: label.len() });
    }
    Ok(())
}

fn get_identity(d: &mut Dec<'_>) -> Result<PerNetworkIdentityId, DirectError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| DirectError::InvalidKey)?;
    Ok(PerNetworkIdentityId::from_verifying_key(key))
}
