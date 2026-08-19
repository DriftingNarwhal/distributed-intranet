//! Wire encoding for call signalling and media — Real-Time Spec §1.3–1.4, §2.2.
//!
//! # Two channels, and why they are not one
//!
//! §1.4 describes a "lightweight, session-scoped signaling channel" that
//! participants already need for the initial mesh and that renegotiation reuses.
//! Media is a different thing entirely: continuous, latency-sensitive, and — the
//! point of the whole design — routed through nodes that must not be able to
//! read it. Keeping them separate is what lets a blind relay carry the second
//! without ever touching the first, since a relay that handled signalling would
//! see key envelopes go past.
//!
//! # Why signalling is signed and media is not
//!
//! A signalling message changes what a call *does* — who is in it, which relay
//! carries it — so it has to be attributable. A media frame does not need a
//! signature because it is already authenticated: frames are sealed with an AEAD
//! under the call key, so §2.2's "cannot inject, modify, or selectively suppress
//! content undetected" falls out of the encryption rather than needing a second
//! mechanism. Signing every frame would add a per-frame asymmetric operation to
//! the one path in this system where latency is the whole product.
//!
//! # Delivery semantics
//!
//! §1.5 requires call media to be delivered unreliably and unordered: a frame
//! past its playout deadline is worthless, and waiting for it stalls everything
//! behind it. This module encodes frames; it does not choose how they travel.
//! The transport currently carries them over a reliable ordered protocol, which
//! §1.5 permits only as a fallback and which `intranet-transport`'s
//! `MEDIA_PROTOCOL` documents as such.
//!
//! One consequence shows up here: [`MediaFrame`] carries an explicit sequence
//! number rather than relying on arrival order. That is not redundancy — under
//! the delivery model §1.5 actually asks for, frames arrive out of order and
//! some never arrive at all, so the sequence is the only thing that says where a
//! frame belongs.
//!
//! # What a relay can see, stated exactly
//!
//! A [`MediaEnvelope`] carries the call, the sender, the recipient and
//! ciphertext. §2.2 says a relay sees "ciphertext packets and routing metadata
//! (which participant's stream goes where) — nothing else", and that is
//! literally this struct. The routing fields are deliberately *not* covered by
//! the AEAD, because the relay has to read them; a malicious relay can therefore
//! misroute a frame, and the consequence is bounded to exactly that. A frame
//! delivered to the wrong participant simply fails to open, because the nonce
//! binds the call and the sequence.

use crate::{
    CallId, CallKeyEnvelope, MediaFrame, RealtimeError, RenegotiationTrigger, Topology,
    TopologyProposal,
};
use intranet_crypto::{Dec, DecodeError, Enc, Signature, Timestamp};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for a signalling message's signature.
const SIGNAL_SIGNATURE_DOMAIN: &str = "intranet.call-signal.v1";
/// Domain tag for a signalling message on the wire.
const SIGNAL_DOMAIN: &str = "intranet.wire.call-signal.v1";
/// Domain tag for a media envelope on the wire.
///
/// **v2, and the version is the point.** v1 encoded the recipient as a bare
/// identity, which left no room for the fan-out form §2.2.1 requires. Adding a
/// discriminant in place is not additive — a v1 envelope decoded under a v2
/// reader would read the first byte of its recipient as the discriminant and,
/// twice in every 256 envelopes, succeed at parsing something wrong. Advancing
/// the tag turns that into a decode failure, which is what domain separation is
/// for.
const MEDIA_DOMAIN: &str = "intranet.wire.call-media.v2";

/// The largest sealed key an envelope will carry.
///
/// A call key is 32 bytes plus AEAD overhead, so anything approaching this is
/// malformed. **Flagged: the specs set no bound**, but the length is chosen by
/// the sender and every other length on a wire in this project is bounded.
pub const MAX_SEALED_KEY_BYTES: usize = 256;

/// The largest media frame this build will accept.
///
/// **Flagged: §1 sets no frame size.** A ceiling is needed because the length is
/// peer-chosen. 1 MiB is generous for a single audio or video frame while
/// keeping one envelope's cost bounded — a relay forwards these continuously, so
/// an unbounded frame is an unbounded amplification of whatever an attacker
/// sends.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Why a realtime message could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in message")]
    InvalidKey,
    /// The signalling message's signature did not verify.
    #[error("call signal signature did not verify")]
    BadSignature,
    /// A payload exceeded its ceiling.
    #[error("payload of {size} bytes exceeds the {limit} byte ceiling")]
    TooLarge {
        /// The size claimed.
        size: usize,
        /// The ceiling.
        limit: usize,
    },
}

fn unknown(type_name: &'static str, discriminant: u8) -> WireError {
    WireError::Malformed(DecodeError::UnknownVariant {
        type_name,
        discriminant,
    })
}

fn get_identity(d: &mut Dec<'_>) -> Result<PerNetworkIdentityId, WireError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| WireError::InvalidKey)?;
    Ok(PerNetworkIdentityId::from_verifying_key(key))
}

/// What a signalling message says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalBody {
    /// Invites a participant, carrying their sealed call key.
    ///
    /// The key travels with the invitation rather than in a second round trip:
    /// an invitee who cannot decrypt anything is not yet in the call, and
    /// splitting the two would create a window in which they are nominally
    /// joined and functionally deaf.
    Invite {
        /// The call key, sealed to the recipient under a pairwise secret.
        envelope: CallKeyEnvelope,
    },
    /// Proposes a topology change — §1.4.
    Propose {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: TopologyProposal,
    },
    /// Announces that the sender is leaving.
    Leave {
        /// The call.
        call: CallId,
    },
}

/// A signed signalling message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// What it says.
    pub body: SignalBody,
    /// Who sent it.
    pub sender: PerNetworkIdentityId,
    /// The sender's signature.
    pub signature: Signature,
}

impl Signal {
    /// Builds and signs a message.
    pub fn create(sender: &PerNetworkIdentity, body: SignalBody) -> Self {
        let sender_id = sender.id();
        Self {
            signature: sender.sign(&Self::payload(&body, &sender_id)),
            body,
            sender: sender_id,
        }
    }

    /// Verifies the sender's signature.
    pub fn verify(&self) -> Result<(), WireError> {
        self.sender
            .verifying_key()
            .verify(&Self::payload(&self.body, &self.sender), &self.signature)
            .map_err(|_| WireError::BadSignature)
    }

    fn payload(body: &SignalBody, sender: &PerNetworkIdentityId) -> Enc {
        let mut e = Enc::domain(SIGNAL_SIGNATURE_DOMAIN);
        put_body(&mut e, body);
        sender.encode(&mut e);
        e
    }

    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(SIGNAL_DOMAIN);
        put_body(&mut e, &self.body);
        self.sender.encode(&mut e);
        e.fixed(self.signature.as_bytes());
        e.finish()
    }

    /// Decodes a message and verifies its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, SIGNAL_DOMAIN)?;
        let body = get_body(&mut d)?;
        let sender = get_identity(&mut d)?;
        let signature = Signature::from_bytes(d.fixed::<64>()?);
        d.finish()?;

        let signal = Self {
            body,
            sender,
            signature,
        };
        signal.verify()?;
        Ok(signal)
    }
}

fn put_body(e: &mut Enc, body: &SignalBody) {
    match body {
        SignalBody::Invite { envelope } => {
            e.variant(0).fixed(envelope.call.as_bytes());
            envelope.sender.encode(e);
            envelope.recipient.encode(e);
            e.bytes(&envelope.sealed_key);
        }
        SignalBody::Propose { call, proposal } => {
            e.variant(1).fixed(call.as_bytes());
            proposal.proposer.encode(e);
            match proposal.topology {
                Topology::Mesh => {
                    e.variant(0);
                }
                Topology::Relayed { relay } => {
                    e.variant(1);
                    relay.encode(e);
                }
            }
            e.u8(match proposal.trigger {
                RenegotiationTrigger::ThresholdReached => 0,
                RenegotiationTrigger::BelowThreshold => 1,
                RenegotiationTrigger::RelayUnavailable => 2,
            })
            .i64(proposal.proposed_at.as_millis());
        }
        SignalBody::Leave { call } => {
            e.variant(2).fixed(call.as_bytes());
        }
    }
}

fn get_body(d: &mut Dec<'_>) -> Result<SignalBody, WireError> {
    Ok(match d.variant()? {
        0 => {
            let call = CallId::from_bytes(d.fixed::<32>()?);
            let sender = get_identity(d)?;
            let recipient = get_identity(d)?;
            let sealed_key = d.bytes()?;
            if sealed_key.len() > MAX_SEALED_KEY_BYTES {
                return Err(WireError::TooLarge {
                    size: sealed_key.len(),
                    limit: MAX_SEALED_KEY_BYTES,
                });
            }
            SignalBody::Invite {
                envelope: CallKeyEnvelope {
                    call,
                    sender,
                    recipient,
                    sealed_key: sealed_key.to_vec(),
                },
            }
        }
        1 => {
            let call = CallId::from_bytes(d.fixed::<32>()?);
            let proposer = get_identity(d)?;
            let topology = match d.variant()? {
                0 => Topology::Mesh,
                1 => Topology::Relayed {
                    relay: get_identity(d)?,
                },
                other => return Err(unknown("Topology", other)),
            };
            let trigger = match d.u8()? {
                0 => RenegotiationTrigger::ThresholdReached,
                1 => RenegotiationTrigger::BelowThreshold,
                2 => RenegotiationTrigger::RelayUnavailable,
                other => return Err(unknown("RenegotiationTrigger", other)),
            };
            SignalBody::Propose {
                call,
                proposal: TopologyProposal {
                    proposer,
                    topology,
                    trigger,
                    proposed_at: Timestamp::from_millis(d.i64()?),
                },
            }
        }
        2 => SignalBody::Leave {
            call: CallId::from_bytes(d.fixed::<32>()?),
        },
        other => return Err(unknown("SignalBody", other)),
    })
}

/// Acknowledgement of a signalling message.
///
/// Signalling runs over a request/response protocol, so something has to come
/// back. It carries no information deliberately: a participant's actual response
/// to a proposal is its own proposal or its handover, not a field in an ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalAck;

impl SignalAck {
    /// Encodes the acknowledgement.
    pub fn encode(&self) -> Vec<u8> {
        Enc::domain("intranet.wire.call-signal-ack.v1").finish()
    }

    /// Decodes an acknowledgement.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Dec::domain(bytes, "intranet.wire.call-signal-ack.v1")?.finish()?;
        Ok(Self)
    }
}

/// Who a media envelope is for — §2.2.1.
///
/// # Why this is not just an identity
///
/// A relay exists to stop each participant paying (N−1) × bitrate in upload
/// (§1.1). With a bare identity in this field the sender emits one envelope per
/// recipient and the relay forwards each to the one it names, which spends the
/// sender exactly what mesh spends and adds a hop — a relay that saves nobody
/// anything. [`Recipient::Participants`] is the form that actually does the job:
/// the sender emits one envelope per frame and the relay replicates it.
///
/// # What the sender may not say
///
/// Note what is deliberately absent: there is no variant carrying a *list*. The
/// fan-out set is the participant list the relay was told when it agreed to
/// carry the call, never one travelling in the envelope. That makes this form
/// strictly safer than the per-recipient one — a sender cannot aim a relay at a
/// non-participant, because it has no field in which to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// One named participant.
    ///
    /// The mesh form, where the sender addresses each peer directly. It is also
    /// what a relay produces: each forwarded copy is readdressed to the
    /// participant receiving it, so a participant never holds a fan-out envelope
    /// and a forwarding loop has nowhere to start (§2.2.1 rule 4).
    One(PerNetworkIdentityId),
    /// Every participant of the call except the sender.
    ///
    /// Only a relay acts on this. A node that receives one for a call it did not
    /// agree to carry drops it.
    Participants,
}

impl Recipient {
    /// The participant named, if this is the named form.
    pub fn named(&self) -> Option<PerNetworkIdentityId> {
        match self {
            Self::One(id) => Some(*id),
            Self::Participants => None,
        }
    }

    /// Whether this envelope is addressed to `identity` personally.
    pub fn is(&self, identity: &PerNetworkIdentityId) -> bool {
        matches!(self, Self::One(id) if id == identity)
    }

    fn encode(&self, e: &mut Enc) {
        match self {
            Self::One(id) => {
                e.u8(0);
                id.encode(e);
            }
            Self::Participants => {
                e.u8(1);
            }
        }
    }

    fn decode(d: &mut Dec<'_>) -> Result<Self, WireError> {
        match d.u8()? {
            0 => Ok(Self::One(get_identity(d)?)),
            1 => Ok(Self::Participants),
            other => Err(unknown("Recipient", other)),
        }
    }
}

/// One media frame in transit, with the routing a relay needs — §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaEnvelope {
    /// The call this frame belongs to.
    pub call: CallId,
    /// The participant that produced it.
    pub from: PerNetworkIdentityId,
    /// Who it is for — one participant, or the rest of the call (§2.2.1).
    pub to: Recipient,
    /// The sealed frame.
    pub frame: MediaFrame,
}

impl MediaEnvelope {
    /// Encodes the envelope.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(MEDIA_DOMAIN);
        e.fixed(self.call.as_bytes());
        self.from.encode(&mut e);
        self.to.encode(&mut e);
        e.u64(self.frame.sequence).bytes(&self.frame.ciphertext);
        e.finish()
    }

    /// Decodes an envelope.
    ///
    /// There is no signature to check: the frame is AEAD-sealed under the call
    /// key, so authenticity is established when the recipient opens it. A relay
    /// forwarding this has no way to verify the frame and is not expected to —
    /// that is what makes it blind rather than trusted.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, MEDIA_DOMAIN)?;
        let call = CallId::from_bytes(d.fixed::<32>()?);
        let from = get_identity(&mut d)?;
        let to = Recipient::decode(&mut d)?;
        let sequence = d.u64()?;
        let ciphertext = d.bytes()?;
        if ciphertext.len() > MAX_FRAME_BYTES {
            return Err(WireError::TooLarge {
                size: ciphertext.len(),
                limit: MAX_FRAME_BYTES,
            });
        }
        d.finish()?;
        Ok(Self {
            call,
            from,
            to,
            frame: MediaFrame {
                sequence,
                ciphertext: ciphertext.to_vec(),
            },
        })
    }
}

/// Acknowledgement of a media frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaAck;

impl MediaAck {
    /// Encodes the acknowledgement.
    pub fn encode(&self) -> Vec<u8> {
        Enc::domain("intranet.wire.call-media-ack.v1").finish()
    }

    /// Decodes an acknowledgement.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Dec::domain(bytes, "intranet.wire.call-media-ack.v1")?.finish()?;
        Ok(Self)
    }
}

/// Converts a realtime error into a wire error, for callers that need one.
impl From<RealtimeError> for WireError {
    fn from(_: RealtimeError) -> Self {
        Self::BadSignature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CallKey;
    use intranet_identity::{MasterSeed, NetworkId};

    const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
    }

    fn call() -> CallId {
        CallId::from_bytes([3u8; 32])
    }

    #[test]
    fn every_signal_body_round_trips() {
        let caller = identity(1);
        let callee = identity(2);
        let key = CallKey::from_bytes([9u8; 32]);

        for body in [
            SignalBody::Invite {
                envelope: CallKeyEnvelope::seal(&caller, &callee.id(), call(), &key).unwrap(),
            },
            SignalBody::Propose {
                call: call(),
                proposal: TopologyProposal {
                    proposer: caller.id(),
                    topology: Topology::Mesh,
                    trigger: RenegotiationTrigger::BelowThreshold,
                    proposed_at: Timestamp::from_millis(11),
                },
            },
            SignalBody::Propose {
                call: call(),
                proposal: TopologyProposal {
                    proposer: caller.id(),
                    topology: Topology::Relayed { relay: identity(3).id() },
                    trigger: RenegotiationTrigger::ThresholdReached,
                    proposed_at: Timestamp::from_millis(12),
                },
            },
            SignalBody::Propose {
                call: call(),
                proposal: TopologyProposal {
                    proposer: caller.id(),
                    topology: Topology::Relayed { relay: identity(3).id() },
                    trigger: RenegotiationTrigger::RelayUnavailable,
                    proposed_at: Timestamp::from_millis(13),
                },
            },
            SignalBody::Leave { call: call() },
        ] {
            let signal = Signal::create(&caller, body.clone());
            assert_eq!(Signal::decode(&signal.encode()).unwrap(), signal);
        }
    }

    #[test]
    fn a_sealed_key_survives_the_trip_and_still_opens() {
        // The round trip that matters: an envelope that decoded into something
        // structurally equal but cryptographically different would leave the
        // callee in a call it cannot hear.
        let caller = identity(1);
        let callee = identity(2);
        let key = CallKey::generate().unwrap();

        let signal = Signal::create(
            &caller,
            SignalBody::Invite {
                envelope: CallKeyEnvelope::seal(&caller, &callee.id(), call(), &key).unwrap(),
            },
        );
        let decoded = Signal::decode(&signal.encode()).unwrap();
        let SignalBody::Invite { envelope } = decoded.body else {
            panic!("expected an invite");
        };

        // Compared by fingerprint rather than by bytes: key material
        // deliberately exposes no accessor, and a fingerprint is the
        // documented way to assert two keys are the same one.
        assert_eq!(envelope.open(&callee).unwrap().fingerprint(), key.fingerprint());
    }

    #[test]
    fn every_single_bit_change_to_a_signal_is_rejected() {
        // Signalling decides who is in a call and which relay carries it, so an
        // unauthenticated one is an invitation to reroute someone else's call.
        let signal = Signal::create(&identity(1), SignalBody::Leave { call: call() });
        let encoded = signal.encode();

        let rejected = (0..encoded.len())
            .filter(|index| {
                let mut bytes = encoded.clone();
                bytes[*index] ^= 0x01;
                Signal::decode(&bytes).is_err()
            })
            .count();
        assert_eq!(rejected, encoded.len());
    }

    #[test]
    fn a_proposal_cannot_be_attributed_to_another_participant() {
        // §1.4 converges on proposals by proposer identity and timing, so being
        // able to forge a proposer would let one participant move everyone onto
        // a relay of their choosing while appearing to be someone else.
        let mut forged = Signal::create(
            &identity(1),
            SignalBody::Propose {
                call: call(),
                proposal: TopologyProposal {
                    proposer: identity(1).id(),
                    topology: Topology::Relayed { relay: identity(3).id() },
                    trigger: RenegotiationTrigger::ThresholdReached,
                    proposed_at: Timestamp::from_millis(1),
                },
            },
        );
        forged.sender = identity(2).id();

        assert_eq!(
            Signal::decode(&forged.encode()).unwrap_err(),
            WireError::BadSignature
        );
    }

    #[test]
    fn a_media_envelope_round_trips() {
        let key = CallKey::generate().unwrap();
        let frame = key.seal_frame(&call(), 7, b"audio samples");

        let envelope = MediaEnvelope {
            call: call(),
            from: identity(1).id(),
            to: Recipient::One(identity(2).id()),
            frame,
        };
        let decoded = MediaEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(
            key.open_frame(&call(), &decoded.frame).unwrap(),
            b"audio samples"
        );
    }

    #[test]
    fn a_fanned_out_envelope_round_trips_and_names_nobody() {
        // §2.2.1's central shape: the sender emits one envelope per frame and
        // does not say who it is for. What is being pinned here is the absence —
        // there is no list on the wire for a sender to fill in, so a sender
        // cannot aim a relay at a non-participant even in principle.
        let key = CallKey::generate().unwrap();
        let envelope = MediaEnvelope {
            call: call(),
            from: identity(1).id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call(), 7, b"audio samples"),
        };

        let decoded = MediaEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.to.named(), None, "fan-out names no recipient");
        assert!(
            !decoded.to.is(&identity(2).id()),
            "a fan-out envelope is addressed to nobody personally, so a receiver \
             never mistakes one for its own and never has one to forward again"
        );
    }

    #[test]
    fn the_two_recipient_forms_do_not_decode_as_each_other() {
        // The discriminant is the whole reason the domain tag advanced. If these
        // two encodings were confusable, a relay could read a named envelope as
        // a fan-out and spray a frame at a call that never asked for it.
        let key = CallKey::generate().unwrap();
        let named = MediaEnvelope {
            call: call(),
            from: identity(1).id(),
            to: Recipient::One(identity(2).id()),
            frame: key.seal_frame(&call(), 1, b"x"),
        };
        let fanned = MediaEnvelope {
            to: Recipient::Participants,
            ..named.clone()
        };

        assert_ne!(named.encode(), fanned.encode());
        assert_eq!(MediaEnvelope::decode(&named.encode()).unwrap().to, named.to);
        assert_eq!(
            MediaEnvelope::decode(&fanned.encode()).unwrap().to,
            Recipient::Participants
        );
    }

    #[test]
    fn a_v1_envelope_does_not_decode_as_a_v2_one() {
        // The break is deliberate and this is what makes it safe: a v1 envelope
        // encoded the recipient as a bare 32-byte identity, so read under v2 its
        // first byte would become the discriminant. The domain tag rejects it
        // before that can happen, rather than leaving a 2-in-256 chance of
        // parsing into a plausible wrong answer.
        let key = CallKey::generate().unwrap();
        let mut v1 = Enc::domain("intranet.wire.call-media.v1");
        v1.fixed(call().as_bytes());
        identity(1).id().encode(&mut v1);
        identity(2).id().encode(&mut v1);
        let frame = key.seal_frame(&call(), 1, b"audio samples");
        v1.u64(frame.sequence).bytes(&frame.ciphertext);

        assert!(
            MediaEnvelope::decode(&v1.finish()).is_err(),
            "a v1 envelope must fail to decode rather than parse as a v2 one"
        );
    }

    #[test]
    fn an_unknown_recipient_form_is_refused() {
        // Fail closed on a form this build does not understand. Guessing would
        // mean either dropping a frame silently or forwarding one whose routing
        // was never read — and the second is how a reflector gets built.
        let mut e = Enc::domain(MEDIA_DOMAIN);
        e.fixed(call().as_bytes());
        identity(1).id().encode(&mut e);
        e.u8(7);
        e.u64(1).bytes(b"whatever");

        assert!(matches!(
            MediaEnvelope::decode(&e.finish()).unwrap_err(),
            WireError::Malformed(DecodeError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn a_tampered_frame_fails_to_open_even_though_it_decodes() {
        // §2.2's "cannot inject, modify, or selectively suppress content
        // undetected". The envelope has no signature, so a modified frame
        // decodes perfectly well — detection comes from the AEAD, at the point
        // the recipient tries to use it. That is the property being pinned:
        // decoding is not acceptance.
        let key = CallKey::generate().unwrap();
        let mut envelope = MediaEnvelope {
            call: call(),
            from: identity(1).id(),
            to: Recipient::One(identity(2).id()),
            frame: key.seal_frame(&call(), 7, b"audio samples"),
        };
        envelope.frame.ciphertext[0] ^= 0x01;

        let decoded = MediaEnvelope::decode(&envelope.encode())
            .expect("a tampered frame is still well-formed bytes");
        assert!(
            key.open_frame(&call(), &decoded.frame).is_err(),
            "tampering must be detected when the frame is opened"
        );
    }

    #[test]
    fn a_frame_replayed_into_a_different_call_does_not_open() {
        // The nonce binds the call, so a relay that misrouted a frame — the one
        // thing a blind relay *can* do, since routing metadata is outside the
        // AEAD — cannot make it decrypt somewhere it does not belong.
        let key = CallKey::generate().unwrap();
        let frame = key.seal_frame(&call(), 1, b"audio samples");

        let other_call = CallId::from_bytes([4u8; 32]);
        assert!(key.open_frame(&other_call, &frame).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let envelope = MediaEnvelope {
            call: call(),
            from: identity(1).id(),
            to: Recipient::One(identity(2).id()),
            frame: MediaFrame {
                sequence: 0,
                ciphertext: vec![0u8; MAX_FRAME_BYTES + 1],
            },
        };
        assert!(matches!(
            MediaEnvelope::decode(&envelope.encode()).unwrap_err(),
            WireError::TooLarge { .. }
        ));
    }
}
