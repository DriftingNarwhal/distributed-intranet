//! The join handshake over the wire — Core Protocol Spec §5.6–5.7, §2.4.
//!
//! # What this protocol is responsible for, and what it deliberately is not
//!
//! §5.7 states the principle directly: an invite's only job is establishing the
//! network's very first authenticated connection, and *everything else* a new
//! node needs is obtained afterwards through ordinary steady-state operations.
//! So this protocol carries an invite, gets an answer, and stops.
//!
//! It does **not** deliver the epoch key. Under auto-admit the joiner becomes a
//! member and then asks for a key over `/intranet/epoch-key/1.0.0` like any
//! other member would — the same code path a re-welcome uses, rather than a
//! join-time special case that would rot from being exercised once per node
//! lifetime. It does not carry the governance log either; that is ordinary sync.
//!
//! # The two admission modes are the whole point
//!
//! §2.4 makes admission a network-wide policy, and the difference is not
//! cosmetic:
//!
//! - **Auto-admit**: redemption places the joiner in `everyone` immediately,
//!   recorded as a `MembershipChange` carrying the invite's provenance.
//! - **Explicit intake**: redemption establishes connectivity and an identity
//!   and *nothing else* — no group, no capability, and specifically no epoch
//!   key, since holding the key is equivalent to being able to decrypt network
//!   content regardless of membership. The joiner waits until an admin acts.
//!
//! A response that conflated the two would be the single most consequential
//! thing this protocol could get wrong, which is why they are distinct variants
//! rather than a boolean on one.

use crate::{Invite, InviteSubject};
use intranet_crypto::{Dec, DecodeError, Enc, Hash, Signature, Timestamp};
use intranet_identity::{NetworkId, PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for the signature a joiner makes over its request.
const REQUEST_SIGNATURE_DOMAIN: &str = "intranet.join-request.v1";
/// Domain tag for a request on the wire.
const REQUEST_DOMAIN: &str = "intranet.wire.join-request.v1";
/// Domain tag for a response on the wire.
const RESPONSE_DOMAIN: &str = "intranet.wire.join-response.v1";
/// Domain tag for an invite carried on its own — §5.6.
const INVITE_DOMAIN: &str = "intranet.invite.v1";

/// The most bootstrap addresses an invite on the wire may carry.
///
/// **Flagged: §5.6 requires "one or more" and sets no ceiling.** One is needed
/// because the count is chosen by whoever built the invite. 32 is far more than
/// the handful of entry points §5.5 describes a maturing network handing out.
pub const MAX_BOOTSTRAP_ADDRESSES: usize = 32;

/// The longest bootstrap address string this build will accept.
///
/// **Flagged: the specs set no bound.** A multiaddr with a peer id and a circuit
/// hop is well under 256 bytes; this bounds a hostile invite without constraining
/// any real one.
pub const MAX_ADDRESS_BYTES: usize = 256;

/// Why a join message could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in message")]
    InvalidKey,
    /// The request decoded, but the joiner's signature did not verify.
    #[error("join request signature did not verify after decoding")]
    BadSignature,
    /// A field exceeded its ceiling.
    #[error("{what} is {got}, over the {limit} ceiling")]
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

/// A joiner presenting an invite — §5.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The identity asking to join.
    pub joiner: PerNetworkIdentityId,
    /// The invite being redeemed.
    pub invite: Invite,
    /// The joiner's signature over `(joiner, invite_id)`.
    ///
    /// Separate from the invite's own signature, and load-bearing for a bearer
    /// invite: the invite proves somebody with `approve-node` authorized *a*
    /// join, and this proves the identity now claiming it is the one asking.
    /// Without it a captured bearer invite could be redeemed on behalf of an
    /// identity that never asked for anything.
    pub signature: Signature,
}

impl JoinRequest {
    /// Builds and signs a request.
    pub fn create(joiner: &PerNetworkIdentity, invite: Invite) -> Self {
        let joiner_id = joiner.id();
        Self {
            signature: joiner.sign(&Self::payload(&joiner_id, &invite.invite_id())),
            joiner: joiner_id,
            invite,
        }
    }

    /// Verifies that the named joiner really made this request.
    pub fn verify(&self) -> Result<(), WireError> {
        self.joiner
            .verifying_key()
            .verify(
                &Self::payload(&self.joiner, &self.invite.invite_id()),
                &self.signature,
            )
            .map_err(|_| WireError::BadSignature)
    }

    fn payload(joiner: &PerNetworkIdentityId, invite_id: &Hash) -> Enc {
        let mut e = Enc::domain(REQUEST_SIGNATURE_DOMAIN);
        joiner.encode(&mut e);
        e.fixed(invite_id.as_bytes());
        e
    }

    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(REQUEST_DOMAIN);
        self.joiner.encode(&mut e);
        put_invite(&mut e, &self.invite);
        e.fixed(self.signature.as_bytes());
        e.finish()
    }

    /// Decodes a request and verifies the joiner's signature.
    ///
    /// The *invite's* own signature is deliberately not checked here. It is
    /// checked by [`Invite::validate`] against replayed governance state, which
    /// is where the question "does this issuer hold `approve-node` right now"
    /// can actually be answered — and a signature check that passed here while
    /// the real authorization check happened elsewhere would invite the reading
    /// that decoding had already validated the invite.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, REQUEST_DOMAIN)?;
        let request = Self {
            joiner: get_identity(&mut d)?,
            invite: get_invite(&mut d)?,
            signature: Signature::from_bytes(d.fixed::<64>()?),
        };
        d.finish()?;
        request.verify()?;
        Ok(request)
    }
}

/// Why a join was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRefusal {
    /// The invite did not validate — expired, exhausted, wrong network, wrong
    /// subject, or issued by someone who no longer holds `approve-node`.
    ///
    /// Deliberately one reason rather than several. A joiner can act on all of
    /// them identically (get a better invite), while distinguishing them would
    /// let anyone holding a rejected invite probe a network's governance state
    /// through the refusals.
    InviteInvalid,
    /// The responder could not evaluate the invite — no governance state yet.
    CannotEvaluate,
    /// The request arrived on a connection belonging to someone else.
    NotConnectionOwner,
    /// This invite has already produced its ceiling of pre-admission arrivals.
    ///
    /// §5.3's per-invite scoping: under a multi-use or bearer invite, a
    /// waiting-room identity is free to mint, so the invite is the scarce
    /// resource to meter against rather than the identity.
    InviteCeiling,
    /// The joiner is already a member, so there is nothing to redeem.
    AlreadyMember,
}

impl JoinRefusal {
    /// A short reason, for events and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InviteInvalid => "invite did not validate",
            Self::CannotEvaluate => "responder cannot evaluate governance state",
            Self::NotConnectionOwner => "request arrived on another identity's connection",
            Self::InviteCeiling => "invite has reached its pre-admission ceiling",
            Self::AlreadyMember => "already a member",
        }
    }
}

/// The outcome of presenting an invite — §2.4, §5.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinResponse {
    /// Auto-admit: the joiner is now in `everyone`.
    ///
    /// Carries the governance entry that granted it so the joiner can wait for
    /// that specific entry to reach it by ordinary sync, rather than trusting
    /// the responder's word that it happened.
    Admitted {
        /// The `MembershipChange` entry recording the admission.
        entry: Hash,
    },
    /// Explicit intake: recorded as waiting, holding nothing.
    ///
    /// No group, no capability, and no epoch key. A joiner receiving this has
    /// established connectivity and an identity, which is the entirety of what
    /// §2.4 promises it.
    Waiting,
    /// The join was refused.
    Refused {
        /// Why.
        reason: JoinRefusal,
    },
}

impl JoinResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(RESPONSE_DOMAIN);
        match self {
            Self::Admitted { entry } => {
                e.variant(0).fixed(entry.as_bytes());
            }
            Self::Waiting => {
                e.variant(1);
            }
            Self::Refused { reason } => {
                e.variant(2).u8(match reason {
                    JoinRefusal::InviteInvalid => 0,
                    JoinRefusal::CannotEvaluate => 1,
                    JoinRefusal::NotConnectionOwner => 2,
                    JoinRefusal::InviteCeiling => 3,
                    JoinRefusal::AlreadyMember => 4,
                });
            }
        }
        e.finish()
    }

    /// Decodes a response.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => Self::Admitted {
                entry: Hash::from_bytes(d.fixed::<32>()?),
            },
            1 => Self::Waiting,
            2 => Self::Refused {
                reason: match d.u8()? {
                    0 => JoinRefusal::InviteInvalid,
                    1 => JoinRefusal::CannotEvaluate,
                    2 => JoinRefusal::NotConnectionOwner,
                    3 => JoinRefusal::InviteCeiling,
                    4 => JoinRefusal::AlreadyMember,
                    got => {
                        return Err(WireError::UnknownVariant {
                            what: "JoinRefusal",
                            got,
                        });
                    }
                },
            },
            got => {
                return Err(WireError::UnknownVariant {
                    what: "JoinResponse",
                    got,
                });
            }
        };
        d.finish()?;
        Ok(response)
    }
}

/// Encodes an invite so it can be handed to somebody.
///
/// **An invite that cannot be serialized is not an invite.** §5.6 defines it as
/// a credential carried to a prospective member out of band — pasted into a
/// message, put behind a link — and until this existed the only way its bytes
/// appeared was already inside a [`JoinRequest`], which is the *other* end of
/// the journey. Issuing one and having no way to give it to anybody was a gap
/// nobody hit because nothing had tried to invite a person yet.
///
/// Its own domain tag rather than the request's, so an invite cannot be decoded
/// as a join request or the reverse.
pub fn encode_invite(invite: &Invite) -> Vec<u8> {
    let mut e = Enc::domain(INVITE_DOMAIN);
    put_invite(&mut e, invite);
    e.finish()
}

/// Decodes an invite handed over out of band.
///
/// Verifies nothing beyond the framing. An invite is a *claim* until
/// [`Invite::validate`] checks it against replayed governance state, and a
/// decoder that verified the signature here would invite the reading that
/// decoding had already established something.
pub fn decode_invite(bytes: &[u8]) -> Result<Invite, WireError> {
    let mut d = Dec::domain(bytes, INVITE_DOMAIN)?;
    let invite = get_invite(&mut d)?;
    d.finish()?;
    Ok(invite)
}

fn put_invite(e: &mut Enc, invite: &Invite) {
    invite.network.encode(e);
    e.seq(invite.bootstrap_addresses.iter(), |e, address| {
        e.str(address);
    });
    invite.issuer.encode(e);
    match invite.subject {
        InviteSubject::Bearer => {
            e.variant(0);
        }
        InviteSubject::Identity(identity) => {
            e.variant(1);
            identity.encode(e);
        }
    }
    e.i64(invite.issued_at.as_millis())
        .i64(invite.expires_at.as_millis())
        .u32(invite.max_uses)
        .fixed(invite.signature.as_bytes());
}

fn get_invite(d: &mut Dec<'_>) -> Result<Invite, WireError> {
    let network = NetworkId::from_bytes(d.fixed::<32>()?);
    let bootstrap_addresses = d.seq::<_, WireError>(|d| {
        let address = d.str()?;
        if address.len() > MAX_ADDRESS_BYTES {
            return Err(WireError::TooLarge {
                what: "bootstrap address",
                got: address.len(),
                limit: MAX_ADDRESS_BYTES,
            });
        }
        Ok(address.to_owned())
    })?;
    if bootstrap_addresses.len() > MAX_BOOTSTRAP_ADDRESSES {
        return Err(WireError::TooLarge {
            what: "bootstrap addresses",
            got: bootstrap_addresses.len(),
            limit: MAX_BOOTSTRAP_ADDRESSES,
        });
    }
    let issuer = get_identity(d)?;
    let subject = match d.variant()? {
        0 => InviteSubject::Bearer,
        1 => InviteSubject::Identity(get_identity(d)?),
        got => {
            return Err(WireError::UnknownVariant {
                what: "InviteSubject",
                got,
            });
        }
    };
    Ok(Invite {
        network,
        bootstrap_addresses,
        issuer,
        subject,
        issued_at: Timestamp::from_millis(d.i64()?),
        expires_at: Timestamp::from_millis(d.i64()?),
        max_uses: d.u32()?,
        signature: Signature::from_bytes(d.fixed::<64>()?),
    })
}

fn get_identity(d: &mut Dec<'_>) -> Result<PerNetworkIdentityId, WireError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| WireError::InvalidKey)?;
    Ok(PerNetworkIdentityId::from_verifying_key(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::MasterSeed;

    const NETWORK: NetworkId = NetworkId::from_bytes([9u8; 32]);

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
    }

    fn invite(issuer: &PerNetworkIdentity, subject: InviteSubject) -> Invite {
        Invite::issue(
            issuer,
            vec!["/ip4/127.0.0.1/tcp/4001".to_owned()],
            subject,
            Timestamp::from_millis(0),
            Timestamp::from_millis(10_000),
            4,
        )
    }

    #[test]
    fn a_request_round_trips_with_its_invite_intact() {
        let issuer = identity(1);
        let joiner = identity(2);
        let request = JoinRequest::create(&joiner, invite(&issuer, InviteSubject::Bearer));
        let decoded = JoinRequest::decode(&request.encode()).unwrap();

        assert_eq!(decoded, request);
        // The invite must survive the trip byte-exactly, or its own signature
        // stops verifying at the point it actually matters.
        assert!(decoded.invite.verify_signature().is_ok());
        assert_eq!(decoded.invite.invite_id(), request.invite.invite_id());
    }

    #[test]
    fn a_targeted_invite_round_trips_too() {
        let issuer = identity(1);
        let joiner = identity(2);
        let request = JoinRequest::create(
            &joiner,
            invite(&issuer, InviteSubject::Identity(joiner.id())),
        );
        let decoded = JoinRequest::decode(&request.encode()).unwrap();
        assert_eq!(decoded.invite.subject, InviteSubject::Identity(joiner.id()));
        assert!(decoded.invite.verify_signature().is_ok());
    }

    #[test]
    fn a_bearer_invite_cannot_be_redeemed_for_an_identity_that_did_not_ask() {
        // The reason the joiner signs at all. A bearer invite is redeemable by
        // whoever holds it, so without this an intercepted invite could be
        // presented in a victim's name.
        let issuer = identity(1);
        let joiner = identity(2);
        let victim = identity(3);

        let mut request = JoinRequest::create(&joiner, invite(&issuer, InviteSubject::Bearer));
        request.joiner = victim.id();

        assert_eq!(request.verify(), Err(WireError::BadSignature));
        assert_eq!(
            JoinRequest::decode(&request.encode()),
            Err(WireError::BadSignature)
        );
    }

    #[test]
    fn swapping_the_invite_fails_the_joiners_signature() {
        // The joiner signs the invite id, so a request cannot be re-pointed at a
        // different invite in flight.
        let issuer = identity(1);
        let joiner = identity(2);
        let mut request = JoinRequest::create(&joiner, invite(&issuer, InviteSubject::Bearer));
        request.invite = Invite::issue(
            &issuer,
            vec!["/ip4/127.0.0.1/tcp/9999".to_owned()],
            InviteSubject::Bearer,
            Timestamp::from_millis(0),
            Timestamp::from_millis(10_000),
            4,
        );
        assert_eq!(request.verify(), Err(WireError::BadSignature));
    }

    #[test]
    fn responses_round_trip() {
        let admitted = JoinResponse::Admitted {
            entry: Hash::from_bytes([4u8; 32]),
        };
        assert_eq!(JoinResponse::decode(&admitted.encode()).unwrap(), admitted);
        assert_eq!(
            JoinResponse::decode(&JoinResponse::Waiting.encode()).unwrap(),
            JoinResponse::Waiting
        );

        for reason in [
            JoinRefusal::InviteInvalid,
            JoinRefusal::CannotEvaluate,
            JoinRefusal::NotConnectionOwner,
            JoinRefusal::InviteCeiling,
            JoinRefusal::AlreadyMember,
        ] {
            let refused = JoinResponse::Refused { reason };
            assert_eq!(JoinResponse::decode(&refused.encode()).unwrap(), refused);
        }
    }

    #[test]
    fn an_invite_with_too_many_addresses_is_refused() {
        let issuer = identity(1);
        let joiner = identity(2);
        let mut oversized = invite(&issuer, InviteSubject::Bearer);
        oversized.bootstrap_addresses =
            (0..MAX_BOOTSTRAP_ADDRESSES + 1).map(|n| format!("/ip4/127.0.0.1/tcp/{n}")).collect();
        let request = JoinRequest::create(&joiner, oversized);

        assert!(matches!(
            JoinRequest::decode(&request.encode()),
            Err(WireError::TooLarge { .. })
        ));
    }
}
