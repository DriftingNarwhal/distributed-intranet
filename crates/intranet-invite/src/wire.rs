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
///
/// `v2` because the addresses are now framed with their shared ending factored
/// out (`put_addresses`), and `wire.` because this names the *framing*: the
/// identically-spelled tag it used to carry belongs to the signing payload in
/// [`crate::Invite`], and two different things answering to one tag is exactly
/// what domain separation exists to prevent. An older invite now fails to
/// decode with a domain mismatch, which says what happened, rather than as
/// malformed bytes, which does not.
const INVITE_DOMAIN: &str = "intranet.wire.invite.v2";

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
    put_addresses(e, &invite.bootstrap_addresses);
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
    let bootstrap_addresses = get_addresses(d)?;
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

/// Writes the bootstrap addresses, with the ending they share written once.
///
/// # Why an encoding bothers about size at all
///
/// Because §5.6 makes this credential *out of band*: pasted into a message, put
/// behind a link, read off a screen. An invite too long to paste has failed the
/// job the section gives it, and every framing byte here is multiplied by 8/5
/// on its way through base32 into a URI.
///
/// The addresses in one invite all name the same node, so they all end in the
/// same `/p2p/<peer id>` — fifty-odd characters repeated once per address, and
/// on a real machine more than half of everything this field carried. This
/// encoder does not know that, and deliberately does not: it takes the longest
/// string every address ends with and writes it once. That is a fact about
/// these strings rather than about multiaddrs, which is what keeps this crate
/// free of any notion of what an address *means* (see `Invite`).
///
/// Two shapes were measured against this one. A shared table of `/`-separated
/// components dedupes more in principle and comes out **larger** in practice,
/// because `Enc` frames every length with a fixed eight-byte `u64`: the table's
/// prefixes and the per-address index lists cost more than the repetition they
/// remove. Compressing the whole encoding would need a dependency, a bound
/// against a decompression bomb, and a size that varies with the data. This
/// costs one string and one subtraction, and it is bounded by construction —
/// nothing here can decode to more than what was encoded.
///
/// Not what is signed. [`Invite`]'s signature covers its own payload, in which
/// the addresses appear whole, so this changes the URI and nothing about what a
/// receiving node verifies.
fn put_addresses(e: &mut Enc, addresses: &[String]) {
    let suffix = common_suffix(addresses);
    e.str(suffix);
    e.seq(addresses.iter(), |e, address| {
        e.str(&address[..address.len() - suffix.len()]);
    });
}

/// Reads the bootstrap addresses back, re-joining each to the shared ending.
///
/// The bounds are checked against the address as *reconstructed*, because that
/// is the string the rest of the system will hold — a limit applied to the
/// encoded halves would let a long shared ending past a check it was meant to
/// fail.
fn get_addresses(d: &mut Dec<'_>) -> Result<Vec<String>, WireError> {
    let suffix = d.str()?;
    let addresses = d.seq::<_, WireError>(|d| {
        let head = d.str()?;
        let length = head.len() + suffix.len();
        if length > MAX_ADDRESS_BYTES {
            return Err(WireError::TooLarge {
                what: "bootstrap address",
                got: length,
                limit: MAX_ADDRESS_BYTES,
            });
        }
        Ok(format!("{head}{suffix}"))
    })?;
    if addresses.len() > MAX_BOOTSTRAP_ADDRESSES {
        return Err(WireError::TooLarge {
            what: "bootstrap addresses",
            got: addresses.len(),
            limit: MAX_BOOTSTRAP_ADDRESSES,
        });
    }
    Ok(addresses)
}

/// The longest string every one of these ends with.
///
/// Measured in bytes and then backed off to a boundary every address agrees on,
/// so that slicing here cannot split a character. Multiaddrs are ASCII and this
/// would not arise from one, but the field is `Vec<String>` and the invariant
/// belongs where the slicing happens rather than in an assumption about what
/// callers put in it.
fn common_suffix(addresses: &[String]) -> &str {
    let Some(first) = addresses.first() else {
        return "";
    };
    let mut length = addresses[1..].iter().fold(first.len(), |shortest, address| {
        let shared = first
            .bytes()
            .rev()
            .zip(address.bytes().rev())
            .take_while(|(a, b)| a == b)
            .count();
        shortest.min(shared)
    });
    while length > 0
        && !addresses
            .iter()
            .all(|address| address.is_char_boundary(address.len() - length))
    {
        length -= 1;
    }
    &first[first.len() - length..]
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

#[cfg(test)]
mod address_encoding_tests {
    use super::*;

    /// Round-trips a set of addresses through the invite encoding alone.
    fn round_trip(addresses: &[&str]) -> Vec<String> {
        let owned: Vec<String> = addresses.iter().map(|a| (*a).to_owned()).collect();
        let mut e = Enc::new();
        put_addresses(&mut e, &owned);
        let bytes = e.finish();
        let mut d = Dec::new(&bytes);
        let back = get_addresses(&mut d).expect("decodes");
        d.finish().expect("nothing left over");
        back
    }

    #[test]
    fn addresses_come_back_exactly_as_they_went_in() {
        // The ordinary case: one node's addresses, all ending in its peer id.
        let addresses = [
            "/ip6/2600:1700:a825:4800::3f/tcp/65343/p2p/12D3KooWMHZbUfFYuqe6Nx",
            "/ip4/192.168.1.200/udp/65343/quic-v1/p2p/12D3KooWMHZbUfFYuqe6Nx",
            "/dns4/relay.example/tcp/4001/p2p/12D3KooWAT1R2Jjc/p2p-circuit/p2p/12D3KooWMHZbUfFYuqe6Nx",
        ];
        assert_eq!(round_trip(&addresses), addresses);
    }

    #[test]
    fn addresses_sharing_no_ending_still_round_trip() {
        // Nothing in common, so the shared ending is empty and this degenerates
        // to what it replaced. The saving is the point; the correctness is not
        // allowed to depend on there being one.
        let addresses = ["/ip4/203.0.113.7/tcp/1", "/ip4/203.0.113.8/tcp/2"];
        assert_eq!(round_trip(&addresses), addresses);
    }

    #[test]
    fn one_address_round_trips_even_though_it_is_entirely_its_own_ending() {
        // The degenerate case: the shared ending is the whole string and the
        // remainder is empty, which the decoder must rejoin to the same address
        // rather than to nothing.
        assert_eq!(round_trip(&["/ip4/203.0.113.7/tcp/1"]), ["/ip4/203.0.113.7/tcp/1"]);
        assert!(round_trip(&[]).is_empty());
    }

    #[test]
    fn one_address_being_the_ending_of_another_does_not_lose_it() {
        // The shared ending is the whole of the shorter address, so its own
        // remainder is empty while the longer one's is not. An encoder that
        // treated an empty remainder as absent would drop an address here.
        let addresses = ["/tcp/1/p2p/abc", "/ip4/203.0.113.7/tcp/1/p2p/abc"];
        assert_eq!(round_trip(&addresses), addresses);
        assert_eq!(round_trip(&["", "x"]), ["", "x"]);
    }

    #[test]
    fn a_shared_ending_is_never_cut_through_a_character() {
        // The field is `Vec<String>`, so nothing stops a caller putting
        // multi-byte text in it. These two share the trailing bytes of `é`
        // without sharing the character, and slicing on the byte count would
        // panic rather than produce a wrong answer — which is why this is a
        // test and not a comment.
        let addresses = ["/dns4/café", "/dns4/caf\u{fa9}"];
        assert_eq!(round_trip(&addresses), addresses);
    }

    #[test]
    fn the_limit_is_checked_against_the_address_a_joiner_would_hold() {
        // A short remainder and a long shared ending: the halves are each well
        // inside the bound and the address they rejoin to is not. Checking the
        // encoded halves would let this through.
        let ending = "x".repeat(MAX_ADDRESS_BYTES);
        let mut e = Enc::new();
        put_addresses(&mut e, &[format!("/a{ending}"), format!("/b{ending}")]);
        let bytes = e.finish();

        let refusal = get_addresses(&mut Dec::new(&bytes)).expect_err("must be refused");
        assert!(
            matches!(refusal, WireError::TooLarge { what: "bootstrap address", .. }),
            "{refusal:?}"
        );
    }

    #[test]
    fn factoring_the_peer_id_out_roughly_halves_what_the_addresses_cost() {
        // The measurement that prompted this, on the nine addresses a real
        // machine's invite carries after `kols-node` selects them.
        const ME: &str = "12D3KooWMHZbUfFYuqe6NxXBFSg3aLzfTSa1B5QKGNKwMrWz5FaD";
        let addresses: Vec<String> = [
            "/ip6/2600:1700:a825:4800::3f/tcp/65343",
            "/ip6/2600:1700:a825:4800::3f/udp/65343/quic-v1",
            "/ip6/2600:1700:a825:4800:634c:8370:a381:9f64/tcp/65343",
            "/ip6/2600:1700:a825:4800:634c:8370:a381:9f64/udp/65343/quic-v1",
            "/ip6/2600:1700:a825:4800:d46f:a0b3:57f5:bbc7/tcp/65343",
            "/ip6/2600:1700:a825:4800:d46f:a0b3:57f5:bbc7/udp/65343/quic-v1",
            "/dns4/switchback.proxy.rlwy.net/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit",
            "/ip4/192.168.1.200/tcp/65343",
            "/ip4/192.168.1.200/udp/65343/quic-v1",
        ]
        .iter()
        .map(|a| format!("{a}/p2p/{ME}"))
        .collect();

        let mut factored = Enc::new();
        put_addresses(&mut factored, &addresses);
        let mut whole = Enc::new();
        whole.seq(addresses.iter(), |e, address| {
            e.str(address);
        });

        // 1,082 bytes to 634 when this was written. Not half, and the reason
        // is the floor under any scheme here: `Enc` spends a fixed eight-byte
        // `u64` framing every length, so nine addresses cost 72 bytes before a
        // single character of address is written. What is left after factoring
        // is mostly addresses.
        let (after, before) = (factored.finish().len(), whole.finish().len());
        assert!(
            after * 3 < before * 2,
            "expected the addresses to cost at least a third less; {before} -> {after}"
        );
    }
}
