//! Wire encoding for capability advertisements and their gossip — §4.2, §4.5.
//!
//! # Why this is a different protocol shape from the governance log
//!
//! The governance log is a hash-chained tree: entries are immutable, ancestry
//! matters, and a sync is "give me the entries under this tip". The capability
//! ledger is none of those things. It is a *set*, keyed by node, where each node
//! has exactly one current advertisement that is replaced wholesale when it
//! re-announces and expires if it does not (§4.5's refresh-or-expire pattern).
//!
//! So the digest exchanged here is `(node, issued_at)` rather than a set of
//! branch tips. That pair is what lets a requester distinguish the three cases
//! it cares about: an advertisement it has never seen, one it holds a *staler*
//! copy of, and one it is already current on. A heads-style digest carrying only
//! identity would collapse the middle case into the last, and refreshes would
//! never propagate — the ledger would populate once and then silently freeze.
//!
//! # Nothing here trusts the decoder
//!
//! As with the governance codec, a decoded advertisement is re-verified against
//! the advertising node's signature before a caller sees it, so a codec that
//! disagreed with the canonical encoding produces a rejected message rather than
//! a ledger quietly holding values nobody advertised. That matters more here
//! than it might look: `storage_offered` and `bandwidth_cap` are the weights
//! that drive HRW placement, so a corrupted field silently redirects where
//! content lands.

use crate::{BandwidthCap, CapabilityAdvertisement, ComputeClass, TimeOfDayWindow};
use intranet_crypto::{Dec, DecodeError, Enc, Signature, Timestamp};
use intranet_identity::{NetworkId, PerNetworkIdentityId};

/// Domain tag for an advertisement on the wire.
const ADVERTISEMENT_WIRE_DOMAIN: &str = "intranet.wire.advertisement.v1";
/// Domain tag for a ledger request.
const REQUEST_DOMAIN: &str = "intranet.wire.ledger-request.v1";
/// Domain tag for a ledger response.
const RESPONSE_DOMAIN: &str = "intranet.wire.ledger-response.v1";

/// The most advertisements one response will carry.
///
/// **Flagged: §4.5 sets no bound, calling propagation tuning rather than
/// architecture.** A bound is needed regardless, since a response is built from
/// a peer's request. 256 is far above any plausible network's active node count
/// per exchange while keeping a hostile peer's maximum allocation bounded, and
/// the protocol is pull-based so a requester simply asks again.
pub const MAX_ADVERTISEMENTS_PER_RESPONSE: usize = 256;

/// Why a ledger message could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in message")]
    InvalidKey,
    /// The advertisement decoded, but its signature did not verify.
    #[error("advertisement signature did not verify after decoding")]
    BadSignature,
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

// ---------------------------------------------------------------------------
// Advertisements
// ---------------------------------------------------------------------------

/// Encodes an advertisement for transmission.
///
/// Field order mirrors `CapabilityAdvertisement::payload` so the two can be read
/// side by side. `reliability_signal` is absent here for the same reason it is
/// absent from the struct: it is local-only observation state that is never
/// advertised or gossiped (§4.6), and putting it on a wire at all would be the
/// first step toward the network-wide reputation score that design deliberately
/// refuses.
pub fn encode_advertisement(advertisement: &CapabilityAdvertisement) -> Vec<u8> {
    let mut e = Enc::domain(ADVERTISEMENT_WIRE_DOMAIN);
    put_advertisement(&mut e, advertisement);
    e.finish()
}

/// Decodes an advertisement and verifies its signature.
pub fn decode_advertisement(bytes: &[u8]) -> Result<CapabilityAdvertisement, WireError> {
    let mut d = Dec::domain(bytes, ADVERTISEMENT_WIRE_DOMAIN)?;
    let advertisement = get_advertisement(&mut d)?;
    d.finish()?;
    advertisement
        .verify()
        .map_err(|_| WireError::BadSignature)?;
    Ok(advertisement)
}

fn put_advertisement(e: &mut Enc, advertisement: &CapabilityAdvertisement) {
    advertisement.network.encode(e);
    advertisement.node.encode(e);
    e.u64(advertisement.storage_offered)
        .u64(advertisement.bandwidth_cap.up_bytes_per_sec)
        .u64(advertisement.bandwidth_cap.down_bytes_per_sec);
    e.option(
        advertisement.bandwidth_cap.active_window.as_ref(),
        |e, window| {
            e.u32(u32::from(window.start_minute))
                .u32(u32::from(window.end_minute));
        },
    );
    e.bool(advertisement.relay_bootstrap_willing)
        .bool(advertisement.relay_media_willing)
        .u8(match advertisement.compute_class {
            ComputeClass::Minimal => 0,
            ComputeClass::Modest => 1,
            ComputeClass::Substantial => 2,
        })
        .i64(advertisement.issued_at.as_millis())
        .fixed(advertisement.signature.as_bytes());
}

fn get_advertisement(d: &mut Dec<'_>) -> Result<CapabilityAdvertisement, WireError> {
    let network = NetworkId::from_bytes(d.fixed::<32>()?);
    let node = get_identity(d)?;
    let storage_offered = d.u64()?;
    let up_bytes_per_sec = d.u64()?;
    let down_bytes_per_sec = d.u64()?;
    let active_window = d.option::<_, WireError>(|d| {
        // Minutes past midnight, so anything at or beyond 1440 is not a time of
        // day. Refused rather than clamped: a clamped window silently changes
        // when a node contributes, which is a change to what it agreed to.
        let start_minute = minute(d.u32()?)?;
        let end_minute = minute(d.u32()?)?;
        Ok(TimeOfDayWindow {
            start_minute,
            end_minute,
        })
    })?;
    let relay_bootstrap_willing = d.bool()?;
    let relay_media_willing = d.bool()?;
    let compute_class = match d.u8()? {
        0 => ComputeClass::Minimal,
        1 => ComputeClass::Modest,
        2 => ComputeClass::Substantial,
        other => return Err(unknown("ComputeClass", other)),
    };
    let issued_at = Timestamp::from_millis(d.i64()?);
    let signature = Signature::from_bytes(d.fixed::<64>()?);

    Ok(CapabilityAdvertisement {
        network,
        node,
        storage_offered,
        bandwidth_cap: BandwidthCap {
            up_bytes_per_sec,
            down_bytes_per_sec,
            active_window,
        },
        relay_bootstrap_willing,
        relay_media_willing,
        compute_class,
        issued_at,
        signature,
    })
}

fn minute(value: u32) -> Result<u16, WireError> {
    if value >= 1440 {
        return Err(WireError::Malformed(DecodeError::ImplausibleLength {
            claimed: u64::from(value),
            remaining: 1440,
        }));
    }
    Ok(value as u16)
}

// ---------------------------------------------------------------------------
// Gossip protocol
// ---------------------------------------------------------------------------

/// A request in the pull-based ledger gossip protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerRequest {
    /// Ask what the peer holds, and how fresh.
    Digest,
    /// Ask for specific nodes' advertisements.
    Fetch {
        /// The nodes whose advertisements are wanted.
        nodes: Vec<PerNetworkIdentityId>,
    },
}

/// A response in the pull-based ledger gossip protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerResponse {
    /// What the responder holds, as `(node, issued_at)` pairs.
    ///
    /// The timestamp is what makes refreshes propagate: without it a requester
    /// could tell only whether it had *heard of* a node, never whether its copy
    /// was current.
    Digest {
        /// One pair per advertisement held.
        entries: Vec<(PerNetworkIdentityId, Timestamp)>,
    },
    /// The requested advertisements.
    Advertisements {
        /// The advertisements, each already signature-verified on decode.
        advertisements: Vec<CapabilityAdvertisement>,
        /// Whether the response hit [`MAX_ADVERTISEMENTS_PER_RESPONSE`].
        truncated: bool,
    },
}

impl LedgerRequest {
    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(REQUEST_DOMAIN);
        match self {
            Self::Digest => {
                e.variant(0);
            }
            Self::Fetch { nodes } => {
                e.variant(1);
                e.seq(nodes.iter(), |e, node| node.encode(e));
            }
        }
        e.finish()
    }

    /// Decodes a request.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, REQUEST_DOMAIN)?;
        let request = match d.variant()? {
            0 => Self::Digest,
            1 => Self::Fetch {
                nodes: d.seq::<_, WireError>(get_identity)?,
            },
            other => return Err(unknown("LedgerRequest", other)),
        };
        d.finish()?;
        Ok(request)
    }
}

impl LedgerResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(RESPONSE_DOMAIN);
        match self {
            Self::Digest { entries } => {
                e.variant(0);
                e.seq(entries.iter(), |e, (node, issued_at)| {
                    node.encode(e);
                    e.i64(issued_at.as_millis());
                });
            }
            Self::Advertisements {
                advertisements,
                truncated,
            } => {
                e.variant(1);
                e.seq(advertisements.iter(), |e, advertisement| {
                    // Length-prefixed so one malformed advertisement is a
                    // bounded failure rather than desynchronizing the response.
                    e.bytes(&encode_advertisement(advertisement));
                });
                e.bool(*truncated);
            }
        }
        e.finish()
    }

    /// Decodes a response, verifying every advertisement's signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => Self::Digest {
                entries: d.seq::<_, WireError>(|d| {
                    let node = get_identity(d)?;
                    Ok((node, Timestamp::from_millis(d.i64()?)))
                })?,
            },
            1 => Self::Advertisements {
                advertisements: d
                    .seq::<_, WireError>(|d| Ok(d.bytes()?.to_vec()))?
                    .iter()
                    .map(|bytes| decode_advertisement(bytes))
                    .collect::<Result<Vec<_>, _>>()?,
                truncated: d.bool()?,
            },
            other => return Err(unknown("LedgerResponse", other)),
        };
        d.finish()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::{MasterSeed, PerNetworkIdentity};

    const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
    }

    fn advertisement(n: u8, window: Option<TimeOfDayWindow>) -> CapabilityAdvertisement {
        CapabilityAdvertisement::create(
            &identity(n),
            1 << 30,
            BandwidthCap {
                up_bytes_per_sec: 1_000_000,
                down_bytes_per_sec: 8_000_000,
                active_window: window,
            },
            true,
            false,
            ComputeClass::Modest,
            Timestamp::from_millis(1_000),
        )
    }

    #[test]
    fn advertisements_round_trip_across_every_shape() {
        for (n, window, class) in [
            (1u8, None, ComputeClass::Minimal),
            (
                2,
                Some(TimeOfDayWindow {
                    start_minute: 0,
                    end_minute: 1439,
                }),
                ComputeClass::Modest,
            ),
            (
                3,
                // Wrapping past midnight — the "contribute while asleep" case,
                // and the one an off-by-one in the codec would silently invert.
                Some(TimeOfDayWindow {
                    start_minute: 1380,
                    end_minute: 360,
                }),
                ComputeClass::Substantial,
            ),
        ] {
            let mut original = advertisement(n, window);
            original = CapabilityAdvertisement::create(
                &identity(n),
                original.storage_offered,
                original.bandwidth_cap,
                original.relay_bootstrap_willing,
                original.relay_media_willing,
                class,
                original.issued_at,
            );
            let decoded = decode_advertisement(&encode_advertisement(&original)).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn an_advertisement_offering_nothing_round_trips() {
        // The default posture, and a first-class state rather than a degenerate
        // one — contribution is opt-in (§4.2), so "I offer nothing" has to
        // survive the trip as faithfully as a generous offer.
        let original = CapabilityAdvertisement::none(&identity(4), Timestamp::from_millis(7));
        let decoded = decode_advertisement(&encode_advertisement(&original)).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.storage_offered, 0);
    }

    #[test]
    fn every_single_bit_change_is_rejected() {
        // `storage_offered` and `bandwidth_cap` are the weights HRW placement
        // ranks on, so a field altered in flight silently redirects where
        // content lands. Signature verification on decode is what makes that
        // impossible rather than merely unlikely.
        let original = advertisement(1, None);
        let encoded = encode_advertisement(&original);

        let rejected = (0..encoded.len())
            .filter(|index| {
                let mut bytes = encoded.clone();
                bytes[*index] ^= 0x01;
                decode_advertisement(&bytes).is_err()
            })
            .count();
        assert_eq!(
            rejected,
            encoded.len(),
            "every single-bit change to a signed advertisement must be rejected"
        );
    }

    #[test]
    fn a_minute_outside_a_day_is_refused_rather_than_clamped() {
        // Clamping would silently change the hours a node agreed to contribute,
        // which is a different promise from the one it signed.
        let original = advertisement(
            1,
            Some(TimeOfDayWindow {
                start_minute: 60,
                end_minute: 120,
            }),
        );
        let mut encoded = encode_advertisement(&original);
        let offset = encoded
            .windows(4)
            .position(|w| w == 60u32.to_be_bytes())
            .expect("the start minute should appear in the encoding");
        encoded[offset..offset + 4].copy_from_slice(&5_000u32.to_be_bytes());

        assert!(matches!(
            decode_advertisement(&encoded).unwrap_err(),
            WireError::Malformed(DecodeError::ImplausibleLength { .. })
        ));
    }

    #[test]
    fn requests_and_responses_round_trip() {
        for request in [
            LedgerRequest::Digest,
            LedgerRequest::Fetch { nodes: vec![] },
            LedgerRequest::Fetch {
                nodes: vec![identity(1).id(), identity(2).id()],
            },
        ] {
            assert_eq!(LedgerRequest::decode(&request.encode()).unwrap(), request);
        }

        for response in [
            LedgerResponse::Digest { entries: vec![] },
            LedgerResponse::Digest {
                entries: vec![
                    (identity(1).id(), Timestamp::from_millis(5)),
                    (identity(2).id(), Timestamp::from_millis(9)),
                ],
            },
            LedgerResponse::Advertisements {
                advertisements: vec![advertisement(1, None), advertisement(2, None)],
                truncated: true,
            },
        ] {
            assert_eq!(LedgerResponse::decode(&response.encode()).unwrap(), response);
        }
    }

    #[test]
    fn a_response_carrying_a_forged_advertisement_is_refused_whole() {
        let mut forged = advertisement(1, None);
        forged.storage_offered = u64::MAX;

        let response = LedgerResponse::Advertisements {
            advertisements: vec![advertisement(2, None), forged],
            truncated: false,
        };
        assert_eq!(
            LedgerResponse::decode(&response.encode()).unwrap_err(),
            WireError::BadSignature
        );
    }
}
