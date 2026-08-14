//! Wire encoding for search postings — Search Spec §3.1, §6.1.
//!
//! # Why postings travel as their own type rather than as generic entry bytes
//!
//! §3.1's efficiency note is explicit: a naive implementation creates one
//! posting object per `(publish, term)` pair, which is expensive for content
//! matching many terms. The specified shape is **one posting object per publish,
//! announced under every matched term's `collection_id`** — the object is built
//! and signed once, and only the lightweight provider-record announcement
//! repeats per term.
//!
//! So a posting is not an append-set entry per term; it is one signed object
//! that appears in many collections. This module encodes that object. The
//! collection machinery underneath (`intranet-transport`'s collection protocol)
//! carries it as opaque bytes, which is what lets the same primitive serve the
//! app name registry without either consumer's shape leaking into the other.
//!
//! # Verification on decode
//!
//! §6.1 makes verification mandatory rather than optional, and this decodes into
//! a signature check for the same reason the governance and ledger codecs do: a
//! posting is a self-attested claim about someone else's content, so an
//! unverified one is an invitation to inject index entries nobody published.
//!
//! Signature validity is only the first of §3.1's three checks. The other two —
//! that the publisher is a *current* member, and that the pointer it references
//! is not delisted — need replayed governance state and so cannot happen here.
//! [`Posting::validate`](crate::Posting::validate) performs them, and a caller
//! that decodes without then validating has done a third of the job.

use crate::{Field, Posting, SearchError, Term, TermStats};
use intranet_crypto::{Dec, DecodeError, Enc, Signature, Timestamp};
use intranet_identity::PerNetworkIdentityId;
use intranet_governance::PointerId;
use std::collections::BTreeMap;

/// Domain tag for a posting on the wire.
const POSTING_WIRE_DOMAIN: &str = "intranet.wire.posting.v1";

/// The most terms one posting will carry.
///
/// **Flagged: §2.2 caps indexed field sizes but sets no term-count ceiling.**
/// One is needed because the count is chosen by the publisher: without it a
/// single posting could name a million terms and be announced under a million
/// collection keys, which is a cheap way to spam every node's index. 4096 is far
/// above any plausible document's distinct-term count.
pub const MAX_TERMS_PER_POSTING: usize = 4096;

/// Why a posting could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed posting: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in posting")]
    InvalidKey,
    /// The posting decoded, but its signature did not verify.
    #[error("posting signature did not verify after decoding")]
    BadSignature,
    /// The posting named more terms than this build will accept.
    #[error("posting names {count} terms, above the {MAX_TERMS_PER_POSTING} ceiling")]
    TooManyTerms {
        /// How many were named.
        count: usize,
    },
}

/// Encodes a posting for announcement.
pub fn encode_posting(posting: &Posting) -> Vec<u8> {
    let mut e = Enc::domain(POSTING_WIRE_DOMAIN);
    e.fixed(posting.pointer_id.as_bytes());
    e.seq(posting.terms.iter(), |e, (term, stats)| {
        e.str(term.as_str())
            .u32(stats.frequency)
            .u8(match stats.best_field {
                Field::Title => 0,
                Field::Tag => 1,
                Field::Description => 2,
                Field::Body => 3,
            });
    });
    e.i64(posting.published_at.as_millis());
    posting.publisher_identity.encode(&mut e);
    e.fixed(posting.signature.as_bytes());
    e.finish()
}

/// Decodes a posting and verifies its signature.
///
/// The signature check is §6.1's first mandatory verification. Two more remain
/// and need governance state — see the module docs.
pub fn decode_posting(bytes: &[u8]) -> Result<Posting, WireError> {
    let mut d = Dec::domain(bytes, POSTING_WIRE_DOMAIN)?;
    let pointer_id = PointerId::from_bytes(d.fixed::<32>()?);

    let pairs = d.seq::<_, WireError>(|d| {
        let term = Term::new(d.str()?);
        let frequency = d.u32()?;
        let best_field = match d.u8()? {
            0 => Field::Title,
            1 => Field::Tag,
            2 => Field::Description,
            3 => Field::Body,
            other => {
                return Err(WireError::Malformed(DecodeError::UnknownVariant {
                    type_name: "Field",
                    discriminant: other,
                }));
            }
        };
        Ok((
            term,
            TermStats {
                frequency,
                best_field,
            },
        ))
    })?;
    if pairs.len() > MAX_TERMS_PER_POSTING {
        return Err(WireError::TooManyTerms { count: pairs.len() });
    }
    let terms: BTreeMap<Term, TermStats> = pairs.into_iter().collect();

    let published_at = Timestamp::from_millis(d.i64()?);
    let publisher_identity = {
        let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
            .map_err(|_| WireError::InvalidKey)?;
        PerNetworkIdentityId::from_verifying_key(key)
    };
    let signature = Signature::from_bytes(d.fixed::<64>()?);
    d.finish()?;

    let posting = Posting {
        pointer_id,
        terms,
        published_at,
        publisher_identity,
        signature,
    };
    match posting.verify() {
        Ok(()) => Ok(posting),
        Err(SearchError::BadSignature) => Err(WireError::BadSignature),
        Err(_) => Err(WireError::BadSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentMetadata, IndexableContent};
    use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};

    const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
    }

    fn posting(publisher: &PerNetworkIdentity) -> Posting {
        let metadata = ContentMetadata::new(
            "Trail maps for the north ridge",
            "Printable topographic maps",
        );
        let content = IndexableContent {
            pointer_id: PointerId::from_bytes([7u8; 32]),
            metadata: &metadata,
            document: None,
        };
        Posting::build(publisher, &content, Timestamp::from_millis(1_000))
    }

    #[test]
    fn a_posting_round_trips_with_an_identical_identifier() {
        // The identifier is asserted, not just structural equality: a posting is
        // announced and looked up under `id()`, so a round trip that produced an
        // equal-looking posting with a different id would be announced under a
        // key nobody searches.
        let original = posting(&identity(1));
        let decoded = decode_posting(&encode_posting(&original)).unwrap();

        assert_eq!(decoded, original);
        assert_eq!(decoded.id(), original.id());
        assert!(!decoded.terms.is_empty(), "the fixture should match terms");
    }

    #[test]
    fn the_collection_keys_survive_the_round_trip() {
        // A posting is found through the collections it is announced under, so
        // these mattering is the whole point of carrying the term set.
        let original = posting(&identity(1));
        let decoded = decode_posting(&encode_posting(&original)).unwrap();
        assert_eq!(
            decoded.announcements(&NETWORK),
            original.announcements(&NETWORK)
        );
    }

    #[test]
    fn every_single_bit_change_is_rejected() {
        // §6.1's mandatory verification, at the point bytes arrive from someone
        // else. A posting is a self-attested claim about content, so accepting
        // an unverified one lets anyone inject index entries.
        let original = posting(&identity(1));
        let encoded = encode_posting(&original);

        let rejected = (0..encoded.len())
            .filter(|index| {
                let mut bytes = encoded.clone();
                bytes[*index] ^= 0x01;
                decode_posting(&bytes).is_err()
            })
            .count();
        assert_eq!(rejected, encoded.len());
    }

    #[test]
    fn a_posting_attributed_to_another_publisher_is_rejected() {
        let mut forged = posting(&identity(1));
        forged.publisher_identity = identity(2).id();

        assert_eq!(
            decode_posting(&encode_posting(&forged)).unwrap_err(),
            WireError::BadSignature
        );
    }

    #[test]
    fn a_posting_claiming_different_content_is_rejected() {
        // The pointer is what a search result resolves to, so being able to
        // repoint a legitimate posting would turn any indexed term into a
        // redirect to content of the attacker's choosing.
        let mut tampered = posting(&identity(1));
        tampered.pointer_id = PointerId::from_bytes([9u8; 32]);

        assert_eq!(
            decode_posting(&encode_posting(&tampered)).unwrap_err(),
            WireError::BadSignature
        );
    }
}
