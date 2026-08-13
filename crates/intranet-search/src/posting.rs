//! Search postings — Search Spec §3.1, §4.
//!
//! # One object, many announcements
//!
//! A naive implementation creates one posting object per `(publish, term)`
//! pair — expensive for content matching many terms, since each would carry its
//! own key material, wrapping, and TTL refresh. Instead there is **one posting
//! object per publish**, announced under every one of its matched terms'
//! collection keys. The object and its key material are created once; only the
//! lightweight announcement repeats per term.
//!
//! # Indexing is a side effect of publishing
//!
//! A posting is derived from content the publisher is already publishing, in
//! the same action. There is no separate indexing pipeline, no delay between
//! "content is live" and "content is searchable", and — the point of the whole
//! document — **no external agent ever visits content to make it
//! discoverable**. That is the structural answer to the no-crawlers
//! requirement: an index that is a by-product of publishing gives a crawler
//! nothing to do.

use crate::{Field, IndexableContent, SearchError, Term, tokenize};
use intranet_crypto::{Enc, Hash, Signature, Timestamp, hash_bytes};
use intranet_governance::{GovernanceState, PointerId};
use intranet_identity::{NetworkId, PerNetworkIdentity, PerNetworkIdentityId};
use std::collections::BTreeMap;

/// Domain tag for posting signatures.
const POSTING_DOMAIN: &str = "intranet.search-posting.v1";

/// How one term occurs within one piece of content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermStats {
    /// How many times the term appears across all indexed fields.
    pub frequency: u32,
    /// The highest-weighted field the term appeared in.
    ///
    /// Only the best field is kept rather than every occurrence's field: a term
    /// in both title and body is, for ranking purposes, a title term, and
    /// storing the full breakdown would grow postings without changing results.
    pub best_field: Field,
}

/// One publish's complete index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    /// The content this posting indexes.
    pub pointer_id: PointerId,
    /// Every term this content matched, with its statistics.
    pub terms: BTreeMap<Term, TermStats>,
    /// When the posting was produced.
    pub published_at: Timestamp,
    /// Who published it.
    pub publisher_identity: PerNetworkIdentityId,
    /// The publisher's signature.
    pub signature: Signature,
}

impl Posting {
    /// Derives a posting from content being published.
    ///
    /// Runs during the publish action itself, which is what makes indexing
    /// automatic rather than something a publisher must remember to do.
    pub fn build(
        publisher: &PerNetworkIdentity,
        content: &IndexableContent<'_>,
        published_at: Timestamp,
    ) -> Self {
        let mut terms: BTreeMap<Term, TermStats> = BTreeMap::new();

        for (field, text) in content.fields() {
            for (term, count) in tokenize::term_frequencies(text) {
                terms
                    .entry(term)
                    .and_modify(|stats| {
                        stats.frequency = stats.frequency.saturating_add(count);
                        // Keep the strongest field this term appeared in.
                        if field.weight() > stats.best_field.weight() {
                            stats.best_field = field;
                        }
                    })
                    .or_insert(TermStats {
                        frequency: count,
                        best_field: field,
                    });
            }
        }

        let publisher_id = publisher.id();
        let payload = Self::payload(&content.pointer_id, &terms, published_at, &publisher_id);
        Self {
            pointer_id: content.pointer_id,
            terms,
            published_at,
            publisher_identity: publisher_id,
            signature: publisher.sign(&payload),
        }
    }

    /// This posting's content-addressed identifier.
    pub fn id(&self) -> Hash {
        let mut e = Self::payload(
            &self.pointer_id,
            &self.terms,
            self.published_at,
            &self.publisher_identity,
        );
        e.fixed(self.signature.as_bytes());
        hash_bytes(&e.finish())
    }

    /// The collection keys this posting should be announced under.
    ///
    /// One announcement per matched term. Each is an ordinary provider-record
    /// announcement — the same mechanism content routing already uses — so
    /// nothing here needs a new DHT operation or conflict resolution.
    pub fn announcements(&self, network: &NetworkId) -> Vec<Hash> {
        self.terms
            .keys()
            .map(|term| intranet_storage::collection_id(network, term.as_str()))
            .collect()
    }

    /// Verifies the publisher's signature.
    pub fn verify(&self) -> Result<(), SearchError> {
        let payload = Self::payload(
            &self.pointer_id,
            &self.terms,
            self.published_at,
            &self.publisher_identity,
        );
        self.publisher_identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| SearchError::BadSignature)
    }

    /// Validates this posting — all three mandatory checks.
    ///
    /// Signature, current membership, and the indexed pointer's moderation
    /// state. The membership and delisting checks reuse the storage layer's
    /// shared append-set validation rather than reimplementing them, so the two
    /// consumers of that primitive cannot drift apart on security-critical
    /// logic.
    ///
    /// The third check is what gives moderation teeth here. Without it a
    /// *still-current* member could keep an index entry alive for content
    /// already delisted, leaving moderation effective only with the malicious
    /// party's cooperation.
    pub fn validate(&self, state: &GovernanceState) -> Result<(), SearchError> {
        self.verify()?;
        intranet_storage::validate_entry_context(
            &self.publisher_identity,
            Some(&self.pointer_id),
            state,
        )
        .map_err(SearchError::Rejected)
    }

    /// Whether this posting has aged past `ttl_millis` without refresh.
    ///
    /// Postings expire unless periodically re-announced, so removed or delisted
    /// content falls out of the index naturally — no explicit deletion protocol
    /// is needed for the ordinary case.
    pub fn is_stale(&self, now: Timestamp, ttl_millis: i64) -> bool {
        now.millis_since(self.published_at) > ttl_millis
    }

    fn payload(
        pointer_id: &PointerId,
        terms: &BTreeMap<Term, TermStats>,
        published_at: Timestamp,
        publisher: &PerNetworkIdentityId,
    ) -> Enc {
        let mut e = Enc::domain(POSTING_DOMAIN);
        e.fixed(pointer_id.as_bytes());
        e.seq(terms.iter(), |e, (term, stats)| {
            e.str(term.as_str())
                .u32(stats.frequency)
                .u8(stats.best_field.discriminant());
        });
        e.i64(published_at.as_millis());
        publisher.encode(&mut e);
        e
    }
}

/// How long a posting stays live without re-announcement.
///
/// **Flagged: §8 lists this as needing a concrete default that is tuning rather
/// than structure.** Twenty-four hours is long enough that re-announcement is
/// cheap background work, short enough that a departed publisher's content
/// leaves the index within a day.
pub const DEFAULT_POSTING_TTL_MILLIS: i64 = 24 * 60 * 60 * 1000;
