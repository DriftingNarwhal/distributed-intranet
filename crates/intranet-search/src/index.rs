//! A node's local view of the distributed index — Search Spec §3.
//!
//! Models what one node has actually enumerated from the DHT, which is
//! explicitly not guaranteed to be everything: provider-record queries are
//! capped, so a very popular term may not enumerate completely in one pass.
//! That is acceptable here in a way it is not for name ownership — a slightly
//! incomplete result set is a normal property of search, whereas an incomplete
//! ownership answer would be a wrong one rather than a partial one.

use crate::{Posting, SearchError, Term, posting::DEFAULT_POSTING_TTL_MILLIS};
use intranet_crypto::{Hash, Timestamp};
use intranet_governance::GovernanceState;
use intranet_identity::NetworkId;
use std::collections::{BTreeMap, BTreeSet};

/// One node's local index for one network.
///
/// Scoped to a single network by construction. Search is permanently
/// single-network — an index spanning networks would require either a common
/// index across independent trust boundaries or a node correlating its own
/// memberships, and both undo guarantees the identity model is built on. The
/// network is therefore a field here, not a parameter callers pass per query.
#[derive(Debug, Clone)]
pub struct LocalIndex {
    network: NetworkId,
    postings: BTreeMap<Hash, Posting>,
    by_term: BTreeMap<Term, BTreeSet<Hash>>,
    truncated_terms: BTreeSet<Term>,
    ttl_millis: i64,
}

impl LocalIndex {
    /// Creates an empty index for a network.
    pub fn new(network: NetworkId) -> Self {
        Self {
            network,
            postings: BTreeMap::new(),
            by_term: BTreeMap::new(),
            truncated_terms: BTreeSet::new(),
            ttl_millis: DEFAULT_POSTING_TTL_MILLIS,
        }
    }

    /// Sets how long postings stay live without re-announcement.
    pub fn with_ttl(mut self, ttl_millis: i64) -> Self {
        self.ttl_millis = ttl_millis;
        self
    }

    /// The network this index covers.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Records a posting, validating it first.
    ///
    /// Validation is mandatory rather than advisory: an unvalidated index would
    /// let a revoked member's postings, or postings for delisted content, keep
    /// surfacing indefinitely.
    pub fn insert(&mut self, posting: Posting, state: &GovernanceState) -> Result<(), SearchError> {
        if state.network != self.network {
            return Err(SearchError::WrongNetwork);
        }
        posting.validate(state)?;

        let id = posting.id();
        for term in posting.terms.keys() {
            self.by_term.entry(term.clone()).or_default().insert(id);
        }
        self.postings.insert(id, posting);
        Ok(())
    }

    /// Records that a term's enumeration was cut short by a provider cap.
    pub fn mark_truncated(&mut self, term: Term) {
        self.truncated_terms.insert(term);
    }

    /// Whether results for a term are known to be incomplete.
    pub fn is_truncated(&self, term: &Term) -> bool {
        self.truncated_terms.contains(term)
    }

    /// Postings currently held for a term.
    pub fn postings_for(&self, term: &Term) -> Vec<&Posting> {
        self.by_term
            .get(term)
            .map(|ids| ids.iter().filter_map(|id| self.postings.get(id)).collect())
            .unwrap_or_default()
    }

    /// Total postings held, across all terms.
    pub fn len(&self) -> usize {
        self.postings.len()
    }

    /// Whether the index holds nothing.
    pub fn is_empty(&self) -> bool {
        self.postings.is_empty()
    }

    /// How many distinct terms are indexed.
    pub fn term_count(&self) -> usize {
        self.by_term.len()
    }

    /// Drops postings that have aged out without re-announcement.
    ///
    /// Returns how many were dropped. This is the mechanism by which removed
    /// content leaves the index without any explicit deletion protocol.
    pub fn expire(&mut self, now: Timestamp) -> usize {
        let stale: Vec<Hash> = self
            .postings
            .iter()
            .filter(|(_, posting)| posting.is_stale(now, self.ttl_millis))
            .map(|(id, _)| *id)
            .collect();
        self.remove_all(&stale);
        stale.len()
    }

    /// Re-validates every posting against current governance state.
    ///
    /// Run after governance advances. A publisher may have been revoked, or
    /// indexed content delisted, since a posting was stored — and neither
    /// requires the publisher's cooperation to take effect, which is precisely
    /// what makes moderation real rather than cosmetic.
    pub fn revalidate(&mut self, state: &GovernanceState) -> usize {
        let rejected: Vec<Hash> = self
            .postings
            .iter()
            .filter(|(_, posting)| posting.validate(state).is_err())
            .map(|(id, _)| *id)
            .collect();
        self.remove_all(&rejected);
        rejected.len()
    }

    /// Replaces a pointer's postings with a newer one — §3.3.
    ///
    /// Re-publishing is the natural trigger for re-indexing, so an update
    /// supersedes the previous posting for that pointer rather than
    /// accumulating alongside it.
    pub fn reindex(
        &mut self,
        posting: Posting,
        state: &GovernanceState,
    ) -> Result<(), SearchError> {
        let superseded: Vec<Hash> = self
            .postings
            .iter()
            .filter(|(_, held)| held.pointer_id == posting.pointer_id)
            .map(|(id, _)| *id)
            .collect();
        self.remove_all(&superseded);
        self.insert(posting, state)
    }

    fn remove_all(&mut self, ids: &[Hash]) {
        for id in ids {
            self.postings.remove(id);
        }
        let dropped: BTreeSet<Hash> = ids.iter().copied().collect();
        self.by_term.retain(|_, postings| {
            postings.retain(|id| !dropped.contains(id));
            !postings.is_empty()
        });
    }
}
