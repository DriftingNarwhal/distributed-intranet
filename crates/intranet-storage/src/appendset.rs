//! Distributed append-sets — Storage Spec §2.5.
//!
//! # The problem this exists to solve
//!
//! A mutable pointer is inherently single-writer: one owner, one linear version
//! history. Several real needs do not fit that shape — an app directory where
//! many publishers register names independently, a search index where many
//! publishers contribute postings under shared terms. Both were originally
//! specified as "just write to a shared key", which does not work: a single DHT
//! key with no coordination between independent writers is a known hard
//! multi-writer problem, with concurrent-write conflicts, unbounded growth, and
//! no real way to enumerate what is there.
//!
//! # The primitive
//!
//! Content routing already answers "many independent nodes announce something
//! under one shared key without conflicting" — that is what provider records do
//! for ordinary content. An append-set is that same mechanism one level up:
//! each entry is independently content-addressed, and different publishers'
//! entries simply coexist as separate announcements under one collection key.
//! Nothing is ever overwritten, so there is no conflict to resolve.
//!
//! # Enumeration is best-effort
//!
//! Real Kademlia implementations cap providers returned and stored per key, so a
//! large or popular collection may not enumerate completely in one pass. That is
//! acceptable where best-effort discovery is the actual requirement — a slightly
//! incomplete search result set is normal. It is **not** acceptable where
//! incompleteness means a wrong answer rather than a partial one, which is why
//! app-name ownership anchors authority in the governance log and uses this
//! primitive only as a discovery hint.

use crate::StorageError;
use intranet_crypto::{Enc, Hash, Signature, hash_bytes};
use intranet_governance::{GovernanceState, PointerId};
use intranet_identity::{NetworkId, PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for append-set entry signatures.
const ENTRY_DOMAIN: &str = "intranet.append-set-entry.v1";

/// Derives a collection's key from its network and name.
///
/// Scoped by network so two networks' collections of the same name never
/// collide, consistent with every other per-network mechanism.
pub fn collection_id(network: &NetworkId, name: &str) -> Hash {
    let mut e = Enc::domain("intranet.append-set-collection.v1");
    network.encode(&mut e);
    e.str(name);
    hash_bytes(&e.finish())
}

/// The context checks every append-set-derived record must pass.
///
/// Extracted so that consumers building their own record types on this
/// primitive — search postings being the first — reuse the security-critical
/// logic rather than reimplementing it. Two of the three mandatory checks live
/// here; the third, the signature, is specific to each record's own encoding
/// and stays with the type that defines it.
///
/// Both checks resolve against replayed governance state, so a node answers
/// them by computation rather than by asking anyone.
pub fn validate_entry_context(
    publisher: &PerNetworkIdentityId,
    references: Option<&PointerId>,
    state: &GovernanceState,
) -> Result<(), StorageError> {
    if !state.is_member(publisher) {
        return Err(StorageError::PublisherNotAMember {
            publisher: publisher.short(),
        });
    }

    if let Some(pointer) = references
        && state.is_delisted(pointer)
    {
        return Err(StorageError::ReferencesDelistedContent {
            pointer: pointer.short(),
        });
    }

    Ok(())
}

/// One independently-addressed entry in a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendSetEntry {
    /// Which collection this belongs to.
    pub collection_id: Hash,
    /// The entry's data.
    pub payload: Vec<u8>,
    /// Pointer this entry refers to, if any.
    ///
    /// Present for entries that index other content — a search posting names the
    /// pointer it indexes. Its moderation state is then part of validating this
    /// entry, which is what stops a still-current member keeping an index entry
    /// alive for content that has already been delisted.
    pub references: Option<PointerId>,
    /// Who published it.
    pub publisher_identity: PerNetworkIdentityId,
    /// The publisher's signature.
    pub signature: Signature,
}

impl AppendSetEntry {
    /// Creates and signs an entry.
    pub fn create(
        publisher: &PerNetworkIdentity,
        collection_id: Hash,
        payload: Vec<u8>,
        references: Option<PointerId>,
    ) -> Self {
        let publisher_id = publisher.id();
        let payload_enc = Self::payload_bytes(&collection_id, &payload, &references, &publisher_id);
        Self {
            collection_id,
            payload,
            references,
            publisher_identity: publisher_id,
            signature: publisher.sign(&payload_enc),
        }
    }

    /// The entry's own content-addressed identifier.
    pub fn entry_id(&self) -> Hash {
        let mut e = Self::payload_bytes(
            &self.collection_id,
            &self.payload,
            &self.references,
            &self.publisher_identity,
        );
        e.fixed(self.signature.as_bytes());
        hash_bytes(&e.finish())
    }

    /// Validates this entry — all three checks, not two.
    ///
    /// Any node storing or relying on append-set data must verify:
    ///
    /// 1. **Signature.** Otherwise entries can be forged wholesale.
    /// 2. **Current membership**, checked against replayed governance state — so
    ///    a revoked identity's entries stop counting the moment their membership
    ///    ends, rather than persisting as long as they keep announcing.
    /// 3. **The referenced pointer is not delisted**, resolved from the most
    ///    recent `ModerationEntry` in the governance log.
    ///
    /// The third check is the one two successive review passes were needed to
    /// find. Without it, a *still-current* member can keep an index entry alive
    /// pointing at content that has already been moderated away — which would
    /// make moderation elsewhere cosmetic rather than effective, since it would
    /// depend on the malicious party's cooperation to take effect.
    pub fn validate(&self, state: &GovernanceState) -> Result<(), StorageError> {
        let payload = Self::payload_bytes(
            &self.collection_id,
            &self.payload,
            &self.references,
            &self.publisher_identity,
        );
        self.publisher_identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| StorageError::BadSignature)?;

        validate_entry_context(&self.publisher_identity, self.references.as_ref(), state)
    }

    fn payload_bytes(
        collection_id: &Hash,
        payload: &[u8],
        references: &Option<PointerId>,
        publisher: &PerNetworkIdentityId,
    ) -> Enc {
        let mut e = Enc::domain(ENTRY_DOMAIN);
        e.fixed(collection_id.as_bytes()).bytes(payload);
        e.option(references.as_ref(), |e, pointer| {
            e.fixed(pointer.as_bytes());
        });
        publisher.encode(&mut e);
        e
    }
}

/// A locally-held view of one collection.
///
/// Models what a node has actually enumerated, which is explicitly **not**
/// guaranteed to be everything. Consumers that need an authoritative answer must
/// anchor it elsewhere rather than treating this as complete.
#[derive(Debug, Clone)]
pub struct AppendSetView {
    collection_id: Hash,
    entries: std::collections::BTreeMap<Hash, AppendSetEntry>,
    /// Whether the last enumeration was truncated by a provider-record cap.
    truncated: bool,
}

impl AppendSetView {
    /// Creates an empty view of a collection.
    pub fn new(collection_id: Hash) -> Self {
        Self {
            collection_id,
            entries: std::collections::BTreeMap::new(),
            truncated: false,
        }
    }

    /// Adds an entry after validating it.
    pub fn insert(
        &mut self,
        entry: AppendSetEntry,
        state: &GovernanceState,
    ) -> Result<(), StorageError> {
        if entry.collection_id != self.collection_id {
            return Err(StorageError::WrongCollection);
        }
        entry.validate(state)?;
        self.entries.insert(entry.entry_id(), entry);
        Ok(())
    }

    /// Records that enumeration was cut short by a provider-record cap.
    ///
    /// Tracked explicitly so consumers can degrade honestly rather than assuming
    /// they saw everything.
    pub fn mark_truncated(&mut self) {
        self.truncated = true;
    }

    /// Whether this view is known to be incomplete.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Entries currently held.
    pub fn entries(&self) -> impl Iterator<Item = &AppendSetEntry> {
        self.entries.values()
    }

    /// How many entries are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the view holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drops entries that no longer validate.
    ///
    /// Re-run after governance state advances: a publisher may have been
    /// revoked, or referenced content delisted, since the entry was stored.
    /// Returns how many were dropped.
    pub fn revalidate(&mut self, state: &GovernanceState) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.validate(state).is_ok());
        before - self.entries.len()
    }
}
