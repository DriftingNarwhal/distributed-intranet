//! Local chunk store — Storage Spec §4.2, §4.6.
//!
//! # Why this is one store and not two
//!
//! §4.6 is explicit that swarm-serving copies and durability replicas are *not*
//! distinguished in storage: a node does not need to know whether it holds a
//! chunk because it was assigned as one of the N replicas (§3) or because a user
//! simply viewed the content. Both hold the bytes and both are eligible to
//! serve. The distinction matters only to the repair loop (§3.4), which cares
//! about the durability count rather than about transient demand-driven copies.
//!
//! So there is one store, and "am I in this swarm" is answered by whether the
//! bytes are present — which is also what makes §4.2's automatic swarm
//! membership fall out with no per-item opt-in: fetching a chunk *is* joining
//! its swarm.
//!
//! # Verification on the way in, not on the way out
//!
//! Every insertion is checked against the content identifier the bytes claim to
//! be (§1.1, §4.4 step 5). Doing it on insert rather than on serve means a
//! corrupt chunk can never enter the store at all, so it can never be passed on;
//! checking only on the way out would leave a node quietly holding — and
//! re-advertising — bytes that do not match their CID.
//!
//! # Retention
//!
//! **Flagged: the specs do not define an eviction policy.** §4.2 ties
//! participation to the node's declared `storage_offered`, and §4.6 notes that
//! demand-driven copies come and go, but nothing says what to discard when a
//! node reaches its limit — and the answer is not obvious, since evicting a
//! durability replica and evicting a cached copy have very different
//! consequences. This store is therefore unbounded and forgets nothing on its
//! own; callers decide what to [`remove`](ChunkStore::remove). That is the
//! honest position until the specs say more, rather than inventing a policy that
//! would silently drop replicas the repair loop is counting on.

use crate::{Cid, StorageError};
use std::collections::BTreeMap;

/// Chunks this node holds and can serve.
#[derive(Debug, Clone, Default)]
pub struct ChunkStore {
    chunks: BTreeMap<Cid, Vec<u8>>,
}

impl ChunkStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores bytes under their own content identifier.
    ///
    /// For locally produced content, where the identifier is derived rather than
    /// claimed and so cannot disagree.
    pub fn put(&mut self, bytes: Vec<u8>) -> Cid {
        let cid = Cid::of(&bytes);
        self.chunks.insert(cid, bytes);
        cid
    }

    /// Stores bytes received as `cid`, verifying they match it.
    ///
    /// The mandatory check from §1.1, applied at the point where it matters:
    /// bytes arriving from another node. A mismatch is returned rather than
    /// stored, so the caller can discard that source's copy, re-request from a
    /// different holder, and record the verification failure against the source
    /// (§4.4 step 5, Core Protocol Spec §4.6).
    pub fn insert(&mut self, cid: Cid, bytes: Vec<u8>) -> Result<(), StorageError> {
        if !cid.verifies(&bytes) {
            return Err(StorageError::ChunkVerificationFailed {
                cid: cid.short(),
            });
        }
        self.chunks.insert(cid, bytes);
        Ok(())
    }

    /// Stores bytes under an identifier **without** checking they match.
    ///
    /// This exists to construct a dishonest peer in tests — a node serving bytes
    /// that are not what their identifier claims — which is otherwise
    /// unreachable precisely because [`insert`](Self::insert) refuses it. There
    /// is no legitimate production use: content addressing is the correctness
    /// guarantee this whole layer rests on, and a caller reaching for this in
    /// real code has decided to store something it cannot name.
    pub fn insert_unchecked(&mut self, cid: Cid, bytes: Vec<u8>) {
        self.chunks.insert(cid, bytes);
    }

    /// The bytes for `cid`, if held.
    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.chunks.get(cid).map(Vec::as_slice)
    }

    /// Whether this node holds `cid`, and is therefore in its swarm (§4.2).
    pub fn has(&self, cid: &Cid) -> bool {
        self.chunks.contains_key(cid)
    }

    /// Drops a chunk.
    pub fn remove(&mut self, cid: &Cid) -> Option<Vec<u8>> {
        self.chunks.remove(cid)
    }

    /// Every chunk held, in identifier order.
    ///
    /// Ordered because it is what a node announces to the network, and an
    /// announcement that varied between runs for no reason would be noise in
    /// exactly the place that is hardest to debug.
    pub fn cids(&self) -> impl Iterator<Item = &Cid> {
        self.chunks.keys()
    }

    /// How many chunks are held.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Total bytes held, for reporting against declared `storage_offered`.
    pub fn total_bytes(&self) -> u64 {
        self.chunks.values().map(|bytes| bytes.len() as u64).sum()
    }

    /// Borrows the chunks as the map [`decode`](crate::decode) expects.
    pub fn blobs(&self) -> &BTreeMap<Cid, Vec<u8>> {
        &self.chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_chunk_is_retrievable_under_its_own_identifier() {
        let mut store = ChunkStore::new();
        let cid = store.put(b"hello swarm".to_vec());

        assert!(store.has(&cid));
        assert_eq!(store.get(&cid), Some(b"hello swarm".as_slice()));
        assert_eq!(store.total_bytes(), 11);
    }

    #[test]
    fn bytes_that_do_not_match_their_identifier_are_refused() {
        // The §4.4 step 5 guarantee, at the point it has to hold: a chunk
        // arriving from another node. Storing it and checking later would leave
        // this node holding — and able to pass on — bytes that are not what
        // their CID says they are.
        let mut store = ChunkStore::new();
        let honest = Cid::of(b"the real chunk");

        let refused = store.insert(honest, b"something else entirely".to_vec());
        assert!(matches!(
            refused,
            Err(StorageError::ChunkVerificationFailed { .. })
        ));
        assert!(
            !store.has(&honest),
            "a chunk that failed verification must not be held at all"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn a_verified_chunk_from_a_peer_is_accepted() {
        let mut store = ChunkStore::new();
        let bytes = b"the real chunk".to_vec();
        let cid = Cid::of(&bytes);

        store.insert(cid, bytes.clone()).unwrap();
        assert_eq!(store.get(&cid), Some(bytes.as_slice()));
    }

    #[test]
    fn holding_a_chunk_is_what_makes_a_node_a_swarm_member() {
        // §4.2: there is no per-item opt-in. Having fetched the bytes for any
        // reason is the whole of the membership test, which is why this is a
        // presence check rather than a flag someone has to remember to set.
        let mut store = ChunkStore::new();
        let cid = Cid::of(b"popular content");
        assert!(!store.has(&cid));

        store.insert(cid, b"popular content".to_vec()).unwrap();
        assert!(store.has(&cid));

        store.remove(&cid);
        assert!(
            !store.has(&cid),
            "a node that no longer caches the bytes is no longer in the swarm"
        );
    }
}
