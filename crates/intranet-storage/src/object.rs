//! Content addressing and object encoding — Storage Spec §1.
//!
//! The pipeline, in the one order that works (§1.2):
//!
//! ```text
//!   plaintext ──chunk──▶ plaintext chunks ──encrypt(DEK)──▶ ciphertext ──hash──▶ CIDs
//! ```
//!
//! Chunk first so boundaries follow the content; encrypt deterministically so
//! unchanged chunks keep their bytes; hash the ciphertext so the address is a
//! function of what is actually stored and any node can verify what it received.

use crate::{ChunkSpec, Dek, StorageError, chunk};
use intranet_crypto::{Enc, Hash, hash_bytes, to_hex};

/// A content identifier: the hash of a stored (encrypted) blob.
///
/// The address *is* a function of the content, so identical stored bytes always
/// produce the same identifier and any change produces a different one. This
/// gives integrity verification for free: a node can confirm retrieved bytes
/// match their claimed CID without trusting whoever served them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct Cid(intranet_crypto::Hash);

impl Cid {
    /// Computes the identifier of a stored blob.
    pub fn of(bytes: &[u8]) -> Self {
        Self(hash_bytes(bytes))
    }

    /// Wraps a raw digest.
    pub const fn from_hash(hash: intranet_crypto::Hash) -> Self {
        Self(hash)
    }

    /// The underlying digest.
    pub const fn hash(&self) -> &intranet_crypto::Hash {
        &self.0
    }

    /// Verifies that `bytes` are the content this identifier names.
    ///
    /// The mandatory correctness step on everything received from the swarm: a
    /// failure means that source's copy is discarded and the chunk re-requested
    /// elsewhere, and it also feeds that source's local reliability signal as an
    /// ordinary verification failure.
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        Self::of(bytes) == *self
    }

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        to_hex(&self.0.as_bytes()[..4])
    }
}

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The ordered chunk list an object resolves to.
///
/// Held in plaintext. Its contents are hashes of ciphertext, which a non-member
/// obtaining replicated bytes can already see — §5.1's posture is that such a
/// node gets "ciphertext, CIDs, and an opaque wrapped key blob it cannot open",
/// so the manifest reveals nothing beyond what that already concedes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Chunk identifiers, in order.
    pub chunks: Vec<Cid>,
    /// Total plaintext length, for pre-allocation and integrity checking.
    pub plaintext_len: u64,
}

impl Manifest {
    /// This manifest's own content identifier.
    ///
    /// A mutable pointer's `current_cid` is this value: resolving a pointer
    /// yields a manifest, which yields the chunks.
    pub fn cid(&self) -> Cid {
        Cid::of(&self.canonical_bytes())
    }

    /// The canonical encoding this manifest hashes as.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = Enc::domain("intranet.manifest.v1");
        e.seq(self.chunks.iter(), |e, cid| {
            e.fixed(cid.hash().as_bytes());
        });
        e.u64(self.plaintext_len);
        e.finish()
    }

    /// Parses a manifest from its canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        // Layout: domain tag (framed) | chunk count (u64) | 32 bytes per chunk |
        // plaintext length (u64).
        const TAG: &str = "intranet.manifest.v1";
        let mut cursor = 0usize;

        let take = |cursor: &mut usize, n: usize| -> Result<&[u8], StorageError> {
            let end = cursor.checked_add(n).ok_or(StorageError::MalformedManifest)?;
            let slice = bytes.get(*cursor..end).ok_or(StorageError::MalformedManifest)?;
            *cursor = end;
            Ok(slice)
        };

        let tag_len = u64::from_be_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| StorageError::MalformedManifest)?,
        );
        if tag_len as usize != TAG.len() || take(&mut cursor, TAG.len())? != TAG.as_bytes() {
            return Err(StorageError::MalformedManifest);
        }

        let count = u64::from_be_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| StorageError::MalformedManifest)?,
        );
        // Guard against a declared count that would allocate wildly before the
        // bytes to back it are even present.
        if count > (bytes.len() / 32) as u64 + 1 {
            return Err(StorageError::MalformedManifest);
        }

        let mut chunks = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let digest: [u8; 32] = take(&mut cursor, 32)?
                .try_into()
                .map_err(|_| StorageError::MalformedManifest)?;
            chunks.push(Cid::from_hash(Hash::from_bytes(digest)));
        }

        let plaintext_len = u64::from_be_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| StorageError::MalformedManifest)?,
        );

        if cursor != bytes.len() {
            return Err(StorageError::MalformedManifest);
        }

        Ok(Self {
            chunks,
            plaintext_len,
        })
    }
}

/// An object encoded for storage: its manifest plus every stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedObject {
    /// The manifest describing the chunk sequence.
    pub manifest: Manifest,
    /// Each chunk's identifier and stored bytes, in manifest order.
    pub chunks: Vec<(Cid, Vec<u8>)>,
}

impl EncodedObject {
    /// The manifest's own content identifier.
    pub fn manifest_cid(&self) -> Cid {
        self.manifest.cid()
    }

    /// Total stored bytes across all chunks.
    pub fn stored_len(&self) -> usize {
        self.chunks.iter().map(|(_, bytes)| bytes.len()).sum()
    }

    /// Chunks this object has that `previous` did not — what a delta fetch needs.
    ///
    /// The concrete form of "don't re-download a page you already have most of":
    /// a node holding an earlier version fetches only what this returns.
    pub fn new_chunks_since(&self, previous: &Manifest) -> Vec<Cid> {
        let held: std::collections::HashSet<Cid> = previous.chunks.iter().copied().collect();
        self.manifest
            .chunks
            .iter()
            .copied()
            .filter(|cid| !held.contains(cid))
            .collect()
    }
}

/// Chunks, encrypts, and addresses an object.
pub fn encode(plaintext: &[u8], dek: &Dek, spec: ChunkSpec) -> EncodedObject {
    let chunks: Vec<(Cid, Vec<u8>)> = chunk::split(plaintext, spec)
        .into_iter()
        .map(|piece| {
            let sealed = dek.seal_chunk(piece);
            (Cid::of(&sealed), sealed)
        })
        .collect();

    EncodedObject {
        manifest: Manifest {
            chunks: chunks.iter().map(|(cid, _)| *cid).collect(),
            plaintext_len: plaintext.len() as u64,
        },
        chunks,
    }
}

/// Reassembles plaintext from a manifest and the stored blobs it names.
///
/// Verifies every chunk against its CID before decrypting. A chunk that fails is
/// an error rather than a silently skipped one: silently tolerating a bad chunk
/// would hand the caller truncated content that looks complete.
pub fn decode(
    manifest: &Manifest,
    blobs: &std::collections::BTreeMap<Cid, Vec<u8>>,
    dek: &Dek,
) -> Result<Vec<u8>, StorageError> {
    let mut plaintext = Vec::with_capacity(manifest.plaintext_len as usize);

    for cid in &manifest.chunks {
        let blob = blobs.get(cid).ok_or(StorageError::MissingChunk {
            cid: cid.short(),
        })?;
        if !cid.verifies(blob) {
            return Err(StorageError::ChunkVerificationFailed {
                cid: cid.short(),
            });
        }
        plaintext.extend_from_slice(&dek.open_chunk(blob)?);
    }

    if plaintext.len() as u64 != manifest.plaintext_len {
        return Err(StorageError::LengthMismatch {
            expected: manifest.plaintext_len,
            got: plaintext.len() as u64,
        });
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn data(len: usize, seed: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut x = seed;
        for _ in 0..len {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            out.push((x >> 16) as u8);
        }
        out
    }

    fn blobs(object: &EncodedObject) -> BTreeMap<Cid, Vec<u8>> {
        object.chunks.iter().cloned().collect()
    }

    #[test]
    fn encode_decode_round_trips() {
        let dek = Dek::generate().unwrap();
        let content = data(300_000, 3);
        let object = encode(&content, &dek, ChunkSpec::default());
        assert_eq!(decode(&object.manifest, &blobs(&object), &dek).unwrap(), content);
    }

    #[test]
    fn empty_content_round_trips() {
        let dek = Dek::generate().unwrap();
        let object = encode(&[], &dek, ChunkSpec::default());
        assert!(object.chunks.is_empty());
        assert_eq!(decode(&object.manifest, &blobs(&object), &dek).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn encoding_is_deterministic() {
        let dek = Dek::from_bytes([1u8; 32]);
        let content = data(200_000, 5);
        let a = encode(&content, &dek, ChunkSpec::default());
        let b = encode(&content, &dek, ChunkSpec::default());
        assert_eq!(a, b);
        assert_eq!(a.manifest_cid(), b.manifest_cid());
    }

    #[test]
    fn an_edit_reuses_almost_every_chunk() {
        // The delta-fetch payoff, end to end through encryption: a small edit
        // must produce only a handful of genuinely new stored blobs.
        let dek = Dek::from_bytes([1u8; 32]);
        let spec = ChunkSpec::default();
        let original = data(400_000, 7);
        let mut edited = original.clone();
        edited.splice(150_000..150_000, b"a small insertion".iter().copied());

        let before = encode(&original, &dek, spec);
        let after = encode(&edited, &dek, spec);

        let fresh = after.new_chunks_since(&before.manifest);
        assert!(
            fresh.len() <= 3,
            "expected a handful of new chunks, got {} of {}",
            fresh.len(),
            after.manifest.chunks.len()
        );
        assert_ne!(before.manifest_cid(), after.manifest_cid());
    }

    #[test]
    fn a_republish_with_no_changes_produces_no_new_chunks() {
        let dek = Dek::from_bytes([1u8; 32]);
        let content = data(200_000, 9);
        let first = encode(&content, &dek, ChunkSpec::default());
        let second = encode(&content, &dek, ChunkSpec::default());
        assert!(second.new_chunks_since(&first.manifest).is_empty());
    }

    #[test]
    fn a_corrupted_chunk_is_detected_not_silently_accepted() {
        let dek = Dek::from_bytes([1u8; 32]);
        let content = data(100_000, 11);
        let object = encode(&content, &dek, ChunkSpec::default());

        let mut store = blobs(&object);
        let target = object.manifest.chunks[0];
        store.insert(target, b"not the real chunk".to_vec());

        assert!(matches!(
            decode(&object.manifest, &store, &dek),
            Err(StorageError::ChunkVerificationFailed { .. })
        ));
    }

    #[test]
    fn a_missing_chunk_is_reported_rather_than_truncating() {
        let dek = Dek::from_bytes([1u8; 32]);
        let content = data(100_000, 13);
        let object = encode(&content, &dek, ChunkSpec::default());

        let mut store = blobs(&object);
        store.remove(&object.manifest.chunks[0]);

        assert!(matches!(
            decode(&object.manifest, &store, &dek),
            Err(StorageError::MissingChunk { .. })
        ));
    }

    #[test]
    fn a_non_member_holding_bytes_learns_nothing_without_the_dek() {
        let dek = Dek::generate().unwrap();
        let content = b"a secret worth protecting, repeated for length".repeat(500);
        let object = encode(&content, &dek, ChunkSpec::default());

        // Every stored blob is opaque without the key.
        for (_, blob) in &object.chunks {
            assert!(
                !blob.windows(6).any(|w| w == b"secret"),
                "plaintext must not survive into stored bytes"
            );
        }
        assert!(Dek::from_bytes([0u8; 32]).open_chunk(&object.chunks[0].1).is_err());
    }

    #[test]
    fn manifest_round_trips_through_its_canonical_bytes() {
        let dek = Dek::from_bytes([1u8; 32]);
        let object = encode(&data(150_000, 17), &dek, ChunkSpec::default());
        let parsed = Manifest::from_bytes(&object.manifest.canonical_bytes()).unwrap();
        assert_eq!(parsed, object.manifest);
        assert_eq!(parsed.cid(), object.manifest_cid());
    }

    #[test]
    fn a_malformed_manifest_is_rejected() {
        assert!(matches!(
            Manifest::from_bytes(b"nonsense"),
            Err(StorageError::MalformedManifest)
        ));

        // Trailing bytes must not be silently ignored.
        let dek = Dek::from_bytes([1u8; 32]);
        let object = encode(&data(50_000, 19), &dek, ChunkSpec::default());
        let mut bytes = object.manifest.canonical_bytes();
        bytes.push(0);
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(StorageError::MalformedManifest)
        ));
    }

    #[test]
    fn a_manifest_declaring_an_absurd_chunk_count_is_rejected() {
        // Guards against a hostile manifest driving a huge allocation before the
        // bytes to back it are even present.
        let mut e = Enc::domain("intranet.manifest.v1");
        e.u64(u64::MAX / 32);
        assert!(matches!(
            Manifest::from_bytes(&e.finish()),
            Err(StorageError::MalformedManifest)
        ));
    }

    #[test]
    fn different_content_yields_different_manifest_cids() {
        let dek = Dek::from_bytes([1u8; 32]);
        let spec = ChunkSpec::default();
        assert_ne!(
            encode(&data(100_000, 1), &dek, spec).manifest_cid(),
            encode(&data(100_000, 2), &dek, spec).manifest_cid()
        );
    }
}
