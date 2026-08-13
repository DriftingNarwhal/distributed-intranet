//! BLAKE3 hashing.
//!
//! One hash type is used throughout the protocol: governance log entry hashes
//! (Core Protocol Spec §2.7), content IDs and chunk addresses (Storage Spec §1),
//! DEK commitments (Storage Spec §2.2), collection identifiers (Storage Spec §2.5),
//! and Merkle roots over quorum-certificate ballots (Core Protocol Spec §2.6.1).

use crate::enc::Enc;

/// A 32-byte BLAKE3 digest.
///
/// `Ord` is derived and is load-bearing, not incidental: the fork-choice sibling
/// tie-break (Core Protocol Spec §2.7.1, point 1) and the same-version mutable
/// pointer tie-break (Storage Spec §2.2) are both defined as "lower hash wins",
/// which is exactly this ordering — big-endian, lexicographic over the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Wraps raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A digest of all zeroes, used as the parent of a genesis entry.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        crate::to_hex(&self.0[..4])
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::to_hex(&self.0))
    }
}

/// Hashes raw bytes.
pub fn hash_bytes(bytes: &[u8]) -> Hash {
    Hash(*blake3::hash(bytes).as_bytes())
}

/// Hashes a canonical encoding.
pub fn hash_enc(enc: &Enc) -> Hash {
    hash_bytes(&enc.finish())
}

/// Computes a Merkle root over an ordered list of leaf hashes.
///
/// Used for quorum certificates (Core Protocol Spec §2.6.1, point 4), which are
/// specified as "a Merkle-rooted, independently-verifiable bundle of qualifying
/// signed ballots". Interior nodes are domain-separated from leaves so that a
/// leaf digest can never be presented as an interior node — the standard defence
/// against second-preimage attacks on Merkle trees.
///
/// An odd node at any level is promoted unchanged to the next level. An empty
/// leaf set yields [`Hash::ZERO`]; callers must reject empty certificates on
/// their own terms rather than treating a zero root as meaningful.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut e = Enc::domain("intranet.merkle.node.v1");
                e.fixed(pair[0].as_bytes()).fixed(pair[1].as_bytes());
                next.push(hash_enc(&e));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_is_deterministic_and_sensitive() {
        assert_eq!(hash_bytes(b"abc"), hash_bytes(b"abc"));
        assert_ne!(hash_bytes(b"abc"), hash_bytes(b"abd"));
    }

    #[test]
    fn ordering_is_lexicographic_over_digest_bytes() {
        // The fork-choice tie-break depends on this specific ordering.
        let low = Hash::from_bytes([0x00; 32]);
        let mut mid_bytes = [0x00; 32];
        mid_bytes[0] = 0x01;
        let mid = Hash::from_bytes(mid_bytes);
        let high = Hash::from_bytes([0xff; 32]);
        assert!(low < mid && mid < high);
    }

    #[test]
    fn merkle_root_is_order_sensitive() {
        let a = hash_bytes(b"a");
        let b = hash_bytes(b"b");
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    #[test]
    fn merkle_root_handles_odd_leaf_counts() {
        let leaves: Vec<Hash> = (0u8..5).map(|i| hash_bytes(&[i])).collect();
        let root = merkle_root(&leaves);
        assert_eq!(root, merkle_root(&leaves), "must be deterministic");
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn merkle_leaf_cannot_masquerade_as_interior_node() {
        // Domain separation means a two-leaf root is not simply hash(l0 || l1).
        let l0 = hash_bytes(b"l0");
        let l1 = hash_bytes(b"l1");
        let naive = {
            let mut raw = Vec::new();
            raw.extend_from_slice(l0.as_bytes());
            raw.extend_from_slice(l1.as_bytes());
            hash_bytes(&raw)
        };
        assert_ne!(merkle_root(&[l0, l1]), naive);
    }

    #[test]
    fn empty_leaf_set_yields_zero() {
        assert_eq!(merkle_root(&[]), Hash::ZERO);
    }
}
