//! Content-defined chunking — Storage Spec §1.3.
//!
//! # Why boundaries come from the content
//!
//! A node re-visiting content it already holds should fetch only what actually
//! changed. Fixed-size chunking cannot deliver that: inserting a single byte
//! near the start shifts every subsequent boundary, so a one-character edit
//! looks like a near-total rewrite to the storage layer. Content-defined
//! chunking derives boundaries from the bytes themselves, so a local edit
//! disturbs only the chunks immediately around it and everything else
//! re-chunks identically.
//!
//! # Chunking happens on plaintext, before encryption
//!
//! This ordering is required, not incidental. Encryption randomises its output,
//! so encrypting first would destroy the content-similarity signal the rolling
//! hash depends on — and a one-line edit would once again look like an entirely
//! different file, defeating the whole point.

use intranet_governance::NetworkPolicy;

/// Chunk size bounds derived from a network's target size.
///
/// The target is network-wide policy rather than a per-publisher choice:
/// deduplication depends on identical content producing identical boundaries,
/// and two publishers using different targets within one network would silently
/// lose it between otherwise-identical content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpec {
    /// Smallest permitted chunk.
    pub min: u32,
    /// Target average chunk size.
    pub target: u32,
    /// Largest permitted chunk.
    pub max: u32,
}

impl ChunkSpec {
    /// Lower bound the chunker accepts.
    const FLOOR: u32 = 1024;
    /// Upper bound the chunker accepts.
    const CEILING: u32 = 256 * 1024 * 1024;

    /// Derives bounds from a target size.
    ///
    /// Min and max bracket the target at a quarter and four times, the
    /// conventional spread for FastCDC: wide enough that boundaries are chosen
    /// by content rather than clamped by the limits, narrow enough that a
    /// pathological input cannot produce one enormous chunk.
    pub fn from_target(target: u32) -> Self {
        let target = target.clamp(Self::FLOOR, Self::CEILING);
        Self {
            min: (target / 4).max(Self::FLOOR / 4),
            target,
            max: target.saturating_mul(4).min(Self::CEILING),
        }
    }

    /// Derives bounds from a network's configured target size.
    pub fn from_policy(policy: &NetworkPolicy) -> Self {
        Self::from_target(policy.target_chunk_size)
    }
}

impl Default for ChunkSpec {
    /// The middle of the 16–64KB range the spec defaults to.
    fn default() -> Self {
        Self::from_target(32 * 1024)
    }
}

/// Splits plaintext into content-defined chunks.
///
/// # Small-file exemption
///
/// Content at or below the target size is returned as a single chunk without
/// running the rolling hash at all — there is nothing to gain from chunking
/// something already smaller than one chunk.
///
/// Empty input yields no chunks rather than one empty chunk, so that an empty
/// object and a one-empty-chunk object cannot be confused.
pub fn split(plaintext: &[u8], spec: ChunkSpec) -> Vec<&[u8]> {
    if plaintext.is_empty() {
        return Vec::new();
    }
    if plaintext.len() <= spec.target as usize {
        return vec![plaintext];
    }

    fastcdc::v2020::FastCDC::new(plaintext, spec.min as usize, spec.target as usize, spec.max as usize)
        .map(|chunk| &plaintext[chunk.offset..chunk.offset + chunk.length])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes, so chunk boundaries are content-driven
    /// rather than an artefact of repetitive input.
    fn data(len: usize, seed: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut x = seed;
        for _ in 0..len {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            out.push((x >> 16) as u8);
        }
        out
    }

    fn digests(chunks: &[&[u8]]) -> Vec<intranet_crypto::Hash> {
        chunks.iter().map(|c| intranet_crypto::hash_bytes(c)).collect()
    }

    #[test]
    fn empty_input_produces_no_chunks() {
        assert!(split(&[], ChunkSpec::default()).is_empty());
    }

    #[test]
    fn small_content_is_a_single_chunk() {
        let spec = ChunkSpec::from_target(16 * 1024);
        let small = data(1_000, 1);
        let chunks = split(&small, spec);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], &small[..]);
    }

    #[test]
    fn chunking_is_deterministic() {
        let spec = ChunkSpec::default();
        let content = data(500_000, 7);
        assert_eq!(digests(&split(&content, spec)), digests(&split(&content, spec)));
    }

    #[test]
    fn chunks_reassemble_to_the_original() {
        let spec = ChunkSpec::default();
        let content = data(500_000, 11);
        let rejoined: Vec<u8> = split(&content, spec).concat();
        assert_eq!(rejoined, content);
    }

    #[test]
    fn an_insert_near_the_start_leaves_most_chunks_untouched() {
        // The property the whole design exists for, and the one fixed-size
        // chunking cannot provide: a single byte inserted near the beginning
        // must not invalidate everything after it.
        let spec = ChunkSpec::default();
        let original = data(500_000, 3);
        let mut edited = original.clone();
        edited.insert(37, 0xAB);

        let before: std::collections::HashSet<_> =
            digests(&split(&original, spec)).into_iter().collect();
        let after = digests(&split(&edited, spec));
        let shared = after.iter().filter(|d| before.contains(d)).count();

        assert!(
            shared as f64 / after.len() as f64 > 0.75,
            "only {shared}/{} chunks survived a one-byte insert",
            after.len()
        );
    }

    #[test]
    fn an_edit_in_the_middle_leaves_both_ends_untouched() {
        let spec = ChunkSpec::default();
        let original = data(500_000, 5);
        let mut edited = original.clone();
        edited[250_000] ^= 0xFF;

        let before: std::collections::HashSet<_> =
            digests(&split(&original, spec)).into_iter().collect();
        let after = digests(&split(&edited, spec));
        let changed = after.iter().filter(|d| !before.contains(d)).count();

        assert!(
            changed <= 2,
            "a single-byte edit should disturb at most the chunks around it, saw {changed}"
        );
    }

    #[test]
    fn appending_does_not_disturb_existing_chunks() {
        let spec = ChunkSpec::default();
        let original = data(300_000, 13);
        let mut extended = original.clone();
        extended.extend_from_slice(&data(50_000, 17));

        let before = digests(&split(&original, spec));
        let after: std::collections::HashSet<_> =
            digests(&split(&extended, spec)).into_iter().collect();

        // Every chunk but the last (which the append may have extended) survives.
        let surviving = before[..before.len() - 1]
            .iter()
            .filter(|d| after.contains(d))
            .count();
        assert_eq!(surviving, before.len() - 1);
    }

    #[test]
    fn chunks_respect_the_configured_bounds() {
        let spec = ChunkSpec::from_target(16 * 1024);
        let content = data(2_000_000, 19);
        let chunks = split(&content, spec);

        assert!(chunks.len() > 1);
        for chunk in &chunks[..chunks.len() - 1] {
            assert!(
                chunk.len() <= spec.max as usize,
                "chunk of {} exceeds max {}",
                chunk.len(),
                spec.max
            );
        }
    }

    #[test]
    fn spec_derivation_brackets_the_target() {
        let spec = ChunkSpec::from_target(32 * 1024);
        assert_eq!(spec.target, 32 * 1024);
        assert!(spec.min < spec.target && spec.target < spec.max);
    }

    #[test]
    fn absurd_targets_are_clamped_rather_than_panicking() {
        let tiny = ChunkSpec::from_target(1);
        assert!(tiny.min > 0 && tiny.min < tiny.max);
        let huge = ChunkSpec::from_target(u32::MAX);
        assert!(huge.max <= ChunkSpec::CEILING);
    }

    #[test]
    fn two_publishers_using_the_same_policy_agree_on_boundaries() {
        // Why the target is network-wide: differing targets silently lose
        // deduplication between otherwise-identical content.
        let policy = NetworkPolicy::conservative_default();
        let content = data(400_000, 23);
        let a = ChunkSpec::from_policy(&policy);
        let b = ChunkSpec::from_policy(&policy);
        assert_eq!(digests(&split(&content, a)), digests(&split(&content, b)));

        let divergent = ChunkSpec::from_target(64 * 1024);
        assert_ne!(
            digests(&split(&content, a)),
            digests(&split(&content, divergent)),
            "differing targets must visibly diverge, which is why this is policy"
        );
    }
}
