//! Appending to an object without re-chunking the rest — Storage Spec §1.3.
//!
//! **The claim under test is byte-identity, not similarity.** An incremental
//! encoding that produced *nearly* the same boundaries would be worse than none:
//! two nodes holding the same content would address it differently, and content
//! addressing would stop meaning anything. So every test here compares against
//! `encode` over the same total plaintext and expects the manifest, the chunk
//! ids and the ciphertext to match exactly.

use intranet_storage::{AppendOnlyObject, ChunkSpec, Dek, encode};

/// Deterministic pseudo-random bytes, so boundaries are content-driven rather
/// than an artefact of repetitive input.
fn data(len: usize, seed: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = seed;
    for _ in 0..len {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.push((x >> 16) as u8);
    }
    out
}

fn dek() -> Dek {
    Dek::from_bytes([7u8; 32])
}

/// Appends `pieces` one at a time and asserts the result matches a whole encode
/// at **every** step, not only at the end.
fn agrees_at_every_step(pieces: &[Vec<u8>], spec: ChunkSpec) {
    let dek = dek();
    let mut incremental = AppendOnlyObject::new(spec);
    let mut whole = Vec::new();

    for (step, piece) in pieces.iter().enumerate() {
        whole.extend_from_slice(piece);
        let appended = incremental.extend(piece, &dek).clone();
        let encoded = encode(&whole, &dek, spec);

        assert_eq!(
            appended.manifest.chunks, encoded.manifest.chunks,
            "chunk ids diverged at step {step} ({} bytes)",
            whole.len()
        );
        assert_eq!(
            appended.manifest.plaintext_len, encoded.manifest.plaintext_len,
            "declared length diverged at step {step}"
        );
        assert_eq!(
            appended.chunks, encoded.chunks,
            "ciphertext diverged at step {step} ({} bytes)",
            whole.len()
        );
    }
}

#[test]
fn one_byte_at_a_time_matches_a_whole_encode() {
    // The pathological shape: every append is smaller than any chunk, so the
    // tail is re-cut constantly and the settled prefix must never move.
    let spec = ChunkSpec::from_target(1024);
    let source = data(6_000, 31);
    let pieces: Vec<Vec<u8>> = source.chunks(1).map(<[u8]>::to_vec).collect();
    agrees_at_every_step(&pieces, spec);
}

#[test]
fn growing_across_the_small_content_exemption_matches_a_whole_encode() {
    // The transition that is easy to get wrong. Below the target an object is
    // one chunk without the rolling hash running at all; above it, every
    // boundary is content-defined. An incremental encoder that asked the
    // exemption about the *region* rather than the *object* would answer "still
    // small" forever and never chunk anything.
    let spec = ChunkSpec::from_target(2048);
    let pieces = vec![
        data(100, 41),   // far below the target
        data(1_800, 42), // still below
        data(500, 43),   // crosses it
        data(9_000, 44), // well past
    ];
    agrees_at_every_step(&pieces, spec);
}

#[test]
fn appends_of_wildly_different_sizes_match_a_whole_encode() {
    let spec = ChunkSpec::from_target(4096);
    let pieces = vec![
        data(1, 51),
        data(70_000, 52),
        data(3, 53),
        data(20_000, 54),
        data(1, 55),
        data(1, 56),
        data(200_000, 57),
    ];
    agrees_at_every_step(&pieces, spec);
}

#[test]
fn an_empty_append_changes_nothing() {
    let spec = ChunkSpec::default();
    let dek = dek();
    let mut object = AppendOnlyObject::new(spec);
    object.extend(&data(50_000, 61), &dek);
    let before = object.object().clone();
    let after = object.extend(&[], &dek).clone();
    assert_eq!(before.manifest.chunks, after.manifest.chunks);
    assert_eq!(before.chunks, after.chunks);
}

#[test]
fn an_object_nothing_was_appended_to_is_empty_rather_than_one_empty_chunk() {
    // The same distinction `split` draws: an empty object and an object of one
    // empty chunk must not be confusable.
    let object = AppendOnlyObject::new(ChunkSpec::default());
    assert!(object.is_empty());
    assert_eq!(object.len(), 0);
    assert!(object.object().manifest.chunks.is_empty());
    assert_eq!(
        object.object().manifest.chunks,
        encode(&[], &dek(), ChunkSpec::default()).manifest.chunks
    );
}

#[test]
fn the_settled_chunks_are_never_re_sealed() {
    // The property the saving rests on, asserted directly rather than inferred
    // from a timing: a chunk that is already settled must come out of an append
    // as the *same bytes*, not as bytes that happen to be equal because they
    // were recomputed identically.
    //
    // Checked by pointer identity of the ciphertext buffers: a re-seal would
    // allocate, so an unchanged allocation is evidence the work did not happen.
    let spec = ChunkSpec::from_target(1024);
    let dek = dek();
    let mut object = AppendOnlyObject::new(spec);
    object.extend(&data(40_000, 71), &dek);

    let settled = object.object().chunks.len() - 1;
    let addresses: Vec<*const u8> = object.object().chunks[..settled]
        .iter()
        .map(|(_, bytes)| bytes.as_ptr())
        .collect();

    object.extend(&data(5_000, 72), &dek);

    let after: Vec<*const u8> = object.object().chunks[..settled]
        .iter()
        .map(|(_, bytes)| bytes.as_ptr())
        .collect();
    assert_eq!(
        addresses, after,
        "settled chunks were reallocated, so they were re-sealed"
    );
}

#[test]
fn a_sub_target_region_is_still_cut_once_anything_is_settled() {
    // **The mistake this is written against**: asking the small-content
    // exemption about the *region* being re-cut rather than about the whole
    // object. Once a boundary is settled the object is past the target forever,
    // and a region below it must still be chunked — content-defined chunking
    // cuts below the target too, just less often, because FastCDC normalises
    // with a stricter mask down there.
    //
    // "Less often" is why this needs constructing rather than hoping: the first
    // version of these tests exercised thousands of appends and never once
    // landed on a sub-target region that cut, so the broken version passed the
    // whole suite. Searched deterministically here, and the search failing is
    // itself a failure — a test that quietly found nothing would be worse than
    // no test.
    let spec = ChunkSpec::from_target(1024);
    let dek = dek();
    let mut exercised = false;

    for seed in 1..200u32 {
        let mut incremental = AppendOnlyObject::new(spec);
        let mut whole = Vec::new();

        // Past the target first, so something is settled and the exemption must
        // never be reached again.
        let opening = data(8_000, seed);
        whole.extend_from_slice(&opening);
        incremental.extend(&opening, &dek);

        for step in 0..40u32 {
            let piece = data(37, seed.wrapping_mul(1_000).wrapping_add(step));
            if incremental.tail_len() + piece.len() <= spec.target as usize {
                exercised = true;
            }
            whole.extend_from_slice(&piece);
            let appended = incremental.extend(&piece, &dek).clone();
            let encoded = encode(&whole, &dek, spec);
            assert_eq!(
                appended.manifest.chunks, encoded.manifest.chunks,
                "diverged at seed {seed} step {step} with {} bytes",
                whole.len()
            );
            assert_eq!(appended.chunks, encoded.chunks);
        }
    }

    assert!(
        exercised,
        "no append ever produced a region below the target, so the branch this \
         test exists for was never run"
    );
}
