This project implements a distributed intranet protocol. Full architecture and design
decisions are specified in specs/01-core-protocol-spec.md through specs/06-reference-test-harness-spec.md.
Read all six before making architectural decisions — they're interdependent and
cross-reference each other extensively. Treat them as authoritative; if an implementation
choice isn't covered by them, flag it rather than guessing.

Several spec sections exist specifically to correct an earlier, subtly wrong version of
themselves — those corrections are usually load-bearing, so prefer the current text over
what an older summary or comment might imply.

## Implementation

Rust workspace, one crate per layer, in `crates/`. See README.md for the map and for what
is and is not verified. Every layer is implemented; two things are deliberately not done:
the Docker NAT scenarios have never been executed, and the app execution sandbox is not
built or stubbed.

- `cargo test --workspace` and `cargo clippy --workspace --all-targets` must both stay clean.
- Decisions the specs left open are marked `Flagged` in a comment at the point of the
  decision. Grep for it rather than re-deriving them.
- Determinism is load-bearing in several places (entry hashes, HRW placement, quorum
  outcomes, pointer tie-breaks). Canonical encoding is hand-written per type and placement
  arithmetic is integer on purpose; don't replace either with a derive or floating point.
- Local-only signals (`reliability_signal`) must never reach a cross-node computation.
  The type signatures enforce this — keep it that way.
- Key material types deliberately implement no `Debug` or serialization. Use the
  `fingerprint()` methods for logging and tests rather than deriving `Debug`.
