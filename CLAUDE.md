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
is and is not verified. Every layer is implemented. The Docker NAT scenarios have now been
executed and 4 of 5 pass; hole-punching (scenario 3) does not work, so tier 2 is unverified.
The app execution sandbox is still not built or stubbed.

Governance log propagation is wired: a pull-based request/response sync protocol over
libp2p (`intranet-transport::sync`, `intranet-governance::wire`), chosen because §2.7
allows the log no new transport primitive beyond §5.1 and because a broadcast has no
history — entries appended during a partition would never reach the other side. A heal
is a reconnect and a reconnect is a sync, so there is no separate catch-up path.
Entries must be delivered ancestors-first (`GovernanceLog::ancestors_first`), since
`insert` refuses an entry whose parent it has not seen and a dropped entry is
indistinguishable from one never sent. The wire codec is hand-written and deliberately
untrusted: every decoded entry is re-verified against its author's signature, so a codec
bug is a rejected entry rather than silent divergence.

- `cargo test --workspace` and `cargo clippy --workspace --all-targets` must both stay clean.
  Note that clippy is absent from some environments (a source-tarball rustc with no rustup);
  a run that skips it has checked only half the gate, so say so rather than reporting clean.
- Decisions the specs left open are marked `Flagged` in a comment at the point of the
  decision. Grep for it rather than re-deriving them.
- Determinism is load-bearing in several places (entry hashes, HRW placement, quorum
  outcomes, pointer tie-breaks). Canonical encoding is hand-written per type and placement
  arithmetic is integer on purpose; don't replace either with a derive or floating point.
- Local-only signals (`reliability_signal`) must never reach a cross-node computation.
  The type signatures enforce this — keep it that way.
- Key material types deliberately implement no `Debug` or serialization. Use the
  `fingerprint()` methods for logging and tests rather than deriving `Debug`.
