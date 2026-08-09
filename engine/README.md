# Engine

This directory owns the dependency-free Swift quality-control engine and CLI. The current CLI is
limited to profile validation, doctor checks, deterministic static scanning, and bounded static
evidence execution; it does not run
Xcode, tests, Simulator/device work, performance tools, or external review.

`QualityCore` also owns the independent permission evaluator, Stage 9A in-memory evidence contracts,
and bounded artifact-hashing primitives behind an internal worker boundary. Production artifact
evidence remains blocked until a dedicated OS-backed immutable-snapshot provider exists: a read-only
mount flag alone does not prove that a remote server or another mount cannot alter the data. The
engine does not create or mount privileged snapshots. The public in-memory `EvidenceProducer` and
package-internal static coordinator both fail closed. `quality static-evidence` is the narrow public
boundary for one exact static execution: it binds engine build provenance, source/engine checkout
identities and revisions, descriptor-pinned profile/policy bytes, observed toolchain output, and an
authenticated worker scan of a private Git-tree materialization before coordinator/verifier can emit
evidence. It is not a general workflow producer and does not prove runtime or review outcomes; no
cryptographic attestation exists. Future execution surfaces must consult the permission evaluator
before acting and must not infer user authorization from untrusted evidence.
`quality validate-evidence-expectation` is a structural validator only; its input remains
untrusted and cannot produce an evidence verdict.
