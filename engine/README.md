# Engine

This directory owns the dependency-free Swift quality-control engine and CLI. The current CLI is
limited to profile validation, doctor checks, and deterministic static scanning; it does not run
Xcode, tests, Simulator/device work, performance tools, or external review.

`QualityCore` also owns the independent permission evaluator, the Stage 9A in-memory evidence
contracts, and bounded artifact-hashing primitives behind an internal worker boundary. Production
artifact evidence remains blocked until a dedicated OS-backed immutable-snapshot provider exists:
a read-only mount flag alone does not prove that a remote server or another mount cannot alter the
data. The engine does not create or mount privileged snapshots. The contracts fail closed against
caller-supplied trusted expectations, but no evidence producer or
cryptographic attestation exists yet. Future execution surfaces must consult the permission
evaluator before acting and must not infer user authorization from untrusted evidence.
`quality validate-evidence-expectation` is a structural validator only; its input remains
untrusted and cannot produce an evidence verdict.
