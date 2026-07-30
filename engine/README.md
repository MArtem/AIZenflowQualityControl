# Engine

This directory owns the dependency-free Swift quality-control engine and CLI. The current CLI is
limited to profile validation, doctor checks, and deterministic static scanning; it does not run
Xcode, tests, Simulator/device work, performance tools, or external review.

`QualityCore` also owns the independent permission evaluator and the Stage 9A in-memory evidence
contracts. Those contracts fail closed against caller-supplied trusted expectations, but no evidence
CLI loader, evidence producer, artifact hasher, or cryptographic attestation exists yet. Future
execution surfaces must consult the permission evaluator before acting and must not infer user
authorization from untrusted evidence.
