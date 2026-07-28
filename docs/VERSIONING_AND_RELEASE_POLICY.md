# Versioning And Release Policy

## Purpose

Define how the future executable engine and machine contracts will evolve without silently changing
consumer behavior or evidence meaning.

## Versioning

- Use Semantic Versioning for released engine behavior.
- Treat `0.x` releases as pre-stable; compatibility may change, but every breaking change must be
  explicit and accompanied by a migration note.
- Version schemas and policy contracts independently when consumers must distinguish their formats.
- Stable identifiers for gates, findings, statuses, and verdicts must not be reassigned to different
  meanings.
- A consumer must reject unsupported major versions rather than silently interpreting them.

## Release Gate

No release exists in Stage 4. A future release requires:

1. explicit user authorization;
2. verifier self-tests and adversarial fixtures appropriate to the released behavior;
3. documented compatibility and migration impact;
4. exact source revision and reproducible build information;
5. checksums for distributed artifacts;
6. a rollback path and recorded residual risk.

The first stable release must use a signed tag and published checksums. Repository history, a branch,
or an unreviewed artifact is not a stable release merely because it has a version-like name.

## Rollback

Consumers must pin an approved engine release. Rollback means returning to a previously verified
version and its compatible profile/schema set; it must not rewrite evidence from the failed version
or relabel bypassed results as normal success.

## Review Trigger

Review this policy when compatibility, artifact distribution, signing, release authority, or
consumer pinning changes.
