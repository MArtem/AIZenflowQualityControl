# Threat Model

## Scope

This initial threat model covers the future quality-control engine, its machine inputs and outputs,
bootstrap/migration path, manually triggered workflows, and trust relationship with adopting Xcode
projects. Stage 4 contains no executable implementation.

## Assets To Protect

- integrity of gate results and overall verdicts;
- exact-source and exact-version evidence provenance;
- user-controlled permissions for tests, UI/device work, performance work, and external review;
- source code, credentials, signing material, private data, and logs;
- project-owned configuration and exceptions;
- the ability to roll back engine or adoption changes safely.

## Trust Boundaries

- human governance in Documentation Vault;
- versioned engine and machine policy in this repository;
- project-controlled profiles and local exceptions;
- local developer environment and Xcode toolchain;
- GitHub-hosted workflow environment and third-party Actions;
- generated artifacts, logs, and evidence consumed by humans or automation.

All project input, repository content, profiles, environment variables, external tool output, cached
artifacts, and uploaded evidence are untrusted until validated for their exact scope and version.

## Primary Threats And Required Controls

| Threat | Required control direction |
| --- | --- |
| Forged, stale, or cross-SHA evidence | Bind evidence to source, engine/profile versions, command, toolchain, permission set, and artifact hashes |
| Skipped, blocked, denied, or missing checks shown as success | Use explicit non-PASS statuses and fail closed during aggregation |
| Project-specific assumptions entering reusable defaults | Validate explicit profiles; prohibit app names, schemes, destinations, test paths, and user paths in defaults |
| Permission bypass for test writing or execution | Model permissions independently and require explicit authorization at the execution boundary |
| Malicious repository paths, symlinks, or command arguments | Canonicalize and bound paths; avoid shell interpolation; test traversal and injection cases |
| Secret or private-data leakage through logs/artifacts | Exclude raw command argv from evidence, bind commands by SHA-256 identity, redact other values, minimize retention, bound collection, and never upload source or secrets as telemetry |
| Dependency or workflow supply-chain compromise | Pin dependencies and Actions, use least privilege, verify artifacts, and avoid unreviewed `latest` inputs |
| Bootstrap overwriting project files | Inventory, dry-run, conflict report, explicit apply, post-check, and reversible rollback |
| Weakening policy through local flags or exceptions | Separate project facts from immutable engine floors; make exceptions exact, owned, expiring, and visible |
| Resource exhaustion or hanging tools | Enforce time, output, process, and artifact bounds; report timeout as blocked/failure, never PASS |

## Explicit Non-Claims

This scaffold is not a security control, verifier, sandbox, or evidence producer. Passing future
static gates will not prove runtime correctness, accessibility, migration safety, privacy,
performance, or product intent.

## Validation Required Before Trust

Before the engine can be called reliable, separately approved work must add positive, negative,
malformed, and adversarial fixtures demonstrating that known bypasses and deliberately broken inputs
cannot produce normal `PASS`.

## Review Trigger

Review this model when an executable command, schema, adapter, dependency, bootstrap path, workflow,
consumer, evidence type, or external service is introduced.
