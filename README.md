# AIZenflow Quality Control

`AIZenflowQualityControl` is the future app-neutral executable source of truth for reusable Xcode
quality-control commands, schemas, machine policies, adapters, fixtures, bootstrap mechanisms, and
manual workflow definitions.

## Current Status

Stages 0–5 and the bounded Stage 6 verifier blocks through the public failing canary are complete.
The repository now also contains the Stage 7 permission evaluator and the Stage 9A versioned
evidence contract foundation. The engine can distinguish profile authorization, explicit user
authorization, and prohibited actions independently for test creation, test modification, local
test execution, manual GitHub execution, UI tests, Simulator/device work, and performance work.

Evidence schema version 1 represents exact source/engine/profile identity, toolchain, permission
snapshot, terminal command outcomes with complete permission-action sets, gate results, test counts,
review revision, artifact hashes, residual risk, and an advisory verdict. Verification compares
untrusted evidence with caller-supplied trusted expectations and returns `BYPASSED` for stale
identity, changed permissions, missing/extra commands or gates, forged artifact sets, stale review
SHA, invalid authorization, or a false claimed verdict.

The repository still contains no automatic push/PR workflow, hook, application profile, or
application integration. Stage 9A does not add an evidence CLI/loader, cryptographic attestation,
artifact hashing, or workflow evidence producer; those execution-boundary integrations remain
separate work and no current diagnostic is promoted to authoritative release proof.
Stage 6 also still requires a hard process timeout for already blocked work and buildable Xcode
fixtures; neither is claimed by this contract-only slice.

## Authority Boundary

- `MArtem/AIZenflowDocumentation` owns reusable human policy, intent, routing, and interpretation.
- This repository will own versioned executable mechanisms and machine-readable contracts.
- Each adopting project owns its facts, selected permissions, local exceptions, and thin launcher.

Human policy remains authoritative when executable behavior is absent or ambiguous. Machine output
must identify the exact source revision, engine/profile version, permissions, commands executed,
results, and residual risk.

## Repository Layout

- `engine/` — future command-line engine and result aggregation.
- `schemas/` — versioned machine-readable contracts.
- `policies/` — executable policy definitions with stable identifiers.
- `adapters/` — typed integrations for supported project and toolchain surfaces.
- `fixtures/` — synthetic positive, negative, and adversarial inputs.
- `tests/` — active verifier self-tests, expanded only with explicit permission.
- `bootstrap/` — future dry-run adoption and reversible migration tooling.
- `.github/workflows/` — active GitHub workflow definitions.
- `workflows/` — workflow policy, scope, and operator instructions.
- `docs/` — repository ownership, release policy, and threat model.

## Hard Rules

- No application name, scheme, bundle identifier, destination, test directory, local user path, or
  product exception may become a reusable default.
- Missing, stale, malformed, skipped, denied, bypassed, or forgeable evidence is never normal
  `PASS` evidence.
- Test creation, modification, and execution remain separate user-controlled permissions.
- Workflows remain manual, advisory, zero-additional-cost, and free of paid AI API calls unless the
  user explicitly changes the governing policy.
- Branch protection, hooks, application profiles, and application integration are outside this
  scaffold.

## Stage 5 Commands

The package has no third-party dependencies and declares a macOS 13 minimum. After the user runs
`swift build`, the bounded command surface is:

```text
swift run quality validate-profile --profile <profile.json>
swift run quality doctor --profile <profile.json> --repository-root <repository>
swift run quality static --profile <profile.json> --policy <policy.json> --repository-root <repository>
```

- `validate-profile` decodes schema version 1 and rejects missing, absolute, duplicate, or
  traversal-bearing project/source paths.
- `doctor` verifies configured repository, project/workspace, source, and sandbox paths without
  running Xcode, builds, or tests.
- `static` performs only deterministic file-size, forbidden-artifact, source-boundary, and symlink
  checks from explicit profile and policy inputs.

Every command emits structured JSON and uses `PASS`, `FAIL`, or `BLOCKED`. Malformed,
unreadable, unsupported, missing, or boundary-unsafe inputs never produce `PASS`.

## Permission And Evidence Contracts

- `PermissionEvaluator` maps every independent permission-controlled action to
  `AUTHORIZED_BY_PROFILE`, `USER_AUTHORIZATION_REQUIRED`, or `PROHIBITED`.
- User authorization is trusted only when supplied out of band in `EvidenceExpectation`; a
  self-asserted `USER` value inside evidence is insufficient.
- Expected command SHA-256 identities, exit codes, and complete permission-action sets, exact
  gate-to-command bindings, trusted statuses and messages for every gate, source and engine
  revisions, profile/toolchain facts, permission snapshot, test counts, and artifact hashes are
  supplied by the verifier caller rather than copied from the evidence under review. Raw argv is
  not serialized into evidence.
- Every recorded command has a bounded terminal exit code. Every action in a multi-permission
  command is evaluated independently, every command is accounted for by a gate, and gates must
  carry the same complete action set.
- A command set may be empty only when no gate references a command, allowing truthful
  pre-execution `BLOCKED` and `NOT_RUN_BY_USER_DECISION` evidence.
- Untrusted evidence JSON enters through bounded `EvidenceLoader`; the complete evidence model is
  encode-only so callers cannot bypass duplicate-key, unknown-property, or explicit-null checks by
  decoding it directly. String validation examines at most one scalar beyond the configured
  4,096-scalar limit before failing closed.
- `SKIPPED` aggregates to `BLOCKED`, `NOT_RUN_BY_USER_DECISION` to `NEEDS_OWNER_DECISION`, and a
  claimed verdict inconsistent with the gate set becomes `BYPASSED`.
- `READY_WITH_ACCEPTED_RISK` is represented but is not automatically derived; ownership and
  exception governance remain future stages.

The neutral fixtures under `fixtures/profiles/` demonstrate a structurally valid profile and a
deliberately invalid traversal/cache-boundary profile. They are not a test suite.

## Stage 5 Verification

The user ran the complete focused matrix with SwiftPM caches and scratch output contained inside
`.quality-control-cache/`:

- Debug `swift build`: PASS, exit `0`;
- `validate-profile` with the ignored neutral runtime profile: `PASS`, exit `0`;
- `validate-profile` with `invalid-path-traversal.json`: `FAIL`, exit `1`, reporting both
  traversal paths and the cache-outside-sandbox violation;
- `doctor` with the synthetic local fixture: `PASS`, exit `0`;
- `static` with the synthetic local fixture: `PASS`, exit `0`, scanning one regular file;
- `doctor` with a missing repository root: `BLOCKED`, exit `2`.

The synthetic `.xcodeproj` fixture proves only the current path, boundary, profile, and static-scan
contracts. It is intentionally not a buildable Xcode project and provides no Xcode graph, scheme,
build, test, application, security, or production-readiness evidence.

See `docs/OWNERSHIP_AND_SOURCE_OF_TRUTH.md`, `docs/VERSIONING_AND_RELEASE_POLICY.md`, and
`docs/THREAT_MODEL.md` before adding executable behavior.
