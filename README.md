# AIZenflow Quality Control

`AIZenflowQualityControl` is the future app-neutral executable source of truth for reusable Xcode
quality-control commands, schemas, machine policies, adapters, fixtures, bootstrap mechanisms, and
manual workflow definitions.

## Current Status

Stage 5 is complete at its approved scope, and Stage 6A adds the first bounded verifier contract
suite. The user-owned Swift build, focused command matrix, and contained package test run passed on
2026-07-29. The repository now contains one manually triggered, advisory static self-check workflow
and Swift Testing coverage for result aggregation and profile validation. It still contains no
automatic push/PR workflow, hook, application profile, or application integration. Current command
reports, test results, and the static workflow summary are bounded diagnostics, not the versioned
evidence model planned for a later stage.

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
