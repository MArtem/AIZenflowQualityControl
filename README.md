# AIZenflow Quality Control

`AIZenflowQualityControl` is the future app-neutral executable source of truth for reusable Xcode
quality-control commands, schemas, machine policies, adapters, fixtures, bootstrap mechanisms, and
manual workflow definitions.

## Current Status

Stage 4 repository scaffold only. No executable verifier, test suite, GitHub Actions workflow,
project profile, hook, or application integration exists yet. Nothing in this repository currently
produces verification evidence or a `PASS` verdict.

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
- `tests/` — future verifier self-tests, added only with explicit permission.
- `bootstrap/` — future dry-run adoption and reversible migration tooling.
- `workflows/` — future manually triggered, advisory workflow definitions.
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

See `docs/OWNERSHIP_AND_SOURCE_OF_TRUTH.md`, `docs/VERSIONING_AND_RELEASE_POLICY.md`, and
`docs/THREAT_MODEL.md` before adding executable behavior.
