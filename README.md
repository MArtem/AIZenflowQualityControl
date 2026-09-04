# AIZenflow Quality Control

`AIZenflowQualityControl` is the future app-neutral executable source of truth for reusable Xcode
quality-control commands, schemas, machine policies, adapters, fixtures, bootstrap mechanisms, and
manual workflow definitions.

## Current Status

Stages 0–5 and the bounded Stage 6 verifier blocks through the public failing canary and hard
process timeout are complete.
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
application integration. Stage 9A includes bounded artifact-hashing primitives behind an internal
worker boundary, but production artifact evidence remains blocked until a dedicated OS-backed
immutable-snapshot provider exists; a read-only mount flag alone is not sufficient proof. The
engine does not create or mount privileged snapshots. Its in-memory evidence producer and
package-internal static coordinator require coordinator-owned observations; neither adds a general
workflow evidence producer, cryptographic attestation, or authoritative release proof.
Stage 9C1 adds only `validate-evidence-expectation`: it validates the bounded closed document
envelope and explicitly does not turn a caller-supplied file into trusted evidence or a verdict.
The public `quality static` command now isolates the cooperative scanner in a child process, applies
a 245-second local hard ceiling, dynamically shortens it to preserve the five-minute workflow job
budget, terminates the worker when its authenticated parent exits, bounds captured JSON to 8 MiB,
and validates report/exit consistency before forwarding a result. The internal coordinator converts
only that validated response plus separately observed identity/profile facts into in-memory static
evidence; it accepts no expectation or evidence JSON. Buildable Xcode fixtures remain separate work
and are not claimed by this boundary.
`quality static-evidence` is the narrow public execution boundary for that scanner: it verifies
exact clean Git source/engine checkouts, parent-read profile/policy snapshots, selected toolchain,
worker digest binding, and unchanged checkouts before emitting verifier-checked evidence. It remains
advisory static evidence only; it does not run builds, tests, UI/device checks, reviews, or attest.
`quality build-evidence` is the corresponding narrow boundary for one profile-declared Xcode build.
It authenticates the pinned source and engine checkouts, the running engine `CDHash`, the exact
Git-tracked profile bytes, toolchain, selected scheme/configuration/destination, and permission action
before execution, then observes them again before emitting evidence. A failed build emits `FAIL`
without evidence; missing authority, unstable inputs, unsupported Git index state, supervision
failure, or verification failure emits evidence-free `BLOCKED`. This boundary does not run tests,
UI/device checks, review, archive, signing, upload, or release operations.

The catalog-backed deterministic adapters now include `QC.FORMAT.SWIFTFORMAT`,
`QC.PRIVACY.MANIFEST`, and `QC.CONFIGURATION.SIGNING` in addition to the tracked-secret, TODO
ownership, generated ownership, dependency lock, localization, and resource checks. SwiftFormat
remains a separate manual adapter invocation: it requires an explicitly pinned executable/version
and a tracked configuration, reports its tool/configuration digests, and never changes source files.
Configuration/signing is a separate manual baseline comparison: it reports only explicitly listed
release-sensitive path changes and never claims signing or App Store correctness.

The catalog also includes two app-neutral shipped-source gates: `QC.STATIC.SWIFT_HOT_PATH` blocks
only high-confidence synchronous file/media operations, and `QC.STATIC.SWIFT_CONCURRENCY_ESCAPE`
blocks known Swift concurrency escape hatches (`@unchecked Sendable`, `nonisolated(unsafe)`,
`@preconcurrency`, and `@_unsafeInheritExecutor`). Both scan the clean Git `HEAD`, exclude tests,
fixtures, comments, and documentation, fail closed on malformed or oversized input, and provide no
suppression mechanism. They complement compiler diagnostics; they do not claim that a static scan
proves actor correctness, runtime behavior, or production readiness.

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

## Command Surface

The package has no third-party dependencies and declares a macOS 13 minimum. After the user runs
`swift build`, the bounded command surface is:

```text
swift run quality validate-profile --profile <profile.json>
swift run quality validate-evidence-expectation --expectation <expectation.json>
swift run quality doctor --profile <profile.json> --repository-root <repository>
swift run quality static --profile <profile.json> --policy <policy.json> --repository-root <repository>
swift run quality static --profile <profile.json> --policy <policy.json> --repository-root <repository> --scope explicit-source-paths
quality mode-plan --profile <profile.json> --mode <static|build|build-and-tests|full>
quality mode-execute --profile <profile.json> --mode <static|build|build-and-tests|full> --policy <policy.json> --repository-root <source-repository> --engine-repository-root <engine-repository> --snapshot-root <private-writable-directory> --source-repository <owner/name> --expected-source-revision <40-hex> --expected-engine-revision <40-hex> --expected-engine-cdhash <40-hex> [--scheme <scheme> --configuration <configuration> --destination <destination> --execution-context <local|github>]
quality static-evidence --profile <profile.json> --policy <policy.json> --repository-root <source-repository> --engine-repository-root <engine-repository> --snapshot-root <private-writable-directory> --source-repository <owner/name> --expected-source-revision <40-hex> --expected-engine-revision <40-hex> --expected-engine-cdhash <40-hex>
quality build-evidence --profile <profile.json> --repository-root <source-repository> --engine-repository-root <engine-repository> --source-repository <owner/name> --expected-source-revision <40-hex> --expected-engine-revision <40-hex> --expected-engine-cdhash <40-hex> --scheme <scheme> --configuration <configuration> --destination <destination> --execution-context <local|github>
quality aggregate-evidence --evidence <receipt.json[,receipt.json...]> --expectation <trusted-expectation.json>
```

- `validate-profile` decodes profile schema versions 1 and 2. Version 1 preserves absolute sandbox
  paths for compatibility; version 2 requires normalized repository-relative sandbox paths so the
  same exact Git-tracked profile bytes resolve portably on local Macs and GitHub runners. Project,
  source, and version 2 sandbox traversal remains forbidden.
- `validate-evidence-expectation` validates only a bounded, closed document envelope; the caller-
  supplied document remains untrusted and does not produce an evidence verdict.
- `doctor` verifies configured repository, project/workspace, source, and sandbox paths without
  running builds or tests. For schema version 2 it resolves the sandbox from the supplied repository
  root and rejects symbolic-link escape before Xcode graph discovery.
- `mode-plan` expands one user-selected manual mode into stable, permission-aware steps. It is a
  pre-execution plan only; `NOT_RUN_BY_USER_DECISION`, `SKIPPED`, and `BLOCKED` are never runtime
  PASS evidence.
- `mode-execute` runs the existing authenticated `static-evidence` boundary and, for modes beyond
  `static`, the authenticated `build-evidence` boundary in order. A failed or blocked prerequisite
  skips later steps. Test, snapshot-test, UI-test, archive/signing, feature-flag, privacy,
  observability, and platform-capability steps are emitted as explicit
  `NOT_RUN_BY_USER_DECISION`, `NOT_APPLICABLE`, or `BLOCKED` until their dedicated evidence
  boundaries exist. Child evidence remains attached to each step; the mode envelope never infers
  composite evidence or a trusted expectation.
- `static` performs only deterministic file-size, forbidden-artifact, source-boundary, and symlink
  checks from explicit profile and policy inputs. Schema version 2 remains blocked by default until
  Xcode build-graph membership is authenticated. The explicit `--scope explicit-source-paths`
  variant scans only the profile's declared source paths and states that it does not assert Xcode
  target membership; it cannot produce build or static-evidence proof.
- `static-evidence` scans the asserted Git-tree manifest directly; it never scans mutable
  source-worktree bytes or projects Git paths onto a filesystem. `PASS` includes evidence and an empty-issue verifier result;
  the caller must build the pinned engine first and supply that exact executable's `codesign`
  `CDHash`; preflight, identity, snapshot, process, or checkout failures are evidence-free `BLOCKED`.
- `build-evidence` runs exactly one profile-declared Xcode build through the bounded supervisor.
  The profile must be a regular, non-symlink Git-tracked file inside the clean source checkout and
  its working bytes must equal the expected source revision. Source and engine checkouts containing
  submodules, sparse/skip-worktree entries, or assume-unchanged entries are rejected because the
  current exact-SHA boundary does not model them. `local` records `localBuildExecution`; `github`
  records `githubExecution` and is prohibited when the profile sets GitHub execution to `off`.
  A schema version 2 sandbox is resolved only from the authenticated source checkout root; its
  physical machine path is validated at execution time but is intentionally not copied into the
  portable profile identity.
  Xcode and `xcresulttool` run with a fixed minimal environment, so undeclared caller build-setting,
  linker, toolchain, and xcconfig overrides cannot silently change a command with the same identity.
  The command invocation is only the engine's action-authorization input: it cannot authenticate a
  human operator, so agents and automation must still obtain the separate approval required by the
  governing reusable rules before invoking it.
- `aggregate-evidence` loads bounded, untrusted evidence receipts and a complete caller-owned
  expectation from `schemas/trusted-evidence-expectation.schema.json`, then joins them only through
  `EvidenceVerifier.aggregate`. Empty, duplicate, oversized, malformed, identity-mismatched, or
  unverifiable inputs produce evidence-free `BLOCKED`; a valid failing gate produces a non-PASS
  result with its verified evidence preserved for diagnosis. The command does not infer expected
  commands, permissions, gates, or identities from the receipts.

Every command emits structured JSON. Execution boundaries use `PASS`, `FAIL`, or `BLOCKED`; manual
mode orchestration additionally reports `NOT_APPLICABLE`, `NOT_RUN_BY_USER_DECISION`, and `SKIPPED`.
Malformed,
unreadable, unsupported, missing, or boundary-unsafe inputs never produce `PASS`.
The public result contract is `schemas/build-evidence-result.schema.json`; only its `PASS` branch
permits non-null evidence and verification.

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
  1,024-scalar limit before failing closed. Evidence documents are capped at 8 MiB and top-level
  collections at 64 entries.
- `SKIPPED` aggregates to `BLOCKED`, `NOT_RUN_BY_USER_DECISION` to `NEEDS_OWNER_DECISION`, and a
  claimed verdict inconsistent with the gate set becomes `BYPASSED`.
- `READY_WITH_ACCEPTED_RISK` is represented but is not automatically derived; ownership and
  exception governance remain future stages.
- `EvidenceVerifier.aggregate` is the bounded in-memory join for mode-level evidence: all inputs
  must share one source/engine/profile/toolchain/permission identity, duplicate or oversized input
  is rejected, and the merged result is re-verified against the caller-owned complete expectation.
  Any aggregate verification issue returns no evidence rather than a partial success.

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
