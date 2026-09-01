# Schemas

This directory will own versioned machine-readable contracts such as project profiles, permission
policies, findings, evidence, and verdicts.

Each future schema requires an explicit version, stable identifiers, validation behavior, and
compatibility policy. A malformed or unsupported schema must fail closed rather than produce normal
success evidence.

The current profile and static-policy loaders accept UTF-8 JSON documents of at most 1,000,000
bytes, require regular-file inputs read through EOF, reject duplicate object keys before Foundation
decoding, and cap JSON nesting at 64 containers. Project profile schema version 1 allows at most
256 non-overlapping explicit source paths, validation output is capped at 256 issues, and each
static-policy directory/suffix list is capped at 256 unique entries.

`quality-evidence.schema.json` defines evidence schema version 1. It is a closed, bounded contract
for exact source/engine/profile identity, toolchain and permissions, SHA-256 command identities,
explicit gate statuses, optional test counts and review SHA, artifact hashes, residual risks, and
the claimed advisory verdict. Raw command arguments are excluded from the evidence model. Runtime
verification additionally requires trusted out-of-band expectations for the complete
command/action sets, terminal command outcomes, exact gate-to-command bindings, trusted status and
message for every gate, user-authorized actions, test-count gate, and artifact hashes.

`evidence-expectation.schema.json` has the same closed transport envelope as the untrusted
production context. `quality validate-evidence-expectation` checks only that envelope; validation
does not grant trust, construct an `EvidenceExpectation`, or produce an advisory verdict.
The schema requires `commandID` for `PASS`/`FAIL` and forbids it for explicit non-executed states.
Actionless commands require `NOT_REQUIRED`; commands with controlled actions require `PROFILE` or
`USER`. An empty command set is valid only when runtime gate accounting finds no command reference,
so pre-execution blocked or user-declined outcomes remain representable. Command, gate, and artifact
arrays reject identical duplicate objects in the schema; runtime verification additionally enforces
unique IDs or paths when entries differ. Artifact paths use the same non-empty relative-segment
rules in schema and runtime. The schema is not yet wired to a CLI evidence producer. Public
`EvidenceLoader` decodes bare evidence and `EvidenceReceiptLoader` extracts nested evidence from
the public execution envelope; both reject oversized input,
duplicate object keys, unknown object properties, and explicit null optionals. `QualityEvidence`
remains encode-only. Evidence documents are capped at 8 MiB, top-level collections at 64 entries,
and bounded strings at 1,024 Unicode scalars. Runtime and schema share an explicit stable whitespace
set, including U+200B, and the schema's conservative worst-case escaped-string budget remains below
the loader cap. Residual-risk entries are unique in both layers.

`static-evidence-result.schema.json` defines the versioned closed public envelope for
`quality static-evidence`. It contains the normalized static report and includes evidence plus
verification together only after the execution boundary's coordinator/verifier path succeeds. A
`PASS` result therefore requires `READY` evidence with exactly one successful `static` command and
one bound `QC.STATIC` PASS gate, a `READY` verification with zero issues, and a matching `PASS`
report. Evidence-free boundary failures remain `BLOCKED` and do not imply that a
build, tests, UI/device check, review, or attestation happened.

`trusted-evidence-expectation.schema.json` is the explicit caller-owned expectation format for
mode-level aggregation. It carries the complete identity, permission, command, gate, test-count,
review, artifact, and residual-risk expectations; it is not inferred from evidence. The public
`quality aggregate-evidence` command loads this format together with up to 64 evidence receipts and
emits the closed `aggregate-evidence-result.schema.json` envelope. Invalid or unverifiable inputs
remain evidence-free `BLOCKED`.

`mode-plan-result.schema.json` defines the deterministic pre-execution plan emitted by
`quality mode-plan`. It expands `static`, `build`, `build-and-tests`, and `full` into stable step
IDs while preserving applicability and permission status. A mode plan is not runtime evidence:
`NOT_RUN_BY_USER_DECISION`, `SKIPPED`, and `BLOCKED` never become `PASS`; the actual execution
boundaries must produce separately authenticated evidence.

`deterministic-check-result.schema.json` defines catalog-backed adapter results. It binds the check
report to a lowercase Git `HEAD` revision and permits the bounded `QC.SECRETS.TRACKED`,
`QC.TODO.OWNER`, `QC.GENERATED.OWNERSHIP`, `QC.DEPENDENCY.LOCK_DRIFT`,
`QC.LOCALIZATION.CATALOG`, and `QC.RESOURCES.ASSETS` finding shapes. Adapter unavailability is
represented as `BLOCKED`, not a successful empty scan.

`generated-files-manifest.schema.json` defines the transport shape for the tracked generated-file
ownership manifest. Runtime validation additionally enforces unique normalized paths, regular Git
tree objects, UTF-8 content, exact SHA-256 bytes, one matching marker, and the immutable aggregate
limits; schema-valid input alone is not ownership evidence.

`deterministic-check-result.schema.json` also permits `QC.DEPENDENCY.LOCK_DRIFT`. The adapter reads
only committed Git `HEAD`, validates supported `Package.resolved` shapes and immutable revisions,
and compares external SwiftPM/Xcode package declarations with resolved pins. Missing locks for
external declarations and unmatched pins are `FAIL`; malformed, unsupported, oversized, or
non-immutable lock inputs are `BLOCKED`.

The same schema permits `QC.LOCALIZATION.CATALOG`. Its bounded findings cover legacy and string
catalog resource validation; malformed or unsupported resources are represented as `BLOCKED`, while
key parity and fallback coverage findings are `FAIL`.

The same schema permits `QC.RESOURCES.ASSETS`. Its bounded findings cover Xcode asset-catalog
metadata, safe filename ownership, high-confidence literal resource references, and forbidden
compiled resource outputs. Malformed, unsupported, oversized, traversal, or symlink inputs are
`BLOCKED`; missing, duplicate, orphan, or forbidden resources are `FAIL`.

`mode-execution-result.schema.json` defines the bounded envelope emitted by `quality mode-execute`.
It preserves each child boundary report, evidence, and verification result in execution order.
The envelope never infers a composite evidence claim; callers needing one must supply an explicit
trusted expectation to `quality aggregate-evidence`. Missing test, UI, archive/signing,
feature-flag, or privacy boundaries remain explicit `NOT_RUN_BY_USER_DECISION`,
`NOT_APPLICABLE`, or `BLOCKED` steps.
