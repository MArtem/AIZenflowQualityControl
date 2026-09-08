# Machine Policies

This directory will own executable, versioned policy definitions after separate approval.

Reusable policies must remain app-neutral. They may not encode application names, schemes, bundle
identifiers, destinations, test paths, user paths, product exceptions, or implicit permission to
write or execute tests.
`check-catalog.json` is the canonical stable-ID catalog for deterministic and review-candidate
checks. `check-catalog.schema.json` closes the transport shape. Each entry records scope, severity,
applicability, remediation, and positive/negative fixture references. `implemented`, `staged`, and
`review-candidate` distinguish current engine behavior from planned adapters; catalog presence never
claims that a staged check already runs. Placeholder fixture references for staged checks are
catalog commitments, not existing evidence, until their adapters and fixtures are added.

Catalog maturity is deliberately four-dimensional and is not collapsed into `implementation`:
`maturity.implemented` means an adapter or engine path exists; `verified` means the listed fixture or
bounded acceptance evidence was actually exercised; `wired` means the trusted QualityControl mode
dispatcher invokes that check (a direct adapter command is not mode coverage); and `pilotEnabled`
means the check has passed the later consumer-pilot promotion gate. A verified check must list exact
repository-relative evidence paths. Until the canary and two consumer pilots are explicitly opened,
`pilotEnabled` remains false, even for an implemented and verified adapter.

`QC.SECRETS.TRACKED` is the first executable catalog adapter. It is intentionally conservative and
check-only: it scans a clean exact Git `HEAD` for high-confidence credential markers and
credential-shaped provisioning/key containers. The remaining staged entries still require their
own bounded adapters and positive/negative fixtures.

`QC.GENERATED.OWNERSHIP` is an executable, repository-neutral adapter. It requires the tracked
`.quality-control/generated-files.json` manifest, validates every declared path, SHA-256 digest,
generator/version pair, and exactly one `@generated-by generator=<name> version=<version>` marker.
Text files carrying that marker but absent from the manifest fail; filenames alone are never treated
as evidence of generated output. Missing or malformed manifests, traversal, symlinks, unsupported
objects, and immutable byte/file limits are `BLOCKED`, never `PASS`.

`QC.DEPENDENCY.LOCK_DRIFT` is an executable, repository-neutral adapter. It validates tracked
`Package.resolved` files in SwiftPM v1/v2/v3 shapes, requires lowercase immutable revisions and
unique identities, and matches external `.package(url:)` or Xcode `repositoryURL` declarations to
the resolved pins. Local-only packages with no external declarations may omit a lockfile; malformed
or unsupported lockfiles are `BLOCKED`, while missing or unmatched external pins are `FAIL`.

`QC.LOCALIZATION.CATALOG` is an executable, repository-neutral adapter. It validates tracked
`.strings`, `.stringsdict`, and `.xcstrings` resources, requires parity across legacy locale groups,
and requires a non-empty fallback candidate or source-language fallback. Malformed, duplicate,
unsupported, or bounded-input failures are `BLOCKED`; key drift and missing fallback coverage are
`FAIL`. Translation quality and linguistic correctness remain human review concerns.

`QC.RESOURCES.ASSETS` is an executable, repository-neutral adapter. It validates tracked Xcode
asset catalogs, known asset-set metadata, safe filename references, orphan files, and high-confidence
literal resource references. Malformed, unsupported, oversized, traversal, or symlink inputs are
`BLOCKED`; missing/duplicate/orphan resources, missing literal references, and compiled binary
outputs are `FAIL`. Dynamic names, runtime bundle membership, and visual/linguistic correctness
remain outside the static claim.

`QC.FORMAT.SWIFTFORMAT` is the retained legacy ID for the Apple `swift-format` executable; it is
not third-party SwiftFormat and is not SwiftLint. It requires a caller-pinned regular executable
and exact expected version, plus a tracked JSON configuration. It lints only regular Swift files
from a clean Git `HEAD` through stdin and records tool/configuration digests. Formatter diagnostics
are `FAIL`; missing, malformed, mismatched, unavailable, or resource-limited inputs are `BLOCKED`.
It never performs in-place formatting.

`QC.LINT.SWIFTLINT` is a separate implemented but not yet mode-wired adapter. It requires a
caller-pinned SwiftLint executable/version and tracked YAML configuration, passes an explicit clean-
HEAD file list through SwiftLint's script-input boundary, requests JSON diagnostics, applies bounded
timeouts/output, and never invokes autocorrect. Unapproved YAML rule/path suppression and inline
`swiftlint:disable`/`enable` directives are `BLOCKED`/`FAIL`; missing, malformed, mismatched,
unavailable, timeout, output-overflow, or infrastructure outcomes never become `PASS`. Its maturity
remains `verified=false`, `wired=false`, and `pilotEnabled=false` until the permitted canary/pilot
phase exercises it.

`QC.CONFIGURATION.SIGNING` is an executable, repository-neutral change detector. A tracked policy
lists exact release-sensitive paths and is required to be byte-identical in the trusted ancestor
and `HEAD`. The adapter reports changed paths as `FAIL`, malformed or untrusted inputs as `BLOCKED`,
and no changes as `PASS`; it never infers signing correctness or release authorization.

`QC.STATIC.SWIFT_HOT_PATH` and `QC.STATIC.SWIFT_CONCURRENCY_ESCAPE` are executable,
repository-neutral shipped-source gates. The first is an explicit lexical policy ban for the
configured synchronous or blocking media/file APIs; it does not infer a UI executor or runtime
hot path. The second blocks known Swift concurrency escape hatches. Both operate on clean Git
`HEAD`, exclude tests/fixtures/documentation, mask comments and string literals while preserving
interpolation code, fail closed on malformed or oversized input, and provide no suppression
mechanism. `QC.TESTS.DISABLED` likewise reports static disabled attributes and skip calls only;
conditional compilation, target membership, known-issue handling, and selected/executed runtime
counts remain separate evidence claims.

`QC.BUILD.MEMBERSHIP` is a build-evidence gate rather than a filename scan. Its receipt carries the
profile's explicit source scope separately from the authenticated Xcode compiler inputs for one
declared scheme/target/configuration/destination. Generated ownership remains a separate claim;
extension inputs are included only when observed; external package source-looking inputs are
counted but excluded from the first-party list. Empty, unresolved, outside-scope, symlink-escaping,
malformed, or unavailable membership is `BLOCKED`, never an empty successful scan.
