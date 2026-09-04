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

`QC.FORMAT.SWIFTFORMAT` is an executable, repository-neutral adapter. It requires a caller-pinned
regular `swift-format` executable and exact expected version, plus a tracked JSON configuration.
It lints only regular Swift files from a clean Git `HEAD` through stdin and records tool/configuration
digests. Formatter diagnostics are `FAIL`; missing, malformed, mismatched, unavailable, or
resource-limited inputs are `BLOCKED`. It never performs in-place formatting.

`QC.CONFIGURATION.SIGNING` is an executable, repository-neutral change detector. A tracked policy
lists exact release-sensitive paths and is required to be byte-identical in the trusted ancestor
and `HEAD`. The adapter reports changed paths as `FAIL`, malformed or untrusted inputs as `BLOCKED`,
and no changes as `PASS`; it never infers signing correctness or release authorization.

`QC.STATIC.SWIFT_HOT_PATH` and `QC.STATIC.SWIFT_CONCURRENCY_ESCAPE` are executable,
repository-neutral shipped-source gates. The first blocks only high-confidence synchronous or
blocking media/file operations; the second blocks known Swift concurrency escape hatches. Both
operate on clean Git `HEAD`, exclude tests/fixtures/documentation, fail closed on malformed or
oversized input, and provide no suppression mechanism.
