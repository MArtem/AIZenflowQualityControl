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
