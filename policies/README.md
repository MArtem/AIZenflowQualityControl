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
