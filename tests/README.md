# Verifier Tests

This directory owns unit, integration, fixture, and adversarial tests of the quality-control
engine. Tests use Swift Testing and remain isolated from application test targets.

Stage 6A starts with bounded public-contract verification for report aggregation and profile input
handling. It asserts that empty evidence is `BLOCKED`, `FAIL` and `BLOCKED` take precedence over
`PASS`, and malformed, unknown, duplicate, or oversized profile documents cannot produce normal
`PASS`. A valid closed profile is retained as the positive control.

Test creation, modification, and execution remain separately user-controlled. Temporary test
inputs and SwiftPM scratch output must stay under `.quality-control-cache/` inside the repository.
