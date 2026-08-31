# Fixtures

This directory owns synthetic positive, negative, malformed, and adversarial inputs used to verify
the verifier.

Fixtures must contain no private product code, real secrets, credentials, user data, or application-
specific defaults.

Stage 6G1 adds two static-only fixture repositories:

- `static/passing-project/` contains one safe source file and must produce normal `PASS` with the
  canonical static policy;
- `static/failing-project/` contains one `.canary-fail` file and must produce `FAIL` with
  `policies/deliberate-failure-static-policy.json`.

The dedicated policy is deliberately stricter than the canonical policy. This keeps the failing
fixture inert during the normal whole-repository self-scan while allowing an explicit verifier or
future public canary to prove the expected failure path. These fixtures do not claim to be
buildable Xcode projects and provide no build, test, Simulator, or application-runtime evidence.

`generated/passing-project/` contains a manifest, matching hash, generator/version declaration, and
marker. `generated/failing-project/` contains a marker-bearing file omitted from its manifest; the
adapter must return `FAIL`. These fixtures define the ownership protocol without filename heuristics.

`dependencies/passing-project/` contains an external SwiftPM declaration and a matching immutable
Package.resolved v2 pin. `dependencies/failing-project/` contains an external declaration whose
lockfile resolves a different identity; the adapter must return `FAIL`. Additional malformed,
duplicate, and unsupported lock shapes are covered by focused adapter tests.
