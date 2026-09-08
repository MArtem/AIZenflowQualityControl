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

`localization/passing-project/` contains matching English and Russian `.strings` resources.
`localization/failing-project/` intentionally omits one Russian key; the localization adapter must
return `FAIL`. Malformed, duplicate, `.stringsdict`, and `.xcstrings` cases are covered by focused
adapter tests.

`resources/passing-project/` contains a valid asset catalog with a colorset, an image set whose
filename is present, and matching literal `Image`/`Color` references. `resources/failing-project/`
contains a missing asset filename and a tracked compiled `.car` output; the resources adapter must
return `FAIL`. Malformed JSON, traversal, duplicate references, symlink, orphan, and loose-resource
cases are covered by focused adapter tests.

`format/passing-project/` contains a tracked bounded SwiftFormat configuration and already formatted
Swift source. `format/failing-project/` uses the same configuration with spacing and indentation
violations; a caller-pinned `swift-format` invocation must return `FAIL` without modifying either
fixture.

`configuration-signing/passing-project/` and `configuration-signing/failing-project/` contain an
explicit tracked release-sensitive path policy. The adapter harness creates a trusted baseline and
then mutates a listed path only for the failing case; the positive case keeps both trees unchanged.
`configuration-signing/boundary-project/` contains a traversal path and must return `BLOCKED`. These
fixtures detect release-sensitive changes only; they do not claim that signing, entitlements,
profiles, provisioning, or App Store configuration is valid.

`tests/passing-project/` and `tests/failing-project/` are explicit test-source scopes for
`QC.TESTS.DISABLED`. The positive fixture has no static disabled attribute or skip call; the
negative fixture contains `XCTSkip(...)` and must return `FAIL`. The adapter masks comments and
string literals (including raw/multiline forms), preserves code inside interpolation, and labels
preprocessor regions conservatively. It does not infer Xcode target membership, unbound test files,
known-issue wrappers, conditional `XCTSkipIf/Unless` behavior, or selected/executed runtime counts.

`swift-hot-path/passing-project/` demonstrates code without a configured policy token and
`swift-hot-path/failing-project/` demonstrates banned file, image, and PDF APIs. The adapter
must pass only the former; it intentionally does not infer whether a call is off-main or a proven
runtime hot path. `swift-concurrency-escape/passing-project/` uses actor-owned state;
`swift-concurrency-escape/failing-project/` contains forbidden escape-hatch attributes. These
fixtures are source-pattern contracts, not build or runtime evidence.

The Swift lexical contract also has these bounded acceptance cases: tokens in line/block comments,
normal strings, raw strings, and multiline strings stay outside the claim; the same token inside a
string interpolation remains code and is reported; nested block comments and interpolation strings
are masked; and unbalanced strings, comments, or interpolations return `BLOCKED`. A static finding
under `#if`, `#if os(...)`, or a similar compile region is labeled as conditional/platform-gated
context, while `withKnownIssue`, `XCTSkipIf/Unless`, target membership, and runtime selected/
executed counts remain unclaimed.
