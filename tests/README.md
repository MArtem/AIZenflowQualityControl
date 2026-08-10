# Verifier Tests

This directory owns unit, integration, fixture, and adversarial tests of the quality-control
engine. Tests use Swift Testing and remain isolated from application test targets.

The verifier suite covers result aggregation, malformed and bounded profile/policy inputs,
path/symlink boundaries, scan ceilings, cooperative and hard process timeouts, immutable policy
floors, committed passing/failing fixtures, independent permission decisions, and versioned
evidence verification.
Evidence cases prove that stale source/review SHAs, changed permission snapshots, forged command
identities or artifact sets, incomplete multi-action authorization, missing or forged terminal outcomes,
unaccounted commands, upgraded statuses or forged messages, missing trusted user authorization,
prohibited execution, nonzero `PASS` commands, all-skipped counts, skipped gates, schema-invalid
JSON fields, and false claimed verdicts cannot produce normal `READY`. Collection and string-limit
regressions also prove that oversized evidence stops before unbounded deeper scans. Positive
coverage preserves commandless pre-execution blocked and user-declined outcomes.

Test creation, modification, and execution remain separately user-controlled. Temporary test
inputs and SwiftPM scratch output must stay under `.quality-control-cache/` inside the repository.

After explicit local-execution permission, run the following from the repository root. The latest
Stage 9D1 corrective full run passed 115 tests in ten suites. The earlier Stage 7/9A corrective contained run
passed 58 tests in four suites with warnings treated as errors. The combined matrix includes
regressions for digest-only command identity without raw argv, complete
permission-action sets, trusted terminal outcomes, status-dependent gate command IDs,
gate accounting for every command, trusted statuses and messages for every gate, bounded evidence
loading with duplicate/unknown/null rejection, action-dependent schema authorization, early
collection/string-limit returns, identical-object uniqueness, and commandless non-execution,
schema/runtime path, Unicode-length/whitespace parity, conservative aggregate byte budgeting,
unique residual risks, all-skipped counts, integer overflow in untrusted counts, and failed-count
`READY` claims:

```bash
QC_SWIFT_TEST_ROOT="${PWD}/.quality-control-cache/swift-tests"

for QC_SWIFT_TEST_COMPONENT in \
  .quality-control-cache \
  .quality-control-cache/swift-tests \
  .quality-control-cache/swift-tests/cache \
  .quality-control-cache/swift-tests/config \
  .quality-control-cache/swift-tests/security \
  .quality-control-cache/swift-tests/scratch \
  .quality-control-cache/swift-tests/module-cache; do
  if [[ -L "${QC_SWIFT_TEST_COMPONENT}" ]]; then
    echo "Refusing symlinked SwiftPM cache path: ${QC_SWIFT_TEST_COMPONENT}" >&2
    exit 2
  fi
done

mkdir -p \
  "${QC_SWIFT_TEST_ROOT}/cache" \
  "${QC_SWIFT_TEST_ROOT}/config" \
  "${QC_SWIFT_TEST_ROOT}/security" \
  "${QC_SWIFT_TEST_ROOT}/scratch" \
  "${QC_SWIFT_TEST_ROOT}/module-cache"

env \
  CLANG_MODULE_CACHE_PATH="${QC_SWIFT_TEST_ROOT}/module-cache" \
  SWIFTPM_MODULECACHE_OVERRIDE="${QC_SWIFT_TEST_ROOT}/module-cache" \
  swift test \
    --cache-path "${QC_SWIFT_TEST_ROOT}/cache" \
    --config-path "${QC_SWIFT_TEST_ROOT}/config" \
    --security-path "${QC_SWIFT_TEST_ROOT}/security" \
    --scratch-path "${QC_SWIFT_TEST_ROOT}/scratch" \
    -Xswiftc -warnings-as-errors \
    -Xswiftc -module-cache-path \
    -Xswiftc "${QC_SWIFT_TEST_ROOT}/module-cache"
```
