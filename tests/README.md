# Verifier Tests

This directory owns unit, integration, fixture, and adversarial tests of the quality-control
engine. Tests use Swift Testing and remain isolated from application test targets.

The verifier suite covers result aggregation, malformed and bounded profile/policy inputs,
path/symlink boundaries, scan ceilings and cooperative timeouts, immutable policy floors, committed
passing/failing fixtures, independent permission decisions, and versioned evidence verification.
Evidence cases prove that stale source/review SHAs, changed permission snapshots, forged command or
artifact sets, missing trusted user authorization, prohibited execution, nonzero `PASS` commands,
skipped gates, and false claimed verdicts cannot produce normal `READY`.

Test creation, modification, and execution remain separately user-controlled. Temporary test
inputs and SwiftPM scratch output must stay under `.quality-control-cache/` inside the repository.

After explicit local-execution permission, run the following from the repository root. The Stage
7/9A contained run on 2026-07-30 passed 40 tests in four suites with warnings treated as errors:

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
