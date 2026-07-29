# Verifier Tests

This directory owns unit, integration, fixture, and adversarial tests of the quality-control
engine. Tests use Swift Testing and remain isolated from application test targets.

Stage 6A starts with bounded public-contract verification for report aggregation and profile input
handling. It asserts that empty evidence is `BLOCKED`, `FAIL` and `BLOCKED` take precedence over
`PASS`, and malformed, unknown, duplicate, or oversized profile documents cannot produce normal
`PASS`. A valid closed profile is retained as the positive control.

Test creation, modification, and execution remain separately user-controlled. Temporary test
inputs and SwiftPM scratch output must stay under `.quality-control-cache/` inside the repository.

After explicit local-execution permission, run the following from the repository root:

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
