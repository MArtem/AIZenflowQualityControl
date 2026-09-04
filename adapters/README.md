# Adapters

This directory will contain typed integrations for explicitly supported project and toolchain
surfaces.

Adapters must receive project facts through validated profiles. They must not infer or hardcode
application-specific defaults, and unsupported inputs must remain distinguishable from successful
execution.

## Current adapter

`deterministic_checks.py` exposes the catalog-backed adapters:
`QC.SECRETS.TRACKED`. It requires a clean Git checkout and scans the exact `HEAD`, so a result is
deterministic and cannot silently include uncommitted or untracked material. It flags only
high-confidence private-key/credential markers and credential-shaped `.p12`, `.pfx`, and
`.mobileprovision` files. Input, subprocess, output, file-count, finding-count, and string limits
are immutable in the adapter. Unsupported or unavailable checks return `BLOCKED`; they never become
`PASS`. The adapter is check-only and does not write, rotate, or delete credentials.

The same command also exposes `QC.TODO.OWNER`. It accepts only comment-style markers and a
deliberately narrow metadata format, for example `// TODO(owner=alice ticket=APP-123
expires=2026-12-31): follow up`; every tracked comment `TODO`/`FIXME` without all three fields is
a finding. Expiry presence is validated syntactically; calendar/ownership semantics remain a human
review concern. Words inside ordinary strings, workflow labels, or identifiers are not markers.

`QC.GENERATED.OWNERSHIP` requires a tracked `.quality-control/generated-files.json` manifest. Each
entry names one regular UTF-8 Git-tree file, its SHA-256 digest, generator, and generator version.
The file must contain exactly one marker such as `// @generated-by generator=swiftgen version=6.6.2`.
Any marker-bearing tracked file absent from the manifest is a finding. The adapter does not infer
generated status from filenames, does not execute generators, and treats malformed manifests,
symlinks, unsupported files, and resource-limit exhaustion as `BLOCKED`.

`QC.DEPENDENCY.LOCK_DRIFT` validates committed SwiftPM resolution. It supports Package.resolved
versions 1, 2, and 3, requires a lowercase 40-character revision for every pin, rejects duplicate
identities and malformed/unsupported shapes, and matches external Package.swift `.package(url:)`
and Xcode project `repositoryURL` declarations. A repository with only local package references
may omit Package.resolved; an external declaration without a tracked matching lock pin is `FAIL`.

Example:

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.SECRETS.TRACKED
```

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.GENERATED.OWNERSHIP
```

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.DEPENDENCY.LOCK_DRIFT
```

The JSON result follows `schemas/deterministic-check-result.schema.json`. This adapter is a local
engine capability; a consumer workflow may invoke it manually after pinning the engine revision.

`QC.LOCALIZATION.CATALOG` validates tracked `.strings`, `.stringsdict`, and `.xcstrings` resources.
It parses each format with bounded input, rejects malformed, duplicate, unsupported, or oversized
resources as `BLOCKED`, and reports locale key drift or empty fallback values as `FAIL`. Legacy
`.lproj` resources are grouped by logical path; `Base` or `en` is preferred as the fallback locale,
with a deterministic lexical fallback when neither is present. Linguistic quality remains a human
review concern.

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.LOCALIZATION.CATALOG
```

`QC.RESOURCES.ASSETS` validates tracked Xcode asset catalogs and high-confidence literal resource
references. It parses bounded `Contents.json` metadata, requires metadata for known asset-set
directories, rejects traversal, symlink, malformed, unsupported, and oversized inputs as `BLOCKED`,
and reports missing or duplicate filenames, orphan files, forbidden compiled outputs, and missing
literal `Image`, `Color`, `UIImage(named:)`, `NSImage(named:)`, or `NSDataAsset(name:)` resources as
`FAIL`. Dynamic names and runtime bundle membership remain outside the static claim.

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.RESOURCES.ASSETS
```

`QC.FORMAT.SWIFTFORMAT` runs a caller-pinned `swift-format` executable in check-only mode over
regular Swift files from the clean Git `HEAD`. The expected tool version and a tracked JSON
configuration are mandatory; the result records the tool and configuration SHA-256 identities.
Tool/configuration mismatch, malformed inputs, time/resource exhaustion, or tool infrastructure
failure is `BLOCKED`; formatter diagnostics are `FAIL`. The adapter never writes files.

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.FORMAT.SWIFTFORMAT \
  --tool-path /absolute/path/to/swift-format \
  --tool-version 6.3.0 \
  --configuration-path .swift-format.json
```

`QC.PRIVACY.MANIFEST` validates every tracked `PrivacyInfo.xcprivacy` file as a bounded property
list. It rejects malformed or duplicate-key plists, unexpected keys, wrong value types, duplicate
categories, empty/duplicate arrays, invalid tracking-domain shapes, and non-standard manifest file
names as `BLOCKED`. The accepted structure covers Apple's four manifest keys:
`NSPrivacyTracking`, `NSPrivacyTrackingDomains`, `NSPrivacyCollectedDataTypes`, and
`NSPrivacyAccessedAPITypes`. The adapter does not infer API usage, target/bundle membership,
required-reason approval, collected-data truth, runtime lifecycle, SDK coverage, or App Store
acceptance. A repository without a tracked manifest returns `PASS` with those limits stated.

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.PRIVACY.MANIFEST
```

`QC.CONFIGURATION.SIGNING` compares an exact clean Git `HEAD` with a caller-supplied trusted
ancestor. A tracked JSON policy must explicitly list exact release-sensitive paths; wildcards,
traversal, missing paths, policy drift, dirty checkouts, and an invalid/non-ancestor baseline are
`BLOCKED`. A changed listed path is `FAIL` and requires review against the authorized release
profile; no changed path is `PASS` only for that narrow change-detection claim. The adapter does not
validate signing identities, provisioning, entitlements semantics, target membership, or App Store
acceptance, and it never mutates the checkout.

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.CONFIGURATION.SIGNING \
  --baseline-revision <40-hex-ancestor> \
  --configuration-signing-policy .quality-control/configuration-signing.json
```

`QC.TESTS.DISABLED` scans only explicit repository-relative `--test-path` scopes from a clean Git
`HEAD`. It reports Swift Testing `.disabled` attributes and unconditional `XCTSkip(...)` calls as
`FAIL`; malformed paths, missing scopes, unreadable/non-UTF-8 sources, and immutable-limit
violations are `BLOCKED`. It does not infer Xcode target membership or classify conditional
`XCTSkipIf/Unless` behavior.

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <repository> \
  --catalog policies/check-catalog.json \
  --check QC.TESTS.DISABLED \
  --test-path Tests
```
