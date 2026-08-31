# Adapters

This directory will contain typed integrations for explicitly supported project and toolchain
surfaces.

Adapters must receive project facts through validated profiles. They must not infer or hardcode
application-specific defaults, and unsupported inputs must remain distinguishable from successful
execution.

## Current adapter

`deterministic_checks.py` exposes the first catalog-backed adapter:
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

The JSON result follows `schemas/deterministic-check-result.schema.json`. This adapter is a local
engine capability; a consumer workflow may invoke it manually after pinning the engine revision.
