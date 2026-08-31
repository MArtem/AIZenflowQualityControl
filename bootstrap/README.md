# Bootstrap And Migration

`plan.schema.json` defines the versioned, closed plan contract; `journal.schema.json` defines the
bounded reversible apply journal. `inventory.py` is the first
read-only bootstrap mechanism. It consumes an explicit plan describing
source files from a canonical baseline and project-owned destinations, then emits deterministic
`READY`, `REVIEW_REQUIRED`, or `BLOCKED` JSON. It supports read-only `inventory` and `dry-run`, plus
explicitly authorized `apply`, `post-check`, and `rollback` commands.

```text
python3 bootstrap/inventory.py inventory \
  --plan <plan.json> \
  --baseline-root <canonical-baseline> \
  --project-root <project>
```

The plan is bounded, closed, duplicate-key checked, and repository-relative. Each entry is
classified as `MISSING`, `EXACT`, `OVERLAY_PRESENT`, `CONFLICT`, or `BLOCKED`. Exact entries may be
reported as eligible for a future create action; overlay entries always remain `review-overlay`.
Existing files, symlinks, and conflicts are never overwritten. `apply` requires the exact
`--authorize APPLY` token, creates only missing `exact` entries, refuses conflicts and overlays, and
writes a bounded reversible journal. `post-check` verifies the journal against the exact plan and
resulting bytes. `rollback` requires `--authorize ROLLBACK` and removes only files whose bytes still
match the journal; changed files, symlinks, and non-empty directories are preserved and reported as
`BLOCKED`.

The complete adoption lifecycle is `inventory -> dry-run -> explicit apply -> post-check -> rollback`.
Broad copying, destructive replacement, and silent modification of project-owned facts remain
unacceptable migration strategies.
