# Bootstrap And Migration

`plan.schema.json` defines the versioned, closed plan contract. `inventory.py` is the first
read-only bootstrap mechanism. It consumes an explicit plan describing
source files from a canonical baseline and project-owned destinations, then emits deterministic
`READY`, `REVIEW_REQUIRED`, or `BLOCKED` JSON. It supports `inventory` and `dry-run` modes only.

```text
python3 bootstrap/inventory.py inventory \
  --plan <plan.json> \
  --baseline-root <canonical-baseline> \
  --project-root <project>
```

The plan is bounded, closed, duplicate-key checked, and repository-relative. Each entry is
classified as `MISSING`, `EXACT`, `OVERLAY_PRESENT`, `CONFLICT`, or `BLOCKED`. Exact entries may be
reported as eligible for a future create action; overlay entries always remain `review-overlay`.
Existing files, symlinks, and conflicts are never overwritten. The report explicitly says that
`apply` is not implemented and requires user authorization.

The complete adoption lifecycle remains `inventory -> dry-run -> explicit apply -> post-check ->
rollback`. Broad copying, destructive replacement, and silent modification of project-owned facts
are not acceptable migration strategies. The future apply layer must consume the same report, refuse
conflicts, record a reversible journal, and run post-check before claiming adoption.
