# Quality-Control Repository Instructions

## Authority

The reusable human policy is owned by `MArtem/AIZenflowDocumentation`, including its
`UNIVERSAL_XCODE_QUALITY_CONTROL_GOVERNANCE.md` and
`PRODUCTION_CODE_REVIEW_CHECKLIST.md`. This repository owns executable commands, schemas,
policies, adapters, fixtures, bootstrap mechanisms, workflows, and machine evidence.

## Mandatory Pre-Push Review Gate

Start with a compact risk-based verification plan: changed surfaces, credible failure modes,
exact checks, reusable current evidence, escalation triggers, and a bounded time/resource budget.
Choose the smallest sufficient evidence set that materially reduces missed-defect risk; do not
maximize the number of checks.

Run cheap, deterministic, targeted checks first. Reuse evidence only when the relevant source,
inputs, configuration, and toolchain are unchanged. Do not repeat a passing check or widen to a
full scan, build, test suite, or exhaustive review without a new risk, changed evidence, unresolved
ambiguity, or finding that justifies the added cost.

Before committing or pushing any material change, review the complete proposed diff locally.
Type-checks, builds, tests, JSON/schema validation, workflow parsing, and `git diff --check` are
supporting evidence; they do not replace semantic review.

Review the changed control flow and adjacent trust boundaries adversarially. At minimum consider:

- empty, malformed, unknown, oversized, repeated, unavailable, and partially failing inputs;
- fail-open behavior and every route that could emit a false `PASS`;
- filesystem containment, traversal, symlinks, enumeration errors, and bounded resource use;
- deterministic findings, evidence integrity, cancellation, rollback, and partial output;
- permission preservation, secrets, dependency pinning, and workflow supply-chain trust.

Record every actionable finding. P0–P2 findings block commit and push. P3 findings must be fixed or
reported explicitly before push, using the canonical checklist severity policy. After fixes,
repeat the full-diff review from a clean perspective; do not limit the second pass to the
previously reported lines. High-risk control-plane changes require an independent local reviewer
when available and an exhaustive review recommendation for the final pushed SHA.

Test creation, test modification, test execution, runtime verification, GitHub checks, external
review, commit, and push remain subject to the user's current explicit permissions. Missing or
denied evidence must be reported as residual risk and must never be represented as `PASS`. Stop
when the planned gates pass, blocking findings are closed, and residual risk is explicit and
acceptable; avoid review theatre and unrelated checks.
