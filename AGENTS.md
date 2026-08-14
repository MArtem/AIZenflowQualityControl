# Quality-Control Repository Instructions

## Global Rules Bootstrap
<!-- AIZENFLOW_GLOBAL_RULES_BOOTSTRAP_V1 -->
Before any repository action, read and apply
`/Users/Artem/.zenflow/worktrees/documentation-vault/reusable/GLOBAL_RULES_BOOTSTRAP.md`.
It activates the current reusable rules directly from the canonical documentation repository.
This repository file is a repository-specific overlay only: it may strengthen the global
baseline, but it must not silently replace or weaken it. If the canonical bootstrap is
unavailable, stop before changing the repository and report the missing global-rule source; the
user does not need to remind the agent to load it.

## Authority

The reusable human policy is owned by `MArtem/AIZenflowDocumentation`, including its
`UNIVERSAL_XCODE_QUALITY_CONTROL_GOVERNANCE.md` and
`PRODUCTION_CODE_REVIEW_CHECKLIST.md`. This repository owns executable commands, schemas,
policies, adapters, fixtures, bootstrap mechanisms, workflows, and machine evidence.

## Mandatory Exact-SHA Review Gate

Start with a compact risk-based verification plan: changed surfaces, credible failure modes,
exact checks, reusable current evidence, escalation triggers, and a bounded time/resource budget.
Choose the smallest sufficient evidence set that materially reduces missed-defect risk; do not
maximize the number of checks.

Run cheap, deterministic, targeted checks first. Reuse evidence only when the relevant source,
inputs, configuration, and toolchain are unchanged. Do not repeat a passing check or widen to a
full scan, build, test suite, or exhaustive review without a new risk, changed evidence, unresolved
ambiguity, or finding that justifies the added cost.

Before committing, review the complete proposed diff locally.
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

After commit, capture the trusted base SHA and review the complete exact range through committed
`HEAD`; confirm the worktree is clean and run the final relevant checks at that SHA. The receipt
must record base, HEAD, range, contract rows, findings/disposition, command results, reused or
omitted evidence, and residual risk. Re-review authority/provenance, schema/runtime versioning,
aggregate encoded and decoded limits, public API bypasses, filesystem/symlink/TOCTOU boundaries,
false success, and all producer/consumer call sites and claims. A new commit invalidates the
receipt. Verify HEAD is unchanged before push and verify the remote branch resolves to the reviewed
SHA after push. External review is an independent second barrier; it never replaces this gate.

Test creation, test modification, test execution, runtime verification, GitHub checks, external
review, commit, and push remain subject to the user's current explicit permissions. Missing or
denied evidence must be reported as residual risk and must never be represented as `PASS`. Stop
when the planned gates pass, blocking findings are closed, and residual risk is explicit and
acceptable; avoid review theatre and unrelated checks.
