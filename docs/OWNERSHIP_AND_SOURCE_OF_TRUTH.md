# Ownership And Source Of Truth

## Purpose

Define the authority boundary for the universal Xcode quality-control system before executable code
is introduced.

## Sources Of Truth

| Concern | Authoritative owner |
| --- | --- |
| Human policy, intent, routing, interpretation | `MArtem/AIZenflowDocumentation` |
| Executable commands, schemas, machine policies, adapters, fixtures, workflows, verifier evidence | `MArtem/AIZenflowQualityControl` |
| Project/workspace facts, selected permissions, exceptions, thin launcher | Each adopting project |
| Roadmap, inventory evidence, migration decisions, rollout history | Owning task recovery boundary |

This repository does not replace human policy. It implements bounded machine contracts that must
remain traceable to the governing documentation version.

## Ownership Rules

- Reusable executable behavior must be application-neutral and versioned here.
- Project-specific facts and exceptions remain in the adopting project and never become engine
  defaults through convenience or precedent.
- Human governance changes belong in Documentation Vault; executable behavior changes belong here.
- A change crossing both boundaries must update each authoritative source explicitly without
  duplicating normative text.
- Policy weakening, HIGH/CRITICAL exceptions, emergency bypasses, releases, repository pushes, and
  promotion to new consumers require the user's explicit authorization.

## Evidence Authority

Evidence is valid only for its exact source revision, engine version, profile version, toolchain,
permission set, and executed commands. Review text, a filename, local JSON, environment variables,
or user-editable flags cannot independently prove that a check ran.

Missing, stale, malformed, skipped, user-denied, bypassed, or forgeable evidence remains visible and
must never be aggregated into normal `PASS`.

## Review Trigger

Review this boundary whenever repository ownership, policy precedence, evidence semantics,
permission authority, or consumer adoption changes.
