# Schemas

This directory will own versioned machine-readable contracts such as project profiles, permission
policies, findings, evidence, and verdicts.

Each future schema requires an explicit version, stable identifiers, validation behavior, and
compatibility policy. A malformed or unsupported schema must fail closed rather than produce normal
success evidence.

The current profile and static-policy loaders accept UTF-8 JSON documents of at most 1,000,000
bytes, require regular-file inputs read through EOF, reject duplicate object keys before Foundation
decoding, and cap JSON nesting at 64 containers. Project profile schema version 1 allows at most
256 non-overlapping explicit source paths, validation output is capped at 256 issues, and each
static-policy directory/suffix list is capped at 256 unique entries.

`quality-evidence.schema.json` defines evidence schema version 1. It is a closed, bounded contract
for exact source/engine/profile identity, toolchain and permissions, SHA-256 command identities,
explicit gate statuses, optional test counts and review SHA, artifact hashes, residual risks, and
the claimed advisory verdict. Raw command arguments are excluded from the evidence model. Runtime
verification additionally requires trusted out-of-band expectations for the complete
command/action sets, terminal command outcomes, exact gate-to-command bindings, trusted status for
every gate, user-authorized actions, test-count gate, and artifact hashes.
The schema requires `commandID` for `PASS`/`FAIL` and forbids it for explicit non-executed states.
Artifact paths use the same non-empty relative-segment rules in schema and runtime. The schema is
not yet wired to a CLI evidence loader or producer. Bounded strings use Unicode-scalar length in
runtime to match JSON Schema code-point length, and residual-risk entries are unique in both layers.
