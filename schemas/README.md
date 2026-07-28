# Schemas

This directory will own versioned machine-readable contracts such as project profiles, permission
policies, findings, evidence, and verdicts.

Each future schema requires an explicit version, stable identifiers, validation behavior, and
compatibility policy. A malformed or unsupported schema must fail closed rather than produce normal
success evidence.
