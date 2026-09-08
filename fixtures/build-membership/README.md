# Source membership acceptance cases

These cases describe the contract for the future permissioned verifier/canary phase. This
directory contains no executable build fixture and does not claim a runtime PASS.

## Positive control

- The profile declares one or more explicit repository-relative `sourcePaths`.
- The authenticated Xcode build selection records `scheme`, `target(s)`, `configuration`, and
  `destination` from the profile.
- The stable structured compiler log contains at least one in-repository source input, and every
  in-repository compiler input resolves inside an explicit profile scope.
- The receipt carries `declaredSourcePaths` and `compiledSourcePaths` as separate arrays, the
  compiler-section count, and the count of external source-looking inputs.

## Narrow-claim controls

- A tracked Swift file that is not present in the compiler log is not called shipped by the
  membership receipt.
- A generated source inside the scope may appear in `compiledSourcePaths`; generated ownership is
  a separate `QC.GENERATED.OWNERSHIP` claim.
- Extension sources are included when the authenticated compiler log includes them. The receipt
  does not infer extension membership from a filename or directory name.
- External SwiftPM/package source-looking inputs are counted separately and are not added to the
  first-party `compiledSourcePaths` list.

## Blocking controls

The result is evidence-free `BLOCKED` when the compiler input set is empty, a response/file list is
unresolved, a relative compiler path cannot be resolved, a source escapes the repository through a
symlink or traversal, the structured log is malformed/oversized, or the target/configuration
selection is undeclared. A source in `Tests` is never silently hidden when it is actually compiled.
