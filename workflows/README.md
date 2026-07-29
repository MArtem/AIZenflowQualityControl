# Manual Workflows

The repository provides one manually triggered, advisory GitHub workflow:

- `.github/workflows/manual-static.yml` — self-checks the quality-control repository without
  running tests, application builds, Simulator/device work, paid services, or Codex Review.

## Run The Static Check

1. Open the repository on GitHub and select **Actions**.
2. Select **Manual Static Quality Check** in the left sidebar.
3. Select **Run workflow**.
4. Choose the branch or ref to verify.
5. Select the green **Run workflow** button and open the created run.

The workflow is available only through `workflow_dispatch`; pushes and pull requests do not start
it automatically. A run records the exact source SHA, ref, runner, Swift/Xcode versions, and final
result in the GitHub step summary. GitHub exposes the manual launch after this workflow file exists
on the repository default branch; after this pull request is merged, the branch selector can target
another branch or ref.

## Static Scope

The five-minute `macos-15` job uses read-only repository permissions and performs:

- Swift package-manifest validation;
- JSON parsing for schemas, policies, and fixtures;
- a warnings-as-errors build of the dependency-free `quality` executable followed by a
  policy-driven self-scan using `policies/static-policy.json`;
- branch-diff whitespace validation against the repository default branch.

This is repository self-verification, not an adopted application profile. It does not run the
`quality` executable against an application or build an Xcode project. It does not provide test,
application-runtime, accessibility, performance, security, or production-readiness evidence.

Future workflows must use pinned dependencies, least privilege, bounded artifacts, exact-source
evidence, standard included runners, zero additional monetary cost, and no paid AI API calls. They
must not make branch protection or CI mandatory without a separate user decision.
