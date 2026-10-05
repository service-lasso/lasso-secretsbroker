# Secrets Broker delivery rules

- Normal development uses `develop` and its issue-scoped branch only. Create
  `feature/`, `fix/`, `docs/`, or `chore/` branches from current `develop` and
  target `develop` through a pull request. Do not use a `codex/` prefix.
- Development agents must not inspect, fetch, compare, orient from, branch
  from, merge from, or target the release branch. Its access belongs only to
  explicitly authorized release-promotion, urgent-hotfix, or reconciliation roles.
- Never push directly to protected integration/release branches, force-push,
  delete protected history, weaken a failing check, or publish from an ordinary
  branch push.
- Release publication is an explicitly dispatched, approval-gated operation
  after terminal Windows, Linux, and supported-macOS validation.
- Preserve unrelated dirty, active, ambiguous, external, and historical
  worktrees. Use a fresh issue-scoped worktree.
- Security evidence must distinguish source, exact packaged binaries,
  dependency/advisory state, artifact identity, publication authority, and
  independent assurance.
