# Secrets Broker delivery rules

- `main` is the Broker integration and release branch. Do not create a Broker
  `develop` branch.
- All changes start from current `main` on an issue-scoped `feature/`, `fix/`,
  `docs/`, or `chore/` branch and merge through a pull request.
- Never push directly to `main`, force-push, delete protected history, weaken a
  failing check, or publish from an ordinary branch push.
- Release publication is an explicitly dispatched, approval-gated operation
  after terminal Windows, Linux, and macOS validation.
- Preserve unrelated dirty, active, ambiguous, external, and historical
  worktrees. Use a fresh issue-scoped worktree.
- Security evidence must distinguish source, exact packaged binaries,
  dependency/advisory state, artifact identity, publication authority, and
  independent assurance.

