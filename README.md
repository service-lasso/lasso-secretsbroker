# lasso-secretsbroker

_Status: bootstrap skeleton_

`lasso-secretsbroker` is the Service Lasso-native Secrets Broker service repo.

Service identity:

```text
@secretsbroker
```

The broker is intended to be a lean, local-first, Vault-like process managed by Service Lasso during an early bootstrap phase. Service Lasso core keeps only the tiny bootstrap client/state machine; this repo owns the actual broker daemon, CLI/API contract, storage, policy, audit, source adapters, and resolve/write-back behavior.

## Architecture stance

Default/local mode:

```text
Service Lasso -> @secretsbroker -> local encrypted store
```

Cluster/enterprise mode:

```text
Service Lasso -> @secretsbroker -> Vault/OpenBao cluster
```

`@secretsbroker` is the stable Service Lasso-facing contract. HashiCorp Vault, OpenBao, AWS Secrets Manager, 1Password, Bitwarden/BWS, `env`, `file`, and `exec` are backends/sources behind the broker rather than replacements for the Service Lasso broker contract.

## Current skeleton

The first bootstrap slice provides:

- Service Lasso template repo structure
- root `service.json` with id `@secretsbroker`
- minimal Go daemon
- local HTTP endpoints:
  - `GET /health`
  - `GET /ready`
  - `GET /status`
  - `GET /state`
  - `GET /capabilities`
  - `POST /v1/secrets`
  - `POST /v1/writeback`
  - `POST /v1/resolve`
  - `GET /v1/sources/status`
  - `POST /v1/management/lockouts/clear`
- CLI-style commands:
  - `secretsbroker serve`
  - `secretsbroker-resolve`
  - `secretsbroker status`
  - `secretsbroker key status`
  - `secretsbroker key generate`
  - `secretsbroker key initialize`
  - `secretsbroker key unlock`
  - `secretsbroker key import`
  - `secretsbroker key rewrap`
  - `secretsbroker key wrapper-status`
  - `secretsbroker key rotate`
  - `secretsbroker backup create`
  - `secretsbroker backup restore`
  - `secretsbroker admin status`
  - `secretsbroker admin secrets list|search|value-search|reveal`
  - `secretsbroker admin providers capabilities|status|validate`
  - `secretsbroker admin migration dry-run|apply`
  - `secretsbroker admin audit export`
  - `secretsbroker admin mcp tools|call`
  - `secretsbroker session status`
  - `secretsbroker session generate`
  - `secretsbroker version`
- package/test/verify scripts following the service-template contract

The first local encrypted store and batched resolve MVP is documented in `docs/local-store-resolve.md`. Portable master-key identity/unlock foundation is documented in `docs/portable-master-key.md`; the implemented initialize/unlock/import/re-wrap lifecycle is documented in `docs/master-key-lifecycle.md`; encrypted backup, restore, and key rotation are documented in `docs/backup-restore-rotation.md`; the recommended secure initialization and recovery-key model is documented in `docs/secure-initialization-recovery.md`. Local API token/session security is documented in `docs/local-api-security.md`, and signed scoped launch identity leases are documented in `docs/launch-identity-leases.md`. The provider/source registry model is documented in `docs/provider-source-registry.md`; the external source adapter contract is documented in `docs/external-adapter-contract.md`; env/file/exec source adapters are documented in `docs/env-file-exec-sources.md`; Vault/OpenBao source support is documented in `docs/vault-openbao-source.md`; AWS Secrets Manager source support is documented in `docs/aws-secrets-manager-source.md`. The headless admin CLI is documented in `docs/headless-admin-cli.md`; the first metadata-only MCP adapter is documented in `docs/mcp-adapter.md`. The initial generated secret write-back/capture policy is documented in `docs/writeback-policy.md`. The operational-control baseline for service-json policy assignment, audit, telemetry, events/filtering, and lockout is documented in `docs/operational-controls-baseline.md`. Advanced capability classification for MCP, Secrets Sync, HSM, FIPS, MFA, and automated credential rotation is documented in `docs/advanced-capabilities-roadmap.md`; the focused enterprise security readiness assessment is documented in `docs/enterprise-security-readiness.md`; the focused Secrets Sync design and GitHub Actions first-target plan is documented in `docs/secrets-sync-design.md`. The OpenClaw SecretRef exec resolver is documented in `docs/openclaw-secretref-resolver.md`. OS wrapper enrollment and durable policy storage are intentionally future issues. The initial local API/bootstrap contract is documented in `docs/local-api-bootstrap-contract.md`; lifecycle/source-auth state behavior is documented in `docs/lifecycle-states.md`. Cross-language Node/Go compatibility expectations and reusable fixture format are documented in `docs/parity-contract.md`, with baseline fixtures under `conformance/fixtures/`.
The OS-authenticated local IPC transport foundation is documented in `docs/os-authenticated-ipc-transport.md`.

## Local development

Run tests:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\test.ps1
```

Package Windows artifact:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\package.ps1
```

Run the daemon directly:

```powershell
$env:SECRETSBROKER_MASTER_KEY = "local-dev-key"
$env:SECRETSBROKER_API_TOKEN = "local-api-token"
go run .\cmd\secretsbroker serve --listen 127.0.0.1:17890
```

Production-mode startup must use an OS IPC transport instead of loopback HTTP:

```powershell
$env:SECRETSBROKER_MODE = "production"
$env:SECRETSBROKER_TRANSPORT = "auto"
go run .\cmd\secretsbroker serve
```

On Windows this currently fails closed until named-pipe client identity checks are implemented. On Unix-like platforms, `auto` serves over a Unix socket.

Check status:

```powershell
go run .\cmd\secretsbroker status
```

## Service Lasso integration boundary

`service-lasso` should own only:

- locating/starting the `@secretsbroker` process in bootstrap phase
- checking `/health`, `/status`, and `/state`
- mapping typed broker states into startup/materialization diagnostics
- using the broker during env/config materialization once resolve APIs exist

`lasso-serviceadmin` should remain an optional UI client over Service Lasso and Secrets Broker APIs. The broker must work headless through CLI/API.
