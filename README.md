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
  - `POST /v1/resolve`
  - `GET /v1/sources/status`
- CLI-style commands:
  - `secretsbroker serve`
  - `secretsbroker status`
  - `secretsbroker key status`
  - `secretsbroker key generate`
  - `secretsbroker session status`
  - `secretsbroker session generate`
  - `secretsbroker version`
- package/test/verify scripts following the service-template contract

The first local encrypted store and batched resolve MVP is documented in `docs/local-store-resolve.md`. Portable master-key identity/unlock foundation is documented in `docs/portable-master-key.md`. Local API token/session security is documented in `docs/local-api-security.md`. The provider/source registry model is documented in `docs/provider-source-registry.md`; env/file/exec source adapters are documented in `docs/env-file-exec-sources.md`; Vault/OpenBao source support is documented in `docs/vault-openbao-source.md`. OS wrapper enrollment, policy, and write-back implementations are intentionally future issues. The initial local API/bootstrap contract is documented in `docs/local-api-bootstrap-contract.md`; lifecycle/source-auth state behavior is documented in `docs/lifecycle-states.md`.

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
