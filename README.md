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
- CLI-style commands:
  - `secretsbroker serve`
  - `secretsbroker status`
  - `secretsbroker version`
- package/test/verify scripts following the service-template contract

Secret storage, unlock, policy, audit, provider/source adapters, and resolve/write-back implementations are intentionally future issues. The initial local API and bootstrap contract is documented in `docs/local-api-bootstrap-contract.md`.

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
