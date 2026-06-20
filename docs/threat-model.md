# Secrets Broker Threat Model and Hardening Pass

Status: baseline hardening pass
Issue: #25

## Scope

This document covers the current `@secretsbroker` baseline: local encrypted store, portable master key, loopback HTTP API, source adapters, write-back capture, audit events, backup/restore, and UI-facing diagnostics.

The broker is local-first. It is not yet a multi-tenant remote secret service and should not be exposed as one.

## Assets

- Secret plaintext values resolved for launched services.
- Encrypted local-store payloads and backup artifacts.
- Portable master key / recovery material.
- Local API session token.
- Source adapter credentials such as Vault/OpenBao tokens.
- Launch identity and write-back policy claims.
- Audit trail integrity and redaction boundaries.

## Trust boundaries

| Boundary | Trusted side | Untrusted or lower-trust side |
| --- | --- | --- |
| Local API token | Broker process and authorized local clients | Other local processes, browser pages, service code without token |
| Store encryption | Broker with master key loaded | Store file, backups, filesystem copies |
| Source adapter config | Operator-managed config | Source outputs, exec adapters, external secret managers |
| Write-back policy | Launcher/Service Lasso identity and policy model | Service-provided write-back request body |
| Audit/diagnostics | Metadata only | Secret values, tokens, raw credentials |

## Threats and current mitigations

### Local attacker on the same host

Threats:
- Reads store or backup files from disk.
- Calls secret-bearing HTTP endpoints.
- Replays or guesses local API token.
- Reads logs/audit output looking for values.

Current mitigations:
- Store payloads use AES-256-GCM with per-secret nonces and a key derived from the portable master key.
- Store, audit, and backup writes use owner-only file modes where the platform honors them (`0600` files, `0700` directories).
- Secret-bearing endpoints require a configured local API token and return `503 security_not_configured` rather than falling open.
- Token comparison hashes both candidate and expected token before constant-time compare to avoid length-dependent comparison behavior.
- Secret-bearing request bodies are capped at 1 MiB before JSON decode to limit accidental or malicious memory pressure.
- Error envelopes and audit events carry codes, refs, states, source ids, service ids, and request ids only; they do not include plaintext values or tokens.

Residual risk:
- A privileged local attacker can read process memory, environment variables, command lines, or key files. Prefer key files with OS permissions over shell history or process arguments.
- Loopback HTTP is a development/bootstrap transport. Production should move to OS-authenticated named pipes or Unix sockets.

### Malicious or compromised service

Threats:
- Requests refs outside its namespace.
- Attempts write-back into another service namespace.
- Sends oversized request bodies.
- Replays launch identity after expiry.

Current mitigations:
- Resolve and write-back HTTP requests require a signed launch identity lease with service id, workspace id, allowed refs/namespaces, allowed operations, expiry, and one-time `jti`.
- Write-back capture validates namespace, ref, operation, launch identity service id, expiry, allowed namespaces, and allowed operations before storing generated values.
- Invalid, denied, expired, replayed, and source-auth-required attempts produce typed errors and audit events without storing values.
- Secret-bearing HTTP endpoints require the local API token before request bodies are processed.
- Request-size limits apply to write, resolve, and write-back endpoints.

Residual risk:
- Resolve currently authenticates the local API token but does not yet enforce per-service/ref policy. That belongs in the planned policy engine.

### Compromised source adapter

Threats:
- External source returns errors intended to leak credentials or confuse UI state.
- Exec source exfiltrates environment or runs an unexpected command.
- Vault/OpenBao token is missing, expired, denied, or source is sealed/unavailable.

Current mitigations:
- Source lifecycle normalization exposes safe state/outcome/nextAction/retry metadata instead of raw provider errors.
- Source lifecycle audit events record source id, ref, state, outcome, service id, and request id only.
- Exec adapters run with an empty environment, validate command presence, can restrict commands to trusted directories, reject symlink commands by default, enforce timeout, and cap stdout.
- Vault/OpenBao handling maps missing/unauthorized/forbidden/not-found/sealed/unavailable outcomes into typed lifecycle states without returning token values.

Residual risk:
- Exec sources are powerful local code execution hooks. Operators should keep them disabled unless needed and restrict `trustedDirs`.
- Persistent source config protection is currently delegated to filesystem permissions.

### Log and diagnostic leakage

Threats:
- Secret values, bearer tokens, source tokens, or oversized request content appear in errors, audit JSONL, status, or source registry output.

Current mitigations:
- API errors use fixed safe messages.
- Audit events omit values by schema.
- Source registry status includes source ids/kinds/capabilities/lifecycle metadata but no raw ref values or source credentials.
- Oversized-body errors do not echo request content or authorization tokens.
- Backup/key responses expose key ids/versions and counts, not plaintext secrets or master key material.

Residual risk:
- CLI invocations that pass keys/tokens directly as flags may be visible through shell history or process listings. Use `--master-key-file`, env injection from a trusted launcher, or future OS credential stores where possible.

### Replayed launch token or identity

Threats:
- A service reuses an expired launch identity to write generated secrets.
- A service broadens operation or namespace in its request body.

Current mitigations:
- Resolve and write-back HTTP requests reject missing, tampered, expired, replayed, or out-of-scope signed launch identity leases before secret access.
- Write-back capture requires the requested namespace and operation to be allowed by both the signed lease scope and the provided policy.
- Denied/expired/replayed attempts are audited with metadata only.

Residual risk:
- Bootstrap mode can fall back to the local API token as the HMAC key when `SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY` is not configured. Production deployments should configure a distinct launcher-owned signing key.

### Backup exfiltration

Threats:
- Attacker copies backup artifact and tries offline decryption.
- Operator restores with the wrong key.
- Backup metadata reveals too much.

Current mitigations:
- Backup artifact contains encrypted store payloads, counts, timestamps, key id/version, and service metadata; it does not contain plaintext secret values.
- Restore verifies artifact shape, secret count, key id, and decryptability before writing the store.
- Wrong-key restore fails with `errInvalidBackupKey` and does not overwrite the local store.

Residual risk:
- Backup plus matching master key is sufficient to recover secrets. Store backup artifacts and key/recovery material separately.

## Small hardening changes in this pass

- Local API token comparison now hashes both sides before constant-time comparison.
- Secret-bearing HTTP endpoints now cap request bodies at 1 MiB before JSON decode and return a safe `request_too_large` error.
- Added regression tests that oversized requests do not echo the bearer token or large request value.

## Follow-up candidates

These are intentionally out of scope for this bounded slice unless already tracked elsewhere:

1. Add per-service/ref resolve authorization policy enforcement: [#30](https://github.com/service-lasso/lasso-secretsbroker/issues/30).
2. Replace production loopback HTTP with OS-authenticated named pipe / Unix socket transport: [#31](https://github.com/service-lasso/lasso-secretsbroker/issues/31).
3. Add source config file permission checks and audit tamper-evidence: [#32](https://github.com/service-lasso/lasso-secretsbroker/issues/32).
