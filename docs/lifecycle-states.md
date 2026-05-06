# Secrets Broker Lifecycle States

Status: initial contract  
Issue: #10  
Service id: `@secretsbroker`

## Purpose

`@secretsbroker` must distinguish process liveness from secret usability.

A running process can still be unusable for a dependent service when the broker has not been set up, the portable master key is locked, a required source identity expired, or policy denies access.

Service Lasso should use these states to block only the affected service/ref where possible rather than treating every broker problem as a global startup failure.

## Lifecycle states

### `setup_needed`

Blank install. No local encrypted store/master-key enrollment exists yet.

Operator experience:

- show setup wizard
- create/import portable master key
- initialize local encrypted store
- enroll this machine's OS wrapper when available

Startup behavior:

- broker process can start
- `/health` is OK
- `/ready` is not ready
- dependent secret resolution is blocked until setup completes

### `locked`

Encrypted vault/store exists, but this machine cannot currently unwrap/access the portable master key.

Common causes:

- encrypted vault copied to a new machine
- OS wrapper not enrolled
- portable master key not imported
- local wrapper/keychain/DPAPI entry unavailable

Operator next action:

- import/unlock portable master key
- re-wrap/enroll this machine

### `ready`

Broker can service allowed local requests.

This does not mean every external source is healthy; optional source outages can still produce per-ref `degraded` or `source_auth_required` outcomes.

### `source_auth_required`

A configured source/backend identity is missing, expired, or needs reconnect.

Startup behavior:

- do not prompt for every optional source at broker startup
- prompt/block only when a startup-critical source/ref is needed
- report affected refs/services safely

### `degraded`

Broker is partially usable, but one or more optional sources/backends are unavailable.

Startup behavior:

- unrelated services may continue
- affected refs/services should be reported
- dependent services should block only when they require the degraded source/ref

### `policy_denied`

The broker intentionally denied a request or service/ref relation by policy.

Startup behavior:

- do not report this as a missing secret
- report precise denied ref/service relation where safe
- record audit event when policy/audit implementation exists

## State response shape

`GET /state` and `GET /ready` expose safe machine-readable lifecycle detail:

```json
{
  "serviceId": "@secretsbroker",
  "apiVersion": "secretsbroker.local/v1",
  "state": "source_auth_required",
  "ready": false,
  "outcome": "source_auth_required",
  "keyState": "available",
  "nextAction": "reconnect_source",
  "affectedRefs": ["openclaw/telegram/bot_token"],
  "affectedServices": ["openclaw"]
}
```

Rules:

- state/outcome is stable and machine-readable
- affected refs/services are safe identifiers only, never secret values
- `/ready` returns HTTP `200` only for `ready`
- `/ready` returns HTTP `503` for setup/locked/auth/degraded/policy states
- `/health` remains HTTP `200` while the process is alive

## CLI/dev state simulation

The bootstrap daemon supports state simulation for early Service Lasso integration work:

```powershell
secretsbroker serve --state locked --affected-ref openclaw/anthropic/api_key --affected-service openclaw
secretsbroker status --state source_auth_required
```

Environment equivalents:

```text
SECRETSBROKER_STATE=source_auth_required
SECRETSBROKER_AFFECTED_REFS=openclaw/telegram/bot_token,billing/stripe/api_key
SECRETSBROKER_AFFECTED_SERVICES=openclaw,billing
```

These simulation flags are not a substitute for the real encrypted store/source adapter implementations. They let Service Lasso core and Service Admin build against stable typed outcomes before storage and source adapters land.

## Out of scope for this slice

- encrypted local store
- portable master-key import/unwrap implementation
- source adapter auth flows
- audit persistence
- policy engine
