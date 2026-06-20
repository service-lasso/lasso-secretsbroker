# Operational controls baseline

Status: planning baseline
Issue: #56

## Purpose

This baseline groups policy assignment, audit logging, telemetry, events, filtering, and lockout into one operational-control model for Secrets Broker. These controls protect the same boundary: a Service Lasso-managed service should be able to resolve only the refs it is allowed to use, and every sensitive management or runtime decision should be explainable without exposing raw secret material.

The baseline is intentionally local-first. Vault, OpenBao, and other providers may provide stronger enterprise features behind the broker, but Service Lasso talks to the stable `@secretsbroker` contract.

## Safety rules

- Raw values, provider credentials, tokens, private keys, cookies, passwords, environment values, and recovery material must not be stored in policy, audit, telemetry, event, filter, lockout, diagnostics, issue, or UI payloads.
- Policy and lockout decisions fail closed when identity, policy, audit, provider, or broker state is unknown.
- Reveal and apply-style management operations require local API auth, a reason, an audit result, and policy allow state.
- Telemetry and event payloads use refs, service ids, provider ids, operation names, outcomes, hashes, counters, durations, and state names only.
- Filters operate on metadata fields only. They do not support searching or exporting raw values.

## Minimal production-ready controls

| Control | Baseline requirement | Deferred advanced controls |
| --- | --- | --- |
| Service JSON policy assignment | Allow a service manifest to declare which secret namespaces/refs it may resolve or write back. Enforce the resolved assignment for `resolve`, `writeback`, reveal, edit, reset, migration, and policy apply surfaces. | Full attribute-based policy language, external identity provider claims, policy inheritance UI, signed policy bundles. |
| Audit logging | Append safe audit records for allow, deny, reveal, edit, reset, migration, provider validation, source-auth state, key lifecycle, backup/restore, and policy changes. Export must stay metadata-only. | Tamper-evident chaining, remote audit sinks, retention tiers, legal-hold export workflows. |
| Telemetry | Expose redacted counters and health gauges for operation volume, outcomes, provider/source state, audit availability, lockout state, and policy decision counts. | High-cardinality tracing, distributed spans across external providers, predictive alerting. |
| Events and filtering | Emit bounded operational events for state transitions and important decisions. Support metadata filters by service id, provider id, ref prefix/hash, operation, outcome, severity, and time window. | Streaming webhooks, external event buses, complex query language, replay across remote clusters. |
| Lockout | Track repeated failed local API auth, management reveal/apply denials, and service identity/policy failures. Apply scoped cooldowns without blocking unrelated services. | Adaptive risk scoring, MFA challenges, enterprise identity-provider lockout integration. |

## Service JSON policy assignment

Service manifests should gain an optional `secrets` policy section owned by the service package or app-owned service inventory. The broker must treat the manifest as desired policy input, not as proof that a caller is authorized. The runtime identity presented to Secrets Broker still has to match the service id and scope.

Illustrative shape:

```json
{
  "id": "@serviceadmin",
  "secrets": {
    "resolve": [
      "services/@serviceadmin/runtime/*",
      "providers/ui/*"
    ],
    "writeback": [
      "services/@serviceadmin/generated/*"
    ],
    "manage": [
      "services/*/runtime/*"
    ]
  }
}
```

Baseline semantics:

- `resolve` allows the launched service to resolve matching refs.
- `writeback` allows generated value capture for matching refs.
- `manage` is reserved for operator/admin clients such as Service Admin and must still require local API auth, reason, audit, and operation-specific checks.
- Ref patterns are prefix/wildcard metadata matchers, not regular expressions.
- Policy evaluation returns `allowed`, `denied`, or `unknown`; `unknown` is denied.
- Policy denial responses include safe metadata: service id, operation, outcome, and next action. They do not include the requested value or credential material.

Implemented first slice:

- The broker has a service-manifest policy evaluator for the optional `secrets` section.
- Supported operation families are `resolve`, `writeback`, and management operations mapped to `manage`.
- Patterns support exact refs, `*`, and prefix wildcards ending in `/*`.
- Runtime `resolve` and `writeback` decisions deny `services/<id>/...` refs when the presented service identity does not match `<id>`.
- `POST /v1/resolve` and `POST /v1/writeback` enforce the supplied manifest policy when the request includes `secrets`.
- Existing launch-time write-back grants remain enforced; a supplied manifest policy is an additional fail-closed gate.
- Denied resolve/write-back responses do not echo raw secret values or generated replacement material.

## Audit model

Audit events are append-only JSONL records in local mode and provider-backed records in enterprise/provider mode when available. Records should use a stable schema:

```json
{
  "ts": "2026-05-22T00:00:00Z",
  "requestId": "req-...",
  "operation": "resolve",
  "serviceId": "@serviceadmin",
  "ref": "services/@serviceadmin/runtime/SESSION_SIGNING_KEY",
  "refHash": "sha256:...",
  "providerId": "local",
  "outcome": "policy_denied",
  "reasonCode": "policy_no_match",
  "actorKind": "service",
  "auditStatus": "audit_recorded"
}
```

Required redaction:

- `ref` may be included where the ref itself is not secret material, but exports and diagnostics should support `refHash`-only mode.
- `reason` text from an operator is stored only after length limiting and control-character stripping.
- No event may include raw `value`, credential payloads, auth headers, bearer tokens, private keys, cookies, environment dumps, or provider response bodies.
- Audit failure blocks reveal/apply unless the operation is explicitly marked non-secret-bearing and safe to continue.

Implemented first slice:

- Local audit JSONL records are normalized with `requestId`, `operation`, `serviceId`, `actorKind`, `ref`, `refHash`, `providerId` where applicable, `outcome`, `reasonCode`, and `auditStatus`.
- Audit fields are trimmed, control characters are stripped, and long metadata fields are bounded before persistence.
- Optional tamper-evident local JSONL hash chaining can be enabled with `--audit-hash-chain` or `SECRETSBROKER_AUDIT_HASH_CHAIN=1`. Chained records include `previousHash`, `eventHash`, and `chainStatus` metadata only; the hash is over the normalized metadata event and never over plaintext secret values.
- `secretsbroker admin audit export --ref-hash-only` omits raw refs from exported events while preserving `refHash` for correlation.
- `secretsbroker admin audit export` verifies hash-chain metadata when present and reports `chain.status` as `verified`, `partial`, `invalid`, or `not_enabled`. An invalid chain returns `outcome: "degraded"` with `nextAction: "inspect_audit_chain"`.
- Tests cover metadata-only audit export and prove secret payload values/master-key material are not serialized.

## Telemetry model

Telemetry is operational health data, not audit evidence. It should be safe to expose to Service Lasso and Service Admin without elevated secret access.

Baseline metrics:

- operation counts by operation and outcome
- policy allow/deny/unknown counts
- local API auth failure counts
- lockout active counts by scope
- provider/source state counts
- audit record success/failure counts
- resolve/writeback/reveal/edit/reset/migration durations as bounded histograms

Telemetry labels must be low-cardinality and safe. Use service ids, provider ids, operation names, outcomes, and state names. Use ref prefix groups or hashes only when necessary; do not label with raw values or unbounded refs.

Implemented first slice:

- `GET /v1/telemetry` returns read-only metadata counters for operation/outcome pairs, policy decisions, local API auth failures recorded in audit metadata, source states, provider states, and audit-record status/outcome pairs.
- `secretsbroker admin telemetry` prints the same metadata-only telemetry shape for headless consumers.
- The first slice intentionally reports duration histograms as an empty array until operation-duration timing is recorded by the broker paths.
- Telemetry uses `refHash`-only audit reads internally and does not serialize raw refs, secret values, provider credentials, bearer tokens, private keys, cookies, passwords, environment values, or provider response bodies.

## Events and filtering

Events represent operator-relevant state transitions and decisions. The broker should maintain a bounded recent event store and expose filtered reads.

Event families:

- `policy_decision`
- `auth_failure`
- `audit_recorded` / `audit_unavailable`
- `source_auth_required` / `source_recovered`
- `provider_unavailable` / `provider_recovered`
- `lockout_started` / `lockout_cleared`
- `management_reveal`
- `management_apply`
- `rotation_action`
- `delete_action`
- `key_lifecycle`
- `backup_restore`

Filtering requirements:

- Filters support time window, service id, provider id, source id, operation, outcome, severity, event family, and ref prefix/hash.
- Filters have bounded limits and deterministic pagination.
- Invalid filters fail safely with typed errors.
- Value search and credential search are not event-filter features.

Implemented first slice:

- Audit metadata now feeds a bounded local operational event store with deterministic retention of the most recent 200 events.
- GET /v1/events returns metadata-only events with filters for since, until, serviceId, providerId, sourceId, operation, outcome, severity, family, refPrefix, and refHash.
- secretsbroker admin events list exposes the same bounded event reader for headless administration, including `--source-id`.
- Event responses expose safe ref prefixes and refHash; they do not include raw refs, raw values, provider credentials, tokens, private keys, cookies, passwords, environment values, provider response bodies, or credential search results.
- Event filters use bounded page sizes with cursor pagination, and invalid filters return typed invalid_event_filter errors.
- Auth failures, provider/source failures, lockout-like conditions, rotation/delete actions, and source health changes are represented by explicit event families so Service Admin and notification sinks can filter without parsing operation names.

## Lockout model

Lockout scopes should be narrow enough to avoid turning one bad caller into a whole-broker outage.

Baseline scopes:

- local API session/client identity
- service identity
- operation family
- provider/source credential reference where safe

Lockout triggers:

- repeated invalid local API tokens
- repeated expired or invalid service identity assertions
- repeated policy-denied management apply/reveal attempts
- repeated provider-auth failures for a configured source

Baseline behavior:

- use cooldown windows with safe counters and timestamps
- expose `lockout_active`, `lockout_scope`, and `retryAfterSeconds`
- permit read-only safe status checks while a secret-bearing operation is locked out
- emit audit and event records for lockout start and clear
- provide an admin clear command that requires local API auth and audit reason

Implemented first slice:

- Secret-bearing local API token failures are tracked in memory by narrow local API client scope.
- Three invalid token attempts for the same local API scope start a five-minute cooldown.
- Active lockout responses return metadata only: `lockoutActive`, `lockoutScope`, `retryAfterSeconds`, outcome, and next action.
- Lockout and auth-failure audit/events use operation/outcome metadata only and do not persist presented tokens, expected tokens, request bodies, or secret values.
- Safe read-only status, readiness, capabilities, telemetry, and event endpoints remain available during local API lockout.

Implemented management-denial slice:

- Policy-denied management reveal/edit/reset/policy apply attempts are tracked in memory by operation, requesting service id, and safe ref handle.
- Three denied attempts for the same management scope start a five-minute cooldown for that exact reveal/apply operation.
- Active management lockout responses return metadata only: `lockoutActive`, `lockoutScope`, `retryAfterSeconds`, outcome, and next action.
- Unrelated refs, unrelated management operations, and safe read-only status/list/dry-run surfaces remain available during the cooldown.

Implemented write-back identity/source-auth slice:

- Repeated write-back launch identity failures, write-back policy denials, and source/provider auth-required outcomes are tracked in memory by family, operation, service id, and safe ref handle.
- Three failures for the same write-back scope start a five-minute cooldown for that exact write-back operation.
- Active write-back lockout responses return metadata only: `lockoutActive`, `lockoutScope`, `retryAfterSeconds`, outcome, and next action.
- Unrelated refs, unrelated operations, local status endpoints, and safe management list/search surfaces remain available during the cooldown.

Implemented management clear slice:

- `POST /v1/management/lockouts/clear` clears a requested lockout scope after validating the local API token and requiring an audit reason.
- Valid local API tokens are allowed to clear a local API lockout even while that exact scope is active; invalid tokens remain denied.
- Clear responses and emitted events are metadata-only and include scope, outcome, audit status, and next action without raw secret values, presented tokens, expected tokens, auth headers, private keys, cookies, passwords, or environment values.
- Durable audited admin-clear persistence and broader provider-specific credential lockout surfaces remain follow-up slices.

## API/backend mapping

| Control | API/backend requirement |
| --- | --- |
| Policy assignment | Parse service manifest `secrets` policy, persist effective policy metadata, and enforce it in resolve/write-back/management operation paths. |
| Audit logging | Normalize audit event schema, add redaction guard tests, and fail closed for secret-bearing operations when audit is unavailable. |
| Telemetry | Add read-only metrics endpoint or CLI output with bounded, redacted counters/histograms. |
| Events/filtering | Add bounded event store and `GET /v1/events`-style filtered metadata endpoint. |
| Lockout | Add scoped lockout state, counters, clear command, and typed error responses. |

## Service Admin UI mapping

| Control | UI requirement |
| --- | --- |
| Policy assignment | Show effective allowed refs/namespaces per service and explain denied operations without exposing values. |
| Audit logging | Show audit availability/status, export metadata-only audit events, and block dangerous apply/reveal flows when audit is unavailable. |
| Telemetry | Show broker health and operational counters without raw refs or secret values. |
| Events/filtering | Provide event filters for service, provider, source, operation, outcome, severity, family, and time range. Track UI follow-up in [lasso-serviceadmin#118](https://github.com/service-lasso/lasso-serviceadmin/issues/118). |
| Lockout | Show active lockouts, retry windows, affected scopes, and audited clear action when supported. |

## Test requirements

- Policy tests cover allowed, denied, unknown, malformed manifest policy, and service id mismatch.
- Audit tests prove every secret-bearing allow/deny path records safe metadata and never serializes raw values or credentials.
- Telemetry tests prove labels and counters do not include raw refs where not allowed, values, tokens, or provider payloads.
- Event tests cover bounded retention, pagination, invalid filters, and metadata-only payloads.
- Lockout tests cover scoped lockout, unrelated-scope isolation, cooldown expiry, admin clear, and audit/event emission.
- Service Admin contract tests should assert that UI fixtures and screenshots do not contain raw values, provider credentials, bearer tokens, or private keys.

## Follow-up implementation slices

These slices should be separate issues because they can be designed, implemented, validated, and reviewed independently:

1. Broker service-json policy assignment and enforcement: [lasso-secretsbroker#62](https://github.com/service-lasso/lasso-secretsbroker/issues/62).
2. Broker audit schema hardening and redaction guards: [lasso-secretsbroker#63](https://github.com/service-lasso/lasso-secretsbroker/issues/63).
3. Broker redacted telemetry endpoint/CLI: [lasso-secretsbroker#64](https://github.com/service-lasso/lasso-secretsbroker/issues/64).
4. Broker bounded event store and metadata filtering API: [lasso-secretsbroker#65](https://github.com/service-lasso/lasso-secretsbroker/issues/65).
5. Broker scoped lockout state and audited clear workflow: [lasso-secretsbroker#66](https://github.com/service-lasso/lasso-secretsbroker/issues/66).
6. Broker management lockout clear endpoint: [lasso-secretsbroker#79](https://github.com/service-lasso/lasso-secretsbroker/issues/79).
7. Service Admin operational controls surfaces for policy, audit, telemetry, events, and lockout once the broker contracts exist: [lasso-serviceadmin#118](https://github.com/service-lasso/lasso-serviceadmin/issues/118).

## Out of scope

- Bulk raw value export.
- Plaintext spreadsheet-style editing.
- Provider credential management UI beyond credential-ref metadata.
- Enterprise-only Vault/OpenBao feature parity as a requirement for local mode.
- MFA, HSM, FIPS, and automated credential rotation implementation. Classification and unblock criteria are tracked in `docs/advanced-capabilities-roadmap.md`.
