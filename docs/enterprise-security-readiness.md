# Enterprise Security Readiness Assessment

Status: planning baseline  
Issue: #96  
Parent feedback: service-lasso/lasso-serviceadmin#97

## Purpose

This assessment classifies HSM support, FIPS compliance, MFA, and automated credential rotation for the local-first `@secretsbroker` contract. It is intentionally conservative: a capability is not treated as implemented, compliant, or production-ready until the broker has a concrete contract, tests, operator guidance, and release evidence.

The broker remains the stable Service Lasso-facing boundary:

```text
Service Lasso -> @secretsbroker -> local encrypted store or approved provider adapter
```

Vault, OpenBao, HSMs, identity providers, and enterprise rotation systems may sit behind the broker later. They do not replace the broker contract, and their presence must not cause Service Lasso to claim enterprise parity without tested integration.

## Decision Summary

| Capability | Local-first / open-source stance | Future / enterprise stance | Current decision |
| --- | --- | --- | --- |
| HSM support | Not required for the default local encrypted store. | Possible later as a key-provider adapter after vendor, recovery, and fixture strategy approval. | Parked. Do not implement vendor HSM support yet. |
| FIPS compliance | No compliance claim. Existing crypto usage is not the same as a FIPS-validated operating boundary. | Possible only through a formal compliance track with validated modules, controlled builds, platform matrix, and release evidence. | Parked. Start with gap analysis only if explicitly approved. |
| MFA | Not applicable to launched-service resolve/write-back flows. Local services must not block on human MFA. | Possible for human/operator management operations after Service Admin identity/auth boundary is approved. | Parked. Scope to management-only design later. |
| Automated credential rotation | Metadata-only planning is in scope for local-first mode. Broad provider apply remains unsafe until provider capabilities are proven. | Provider-backed rotation can be added per provider after dry-run, policy, audit, lockout, idempotency, and recovery semantics pass review. | First dry-run contract is complete in #68. No new apply issue is approved by this assessment. |

## Shared Safety Rules

- Raw secret values, generated replacement values, provider credentials, bearer tokens, private keys, cookies, passwords, environment values, recovery material, provider response bodies, and raw provider errors must not appear in routes, query strings, logs, diagnostics, telemetry, events, audit exports, fixtures, screenshots, issue comments, or PR bodies.
- Capability probes and readiness checks expose metadata only: capability name, state, outcome, blocker, next action, provider id, safe ref handle, audit state, and policy result.
- Unknown policy, audit, lockout, identity, provider auth, provider state, compliance state, or key-provider state fails closed.
- Service Lasso and Service Admin must not describe a capability as enforced unless the broker path validates it and tests cover failure and no-leak behavior.

## HSM Support

### Readiness Classification

HSM support is out of scope for local-first mode. The current local store protects payloads with a portable master key, local wrapper, recovery shares, backup/restore validation, and metadata-only audit. That model is compatible with a future key-provider abstraction, but it is not HSM-backed custody.

### Dependencies

- Key-provider interface that separates encrypt/decrypt/wrap operations from local software key material.
- Local software key provider retained as the default provider.
- Fake HSM test provider for deterministic CI without vendor hardware.
- Vendor and platform selection, including Windows/Linux support expectations.
- Enrollment, backup, disaster recovery, key rotation, and key destruction ceremonies.
- Operator documentation for HSM outage, locked module, lost quorum, and recovery fallback.

### Threat Model

HSM integration changes key custody, not the entire broker trust boundary. It can reduce offline key extraction risk, but it does not protect against every privileged-host attack, malicious provider response, bad policy, or plaintext exposure after a successful decrypt. The broker must still enforce local API auth, policy, audit, lockout, redaction, and no-leak diagnostics.

### Expected Operator UX

- Show key-provider state such as `software`, `hsm_configured`, `hsm_locked`, `hsm_unavailable`, or `hsm_key_missing`.
- Guide operators to enroll or unlock a provider without rendering key material.
- Report safe provider id, key id fingerprint, health, and next action.
- Keep local-first recovery paths explicit; do not silently fall back from HSM to software keys for production stores.

### Backend Changes

- Add a provider-neutral key-provider contract.
- Move local-store payload encryption through that contract.
- Add metadata-only key-provider status and audit events.
- Add fail-closed behavior for unavailable or mismatched key providers.

### Validation Path

- Unit tests for provider selection, unavailable provider, wrong key id, rotation, backup/restore, and no-leak status.
- Fake provider integration tests for CI.
- Vendor tests only after a vendor is approved and hardware or simulator access exists.
- Documentation proving that HSM-backed protection is not claimed unless cryptographic operations actually use the HSM provider.

## FIPS Compliance

### Readiness Classification

FIPS compliance is out of scope until there is a formal compliance objective. The broker must not claim FIPS just because it uses strong cryptographic algorithms. A valid claim needs a FIPS-validated module, approved operating mode, dependency and build controls, supported platform matrix, provenance, release signing, and evidence retention.

### Dependencies

- Formal compliance scope: which product, version, platform, and deployment mode.
- FIPS-validated cryptographic module selection and documented boundary.
- Build and release process that preserves the validated boundary.
- Dependency inventory, SBOM, provenance, signing, and reproducibility expectations.
- Test/evidence process for runtime FIPS mode and unsupported configuration rejection.

### Threat Model

FIPS is a compliance and assurance boundary, not a replacement for policy, auth, audit, or redaction. A FIPS-mode broker can still leak secrets if diagnostics, UI, or provider adapters serialize sensitive material. The existing no-leak rules remain mandatory.

### Expected Operator UX

- Show compliance mode as `not_configured`, `unsupported`, `configured_unverified`, or `verified` only when evidence exists.
- Show why FIPS mode is unavailable, such as unsupported OS/runtime/build.
- Avoid badges, green checks, or marketing language that imply validation without evidence.

### Backend Changes

- Add build/runtime capability detection only after a compliance track is approved.
- Add release metadata that names crypto module, build profile, platform, and evidence bundle.
- Fail closed when an operator requires FIPS mode but the runtime cannot prove it.

### Validation Path

- Compliance gap analysis before code changes.
- CI checks for dependency/build metadata.
- Runtime tests for supported and unsupported modes.
- Release evidence review before any user-visible compliance claim.

## MFA

### Readiness Classification

MFA is not appropriate for launched-service secret resolution or write-back. Those flows must remain headless, scoped, auditable, and policy-bound. MFA may be useful later for human/operator management operations such as reveal, clear lockout, high-risk apply, migration apply, or provider reconnect, but only after the operator identity boundary is defined.

### Dependencies

- Service Admin/operator identity and session model.
- Local API session model that distinguishes service callers from human operators.
- Audited management operation contract with reason, confirmation, policy, lockout, and audit state.
- Identity provider decision, recovery policy, and offline/on-prem availability model.
- Clear rules for break-glass when MFA provider is unavailable.

### Threat Model

MFA can reduce misuse of human management sessions, but it can also create availability and recovery risks. It must not lock out headless service startup, make emergency recovery impossible, or store MFA secrets/recovery codes in broker state, UI fixtures, diagnostics, or support bundles.

### Expected Operator UX

- Require MFA only for approved high-risk management actions.
- Show challenge state, timeout, denial, recovery-required, and provider-unavailable metadata without secrets.
- Preserve CLI-first break-glass procedures for recovery paths.
- Keep service runtime operations free of human prompts.

### Backend Changes

- Add management-operation challenge hooks after the operator identity model exists.
- Add metadata-only challenge/audit events.
- Add policy that maps operation risk to MFA requirement.
- Add fail-closed behavior for MFA-required operations when challenge state is unknown.

### Validation Path

- Tests for management-only enforcement and service-runtime exclusion.
- Tests for challenge success, denial, timeout, provider unavailable, and recovery path.
- No-leak tests for MFA secrets, recovery codes, cookies, tokens, and provider responses.

## Automated Credential Rotation

### Readiness Classification

Automated credential rotation is the only assessed capability with a local-first path already started. The metadata-only dry-run contract from #68 is complete and documented in `docs/secrets-management-api.md`. It plans rotation/reset readiness without generating replacement material, mutating provider state, or returning raw values.

Live apply, broad provider rotation, and generated replacement values are not approved by this assessment. They require a separate design after dry-run semantics are reviewed against real provider capabilities.

### Dependencies

- Provider capability model and source registry.
- Service-manifest policy assignment and enforcement.
- Audit logging, telemetry, events/filtering, and scoped lockout.
- Idempotent operation ids and stale-plan revalidation.
- Provider-specific capability tests for every apply-capable adapter.
- Operator confirmation and recovery guidance for partial failures.

### Threat Model

Rotation can break dependent services or copy new credentials into the wrong place. The broker must treat every apply path as high risk: dry-run first, policy allow, provider capability allow, audit reason, fresh revalidation, idempotency, partial outcome reporting, and no raw replacement value exposure.

### Expected Operator UX

- Select refs or campaigns and generate a dry-run plan.
- Show per-ref readiness, policy, provider capability, audit requirement, risk, blocker, stale-after time, and next action.
- Require reason and confirmation for apply only after a fresh plan.
- Show partial success, skipped, denied, unsupported, and recovery guidance without values.

### Backend Changes

- Keep the existing dry-run contract as the baseline.
- Add apply only after an approved follow-up defines replacement generation, provider writes, rollback/recovery, refresh/reconnect, and audit semantics.
- Add one provider at a time; do not add a generic provider-apply switch.

### Validation Path

- Existing #68 tests cover the dry-run contract and no-leak behavior.
- Future apply tests must cover success, denial, unsupported provider, stale plan, auth required, audit unavailable, partial failure, idempotent retry, refresh/reconnect signals, and no-leak outputs.
- Canonical demo validation is required for any Service Admin surface that drives rotation campaigns.

## Implementation Roadmap

| Phase | Capability | Action |
| --- | --- | --- |
| Current | Automated credential rotation | Keep #68 dry-run contract as the only approved broker implementation. Do not create a live apply issue until dry-run behavior and provider capability boundaries are reviewed. |
| Current | HSM | No implementation. If approved later, start with key-provider interface design plus fake provider tests, not a vendor integration. |
| Current | FIPS | No implementation. If approved later, start with compliance gap analysis and build/runtime matrix, not a compliance claim. |
| Current | MFA | No implementation. If approved later, start with management-only MFA requirements after Service Admin/operator auth is decided. |

## Issue Actions From This Assessment

No new narrower implementation issue is created by this assessment.

Reasons:

- Automated credential rotation already has the approved first slice completed in #68.
- HSM, FIPS, and MFA are parked until explicit approval and dependency decisions exist.
- A live rotation apply issue would be premature until the #68 dry-run contract is reviewed against provider-specific capability and recovery requirements.

## Non-Claims

Service Lasso must not claim any of the following from this assessment alone:

- HSM-backed key custody.
- FIPS validated or FIPS compliant operation.
- MFA enforcement for Secrets Broker.
- Automated credential rotation apply support.
- HashiCorp Vault Enterprise, OpenBao, or enterprise secrets-platform parity.

