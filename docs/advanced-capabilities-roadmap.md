# Advanced Capabilities Roadmap

Status: planning baseline
Issue: #57
Parent feedback: service-lasso/lasso-serviceadmin#97

## Purpose

This roadmap classifies advanced platform capabilities raised during Secrets Broker feedback so they do not get mixed into UI or operational-control implementation issues without a security and product boundary.

The broker remains local-first. Vault, OpenBao, HSMs, identity providers, GitHub sync, and other enterprise systems may sit behind or beside the stable `@secretsbroker` contract, but Service Lasso should not imply parity with those systems unless a capability is explicitly implemented, integrated, validated, and documented.

The focused readiness assessment for HSM support, FIPS compliance, MFA, and automated credential rotation is documented in `docs/enterprise-security-readiness.md`.

## Classification rules

- Near-term: can be designed and implemented as a focused local-first broker or Service Lasso slice after current contract dependencies land.
- Later: useful direction, but blocked by missing broker contracts, runtime APIs, product decision, provider support, or security model.
- Out of scope for local-first mode: not a native local broker requirement. Revisit only as an adapter, integration, or compliance track with explicit approval.

Every capability keeps these safety rules:

- No raw values, provider credentials, bearer tokens, private keys, cookies, passwords, environment values, recovery material, or provider response bodies in routes, logs, issue comments, diagnostics, telemetry, events, exports, fixtures, or screenshots.
- Capability probes, dry-runs, and roadmaps must expose metadata, state, outcome, next action, and capability names only.
- Provider-backed or enterprise-backed behavior must fail closed when provider auth, policy, audit, identity, or compliance state is unknown.

## Capability classification

| Capability | Classification | Target repo(s) | Required dependencies | Security and compliance concerns | First executable slice |
| --- | --- | --- | --- | --- | --- |
| MCP server for Service Lasso | Later | `service-lasso/service-lasso` primarily; `service-lasso/lasso-serviceadmin` only for UI surfaces | Stable runtime API facade, action-required queue, diagnostics bundle contract, permission model for operator actions, and explicit tool allowlist | MCP tools can become a privileged remote-control surface. Tool calls must be least-privilege, auditable, local-authenticated, and incapable of returning secret values or raw diagnostics. | Design a read-only Service Lasso MCP contract after the runtime API and diagnostics APIs are stable. Scope it to service catalog, status, health, and safe diagnostics metadata before any mutating tools. |
| MCP server for Secrets Broker | First adapter slice | `service-lasso/lasso-secretsbroker`; optional UI in `service-lasso/lasso-serviceadmin` | Policy assignment, audit, telemetry, events/filtering, lockout, local API auth, and metadata-only diagnostics are available for a read-only adapter. A full transport server still needs an approved auth/consent model. | MCP must not expose reveal, export, credential sync, provider token, or raw audit search by default. Any management tool must require local API auth, policy allow, audit reason, and redaction guard tests. | `docs/mcp-adapter.md` and `secretsbroker admin mcp tools|call` expose read-only metadata tools. Mutations and reveal remain disabled until separate approval. |
| Secrets Sync, including GitHub sync | Later | `service-lasso/lasso-secretsbroker`; target-specific adapters may involve `service-lasso/service-lasso` for package/runtime integration | Provider/source registry, write-back policy, audit schema, events, lockout, provider capability model, operator confirmation flow, and GitHub credential reference handling | Sync can copy sensitive material into third-party systems. It must require explicit destination policy, dry-run, audit, idempotency, rollback guidance, and proof that provider credentials and synced values are never logged or rendered. GitHub sync must distinguish GitHub Actions secrets, Dependabot secrets, environments, and org/repo scopes. | `docs/secrets-sync-design.md` defines the approved planning baseline. The first implementation should be a metadata-only dry-run contract for source ref, destination kind, destination scope, capability, policy result, audit/auth state, drift state, deletion behavior, and blocker state; no apply path. |
| HSM support | Out of scope for local-first mode | `service-lasso/lasso-secretsbroker` if later approved as a key-provider adapter | Key provider abstraction, platform support matrix, HSM vendor selection, enrollment lifecycle, backup/recovery model, CI fixture strategy | HSM integration changes key custody and recovery. It needs vendor-specific threat modeling, operator enrollment, failure/recovery procedures, and a compliance review. Local encrypted store must not claim HSM-backed protection without actual HSM-backed cryptographic operations. | No near-term implementation. If approved later, start with a key-provider interface design that supports local software key provider and one fake HSM test provider before any vendor integration. |
| FIPS compliance | Out of scope until a formal compliance track exists | `service-lasso/lasso-secretsbroker`; build/release work may involve `service-lasso/service-lasso` | FIPS-validated crypto module choice, supported OS/runtime matrix, build provenance, dependency inventory, release signing, and compliance evidence process | FIPS is not a label to add to AES usage. It requires validated modules, controlled builds, operating-mode evidence, and release artifacts that preserve the validated boundary. | No near-term implementation. First approved slice would be a compliance gap analysis and build/runtime matrix, not a code change claiming compliance. |
| MFA for Secrets Broker | Later | `service-lasso/lasso-secretsbroker`; `service-lasso/lasso-serviceadmin` for operator flows; possible external identity provider repo/integration later | Local API/session model, lockout (#66), audit (#63), events (#65), Service Admin auth boundary, identity-provider decision | MFA is meaningful for human/operator management flows, not ordinary launched-service secret resolution. It must not block headless service startup, and it must not store MFA secrets or recovery codes in broker diagnostics. | Defer until operator identity and Service Admin auth decisions are made. First slice should be an MFA requirement/design issue for management-only operations, with service-runtime operations explicitly excluded. |
| Automated credential rotation | Near-term | `service-lasso/lasso-secretsbroker`; UI campaign surfaces later in `service-lasso/lasso-serviceadmin` | Provider capability model, write-back policy, audit hardening (#63), telemetry (#64), events (#65), lockout (#66), provider auth state, idempotent operation ids | Rotation changes live credentials and can break services. It must require dry-run, policy allow, provider capability allow, audit reason, revalidation before apply, partial-failure reporting, and no raw value exposure. Provider-generated replacement values must never appear in logs, diagnostics, events, telemetry, issue comments, PR bodies, or UI fixtures. | Create a broker issue for a metadata-only rotation dry-run and operation contract. The first slice should plan local encrypted-store rotation/reset plus provider capability results and should not implement broad provider apply behavior. |

## Near-term follow-up issues

- Automated credential rotation dry-run and operation contract: [lasso-secretsbroker#68](https://github.com/service-lasso/lasso-secretsbroker/issues/68).
- Secrets Sync / GitHub Actions design baseline and first executable slice: [lasso-secretsbroker#95](https://github.com/service-lasso/lasso-secretsbroker/issues/95) and `docs/secrets-sync-design.md`.
- Enterprise security readiness assessment for HSM, FIPS, MFA, and automated credential rotation: [lasso-secretsbroker#96](https://github.com/service-lasso/lasso-secretsbroker/issues/96) and `docs/enterprise-security-readiness.md`.

The other capabilities are intentionally classified as Later or Out of scope until their dependencies and approval gates are explicit. They should not block current broker operational-control issues (#62-#66) or Service Admin UI work.

## Parking and unblock criteria

| Capability | Parked until |
| --- | --- |
| Service Lasso MCP | Runtime API facade, safe diagnostics, and action-required queue are stable and reviewed. |
| Secrets Broker MCP | Full MCP transport server remains parked until transport auth, human consent, and operation approval UX are reviewed; the current headless adapter exposes read-only metadata tools only. |
| Secrets Sync / GitHub sync | Provider-neutral dry-run contract, audit/events/lockout, provider capability model, and destination policy are ready. |
| HSM | Approved key-provider strategy, vendor choice, recovery model, and fixture approach exist. |
| FIPS | Formal compliance objective, validated crypto/build strategy, and evidence process exist. |
| MFA | Operator identity/auth boundary and management-only MFA scope are approved. |

## Non-goals

- Do not claim HashiCorp Vault Enterprise parity, OpenBao parity, HSM-backed custody, FIPS compliance, MFA enforcement, GitHub secret sync, or automated credential rotation until the concrete implementation and validation exist.
- Do not add plaintext export/import or spreadsheet-style editing as part of any advanced capability.
- Do not expose provider credentials or raw secret values through MCP, sync, roadmap probes, telemetry, events, diagnostics, CLI output, UI fixtures, issue comments, or PR bodies.
