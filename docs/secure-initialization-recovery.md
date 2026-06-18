# Secure Initialization and Recovery-Key Model

Status: design recommendation
Issue: #55, #92
Service id: `@secretsbroker`

## Purpose

This note defines the recommended initialization and recovery-key model for the local-first Secrets Broker. It answers whether PGP-based initialization should be the primary path, how operators can initialize without Keybase, how recovery material should be generated and stored, and what must stay out of UI, logs, diagnostics, and support artifacts.

This is a design contract, not a production-readiness claim. The implemented foundation remains the portable master key, local encrypted store, local wrapper, backup/restore, rotation flows, threshold recovery share generation/import, and recovery policy metadata surfaces documented in `docs/portable-master-key.md`, `docs/master-key-lifecycle.md`, `docs/backup-restore-rotation.md`, `docs/local-api-bootstrap-contract.md`, and `docs/threat-model.md`.

Decision scope for #92: secure initialization and recovery must not depend on Keybase, public keyserver discovery, plaintext recovery UIs, or provider-specific vault assumptions. PGP is allowed only as a future optional share-envelope backend after the local-first ceremony remains safe without it.

Current implementation note for #59/#60 and this #92 planning pass: the broker can generate CLI-first threshold recovery shares, optionally encrypt each share to an operator-supplied age/X25519 recipient, import plaintext or recipient-enveloped share files, verify the reconstructed portable master key against store metadata/decryptability, and refresh a local wrapper only after verification succeeds.

## Recommendation

Use a local-first initialization flow built around:

1. A randomly generated 256-bit portable master key.
2. A local OS/user wrapper for routine unlock on each enrolled machine.
3. Threshold recovery shares for break-glass recovery.
4. Optional recipient-encrypted share envelopes for operators who want each share protected at rest.
5. Metadata-only audit and diagnostics.

Do not make PGP or Keybase the primary initialization dependency.

PGP can be supported later as an optional recipient-envelope backend for organizations that already manage PGP keys well, but it should not be the default because it brings key discovery, expiry, revocation, UX, and tooling complexity into the most sensitive bootstrap path. Keybase should not be required at all.

For the default no-Keybase path, prefer:

- Shamir threshold recovery shares for reconstructing the same portable master key.
- `age`/X25519 recipient encryption as the first optional share-envelope format, because it is compact, file-based, and does not depend on public keyservers or social identity systems.
- OS key stores/wrappers for daily machine-local unlock where available.

## Option Decision Matrix

| Option | Recommended role | Why | Guardrails |
| --- | --- | --- | --- |
| PGP recipient encryption | Future optional share envelope only | Useful for organizations that already have disciplined offline PGP key custody, but too much trust, expiry, revocation, and discovery complexity for default bootstrap. | Operator-supplied public key files only; no Keybase lookup; no keyserver lookup; audit safe fingerprints only; no private keys or passphrases in broker state. |
| Local `age`/X25519 recipient keys | Default optional share envelope | Small, explicit recipient strings/files, no social identity dependency, and already fits the implemented recipient-enveloped share flow. | One recipient per share output; private identities supplied only at import time; store only recipient fingerprints/envelope metadata. |
| Minisign-style signing keys | Integrity/signature adjunct, not recovery encryption | Good for authenticating release/config artifacts, but not a complete recovery-share confidentiality mechanism by itself. | Use only to sign ceremony bundles or policy metadata after a separate encryption/recovery model exists. |
| OS keystore-backed wrapping | Routine local unlock on enrolled machines | Keeps daily unlock local to the current OS/user/machine while preserving portable recovery through shares. | Treat wrappers as machine-local convenience, not backup; unsupported wrappers fail closed and keep CLI/share recovery available. |
| Offline recovery shares | Required break-glass recovery model | Separates recovery authority across holders and avoids binding recovery to one user's account or device. | Threshold policy required; share material stored separately from store/backups/wrappers; rotate shares with the portable master key. |
| Remote/cloud KMS or Vault/OpenBao unseal as the default | Not default for local-first bootstrap | Creates an external availability and custody dependency before Service Lasso can initialize its own local broker. | May be a later enterprise backend/source option behind `@secretsbroker`, not the baseline initialization dependency. |
| Plaintext recovery page, bulk share export, Keybase lookup, public keyserver lookup, storing recovery material in Service Admin | No-go | These paths make the most sensitive material easy to leak, hard to audit, or dependent on external identity systems. | Must not be implemented. Service Admin may show metadata and guide local CLI ceremonies only. |

## Threat Assumptions

The default model assumes:

- The broker is local-first and managed by Service Lasso on operator-controlled infrastructure.
- A privileged local attacker can read process memory, environment variables, command lines, and files the OS permits. The model can reduce accidental exposure and offline theft risk, but it cannot defeat a fully privileged host compromise.
- Encrypted stores and backups may be copied. They must remain unusable without matching portable master key material or valid recovery shares.
- Recovery share holders are trusted to protect their share out of band.
- Service Admin is optional and must not become the only way to unlock or recover the broker.
- Vault/OpenBao can be a backend/source later, but the Service Lasso-facing broker contract remains `@secretsbroker`.

## Operator Ceremony

The supported ceremony is local, explicit, and auditable:

1. Prepare an empty local store path, audit path, and wrapper path on the operator-controlled host.
2. Generate or import the portable master key through the CLI; do not pass it through shell history or UI fields.
3. Choose a threshold policy before storing production secrets, for example 2-of-3 for small deployments or 3-of-5 where more separation is needed.
4. Write each recovery share to an operator-selected target. Prefer offline removable media or a dedicated offline password-manager item per holder.
5. Optionally encrypt each share to an explicit `age`/X25519 recipient before the share file is written.
6. Store encrypted backups away from key/share/wrapper material.
7. Verify recovery on a separate test store or controlled recovery host before relying on the ceremony.
8. Record only safe fingerprints, policy id, threshold, share count, wrapper kind, outcome, and reason metadata in broker state and audit.

The ceremony must remain possible without Service Admin. Service Admin may later guide state and next actions, but sensitive material entry, share generation, share import, and identity private-key use stay in local CLI/broker-controlled flows unless a separately approved secure local UI bridge exists.

## Storage Boundaries

Keep these materials separated:

| Material | Storage boundary | May appear in API/UI/audit? |
| --- | --- | --- |
| Encrypted local store | Broker data directory or backup artifact | Metadata only: key id/version, counts, lifecycle state. |
| Portable master key | Operator-selected secure file, OS secret store, or in-memory unlock input | No. Never render or audit key bytes. |
| Local wrapper | Current machine/user-specific broker data path | Metadata only: wrapper kind, OS, key id, support status. |
| Recovery share plaintext | Holder-controlled offline destination only | No. Never in broker state, Service Admin, logs, diagnostics, or support bundles. |
| Recipient-enveloped recovery share | Holder-controlled file destination | Envelope format and safe recipient fingerprint only. |
| Recipient private identity | Holder-controlled import-time input | No. Never stored by the broker. |
| Backup artifact | Backup destination separate from key/share material | Artifact metadata only; still sensitive operational data. |

## Initialization Workflow

The recommended first implementation should be CLI-first and UI-safe:

1. Operator runs a local initialize command.
2. Broker generates a portable master key in memory.
3. Broker initializes the empty encrypted local store.
4. Broker enrolls a local wrapper for the current OS/user/machine when supported.
5. Operator chooses a recovery policy, for example 2-of-3 or 3-of-5.
6. Broker generates threshold recovery shares for the portable master key.
7. Broker writes each share only to the explicit output target selected by the operator.
8. Broker stores only safe recovery metadata in broker state.
9. Broker emits audit events with operation, outcome, key id fingerprint, threshold, share count, wrapper kind, and request id.

Safe recovery metadata may include:

- key id fingerprint
- recovery policy id
- threshold and share count
- share fingerprints
- recipient fingerprints where recipient envelopes are used
- creation, rotation, and revocation timestamps
- operator-supplied reason text after redaction and length limits

Safe metadata must not include:

- portable master key bytes
- recovery share contents
- unwrapped share plaintext
- recipient private keys
- passphrases
- local API tokens
- source provider credentials
- plaintext secret values

## Recovery Workflow

Recovery should reconstruct or import the same portable master key. It should not create a new key unless the operator explicitly chooses a rotation after successful recovery.

Recommended flow:

1. Operator starts broker against an encrypted store without usable local wrapper material.
2. Broker reports `locked` with safe key id and next action metadata.
3. Operator supplies the threshold number of recovery shares through a local CLI prompt or explicit files.
4. Broker reconstructs the portable master key in memory.
5. Broker verifies the key against store metadata and decryptability before writing anything.
6. Broker writes or refreshes the current machine wrapper only after verification succeeds.
7. Broker audits recovery success or failure without share contents.

Failure behavior:

- Too few shares: fail `locked`, no state mutation.
- Shares for the wrong key id: fail `locked`, no state mutation.
- Corrupted store or unverifiable payloads: fail `degraded`, no wrapper mutation.
- Unsupported wrapper provider: keep the store recoverable through explicit portable-key or recovery-share unlock, but do not claim durable local unlock.

CLI recovery share generation writes share material only to explicit operator-selected files:

```powershell
secretsbroker key recovery generate `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt `
  --policy-id break-glass-2026 `
  --threshold 2 `
  --share-out .\secure\share-1.json `
  --share-out .\secure\share-2.json `
  --share-out .\secure\share-3.json
```

Operators who want share files encrypted at rest can provide one age/X25519 recipient per `--share-out`, in the same order:

```powershell
secretsbroker key recovery generate `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --master-key-file .\secure\portable-master-key.txt `
  --policy-id break-glass-2026 `
  --threshold 2 `
  --share-out .\secure\share-1.json `
  --age-recipient age1...holder1 `
  --share-out .\secure\share-2.json `
  --age-recipient age1...holder2 `
  --share-out .\secure\share-3.json `
  --age-recipient age1...holder3
```

CLI recovery import reconstructs the key in memory, verifies the store, then writes or refreshes the local wrapper:

```powershell
secretsbroker key recovery import `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --wrapper .\data\secretsbroker-wrapper.json `
  --share-in .\secure\share-1.json `
  --share-in .\secure\share-2.json
```

For recipient-enveloped shares, the operator supplies local age/X25519 identity material at import time. Recipient private keys are never written to broker state or audit:

```powershell
secretsbroker key recovery import `
  --store .\data\secretsbroker-store.json `
  --audit .\data\secretsbroker-audit.jsonl `
  --wrapper .\data\secretsbroker-wrapper.json `
  --share-in .\secure\share-1.json `
  --age-identity-file .\secure\holder-1-age-identity.txt `
  --share-in .\secure\share-2.json `
  --age-identity-file .\secure\holder-2-age-identity.txt
```

The share files contain recovery material and must be stored separately from encrypted stores and local wrappers. Broker state, audit events, responses, diagnostics, and Service Admin surfaces must carry only safe policy/share fingerprints and status metadata.

## Rotation Workflow

Recovery material must rotate with the portable master key:

1. Verify the current key can decrypt all local payloads.
2. Generate or accept a new portable master key.
3. Re-encrypt all local payloads under the new key.
4. Generate a new recovery bundle for the new key.
5. Enroll or refresh local wrappers for approved machines.
6. Write audit events for old key id, new key id, threshold metadata, and outcome.
7. Keep old key material only until backups and recovery shares for the new key are verified.

Partial rotation must fail closed. A rotation must not leave mixed-key payloads unless the payload format and recovery docs explicitly support staged key versions and validation proves all active versions are recoverable.

## PGP and No-Keybase Decision

PGP is not recommended as the default initialization path.

Reasons:

- It usually needs extra key management decisions before bootstrap can begin.
- Public key discovery often depends on systems outside Service Lasso control.
- Keybase is not a suitable required dependency for local/on-prem Service Lasso deployments.
- PGP revocation, subkeys, expiry, and trust signatures are easy to mishandle in an operator setup wizard.
- A PGP-first design can make recovery depend on personal key hygiene rather than an explicit Service Lasso recovery policy.

Acceptable future PGP role:

- Optional recipient envelope for a recovery share.
- Explicit operator-provided public key file only.
- No keyserver lookup during initialization.
- No Keybase lookup.
- Audit only safe key fingerprint metadata.

Recommended default role for `age`/X25519:

- Optional recipient envelope for a recovery share.
- Operator supplies recipient strings or public key files directly.
- Broker stores only recipient fingerprints and envelope metadata.
- Share plaintext is never persisted by the broker unless the operator explicitly chooses a plaintext share output target.

## Explicit No-Go Options

Do not implement these as part of initialization or recovery:

- Keybase-dependent setup or recovery.
- Public keyserver discovery during bootstrap.
- PGP private-key import into broker state.
- A web page that displays portable master keys, recovery share plaintext, recipient private identities, passphrases, source credentials, or API tokens.
- Bulk copy/export of all recovery shares from Service Admin.
- Storage of recovery share plaintext, portable master keys, passphrases, private keys, provider credentials, or local API tokens in routes, query strings, page titles, breadcrumbs, browser storage, logs, diagnostics, fixtures, support bundles, issue comments, or screenshots.
- Automatic rotation that invalidates existing recovery shares before the new recovery bundle is generated and verified.

## UI and Service Admin Rules

Service Admin may eventually guide initialization, but it must not become a plaintext recovery-material surface.

Allowed UI behavior:

- Show lifecycle state, key id fingerprint, wrapper status, threshold policy metadata, and recovery next actions.
- Start a local-only initialization or recovery ceremony that delegates sensitive material handling to the broker/CLI.
- Show whether required shares were accepted, rejected, or insufficient.
- Show audit status and recovery policy health.

Disallowed UI behavior:

- Render the portable master key by default.
- Render recovery shares in tables, routes, page titles, breadcrumbs, logs, diagnostics, screenshots, support bundles, local storage, or session storage.
- Upload shares or keys to a remote Service Admin backend.
- Copy/export all recovery shares from a bulk UI.
- Treat provider credentials, tokens, cookies, passphrases, private keys, or source secrets as diagnostic content.

## Audit Contract

Initialization and recovery audit events should include safe metadata only:

- operation name, outcome, and timestamp
- request id
- key id fingerprint
- wrapper kind and support status
- recovery policy id
- threshold and share count
- share fingerprints
- recipient fingerprints
- reason code or operator reason after redaction
- failure code and next action

Audit events must never include:

- plaintext secret values
- portable master key material
- recovery share plaintext
- recipient private keys
- passphrases
- API tokens
- source provider credentials
- raw request bodies that may contain sensitive material

## Implementation Slices

Recommended follow-up implementation sequence:

1. Recovery policy and share metadata contract. Completed for the local-first baseline.
2. CLI-first threshold recovery share generation and recovery import. Completed for the local-first baseline in #59.
3. Optional `age`/X25519 recipient envelopes for individual shares. Completed for the local-first baseline in #60.
4. Wrapper and recovery-policy status surfaces to API/CLI. Completed for the current metadata-only status contract.
5. First remaining executable slice after #92: add an end-to-end initialization ceremony command or guided CLI flow that creates the local store, enrolls or verifies the local wrapper, generates/envelopes recovery shares, persists safe recovery policy metadata, and writes one summarized audit trail without exposing key/share material. This slice should include a dry-run/preview mode for paths/policy, no-secret serialization tests, fail-closed tests for invalid thresholds/recipient counts/output paths, and documentation that Service Admin can invoke or link to the ceremony only after the CLI contract is proven.
6. Add a Service Admin initialization guide only after the broker CLI/API ceremony is proven. The UI guide must remain metadata-only and must not collect or render recovery material.

Each implementation slice must include no-secret serialization tests and negative tests for wrong shares, insufficient shares, corrupted stores, unsupported wrappers, and audit redaction.
