# Issue 194 source handover

Mode: Development. Owner: issue-194 author; parent owns independent review,
hosted candidate, actual Mac qualification, merge and publication.

Base: develop 9c0b0e6c6b9ac5aae746a8f9317cdb0ca0ba909d.
Branch: fix/194-native-ipc-profile. Active spec: SPEC-194 IPC-1/2/3.
Owned isolated checkout: broker194-native-ipc-profile. Other checkouts and
historical releases are retained. No Core product edits or local Linux build.

## Findings and bounded changes

The raw public 9c compatibility profile declares required API TCP 17890 and HTTP
health. Original Core launches production/auto native Unix IPC. It stops the ready
Broker after failed legacy start checks and returns canonical bootstrap 503.
Earlier successful Core9 evidence used curated lesson transport plus artifact
selection. Its binary/native16 and complete public13 checksum proofs remain
valid for their bounded claims; raw profile integration remains unqualified.

Only the explicit compatibility producer now declares production/auto and required
process health, omitting network endpoints/listener interpolation. Original Core
performs authenticated IPC readiness after process start; this check is retained.
Default service.json, modern official packaging, the four-file maintained-Go
patch, dependencies, archive/checksum code, auth policy and all 16 receipt gates
remain intact. Both generated manifests use the same serialized payload.

The protected publisher rejects old receipts and requires an additional strict
coreProfile object; all 16 gates still must pass. Required object:

```json
{
  "manifestSHA256": "<SHA256 of downloaded service-darwin-amd64-macos11.json>",
  "runtimeProfile": "unchanged-produced-manifest",
  "acquisitionOverride": "candidate-artifact-api-selector-only",
  "corePackage": "@service-lasso/service-lasso@2026.9.22-f3de461",
  "canonicalAdminBootstrap": true,
  "signedSecretRefLookup": true,
  "brokerRestartRetention": true,
  "fullCoreReopenRetention": true
}
```

Only candidate artifact acquisition API selection may be overridden for held
prepublication bytes. Do not replace execconfig, env, endpoints or health from a
curated lesson. Original Admin canonical POST /api/setup/bootstrap, signed lookup,
Broker restart and full Core stop/reopen retention require direct native evidence.

## Source evidence and limits

- Verified: integrity/version/gitHead of npm published Core 2026.9.22-f3de461.
  gitHead f3de46166c03d3feca5b27fa72f941e0ce8472ae; registry SHA512 integrity
  Y9sawMjrZkPd95fNHCWHGHjT6CL4cPkYr7i+BvZhImJvU7agiHCzpuC8/X7Tlgip+KD7iRQA8EAIEJeqZZz4DA==.
  Its brokerBaseEnvironment and canonical bootstrap code confirm native transport
  injection and a separate authenticated readiness probe.
- Verified: Python profile/receipt suite, 3 tests with identity, old TCP/HTTP,
  curated profile, wrong hash, missing reopen and nonboolean receipt negatives.
  Both PR validation and the protected producer execute these tests.
- Verified: generated raw manifest accepted by the exact published Core
  validateServiceManifest; required process health normalized correctly.
- Verified: git diff whitespace check and focused self-review.
- Partial proof only: these tests verify source/manifest contracts, not actual
  process start, cryptographic IPC, secret retention or Mac support.
- Deferred to parent: fresh independent review; hosted exact-head build;
  fresh Big Sur original raw-profile Core/Admin first-run, signed lookup,
  Broker restart/full Core reopen retention, complete native16 receipt;
  protected publication; pristine public raw profile and all 13 asset checksums.

Next action: independent review of the frozen PR, then exact hosted candidate
qualification. Issue #194 and reopened #188 remain open until direct acceptance.
Owned inspection files under ignored .tmp and Python cache under local scoped
exclude are retained as source-verification evidence. The open-PR branch/checkout
is intentionally retained for the parent; no merge/publication/readiness claim.
