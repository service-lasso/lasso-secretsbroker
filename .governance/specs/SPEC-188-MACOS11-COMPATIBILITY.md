# Proposed Go 1.26.8 Darwin 11 compatibility delta

Status: active Development specification, issue #188; conceptual architecture reviewed with the following mandatory corrections before implementation.

## Acceptance corrections

- COMPAT-1: Every systemVerify owns a private unshared SecTrust. Evaluate before borrowing chain count/index; copy certificate DER before deferred trust release. Never CFRelease borrowed certificates.
- COMPAT-2: Native host-root rows use Roots:nil. CurrentTime uses existing SecTrustSetVerifyDate. Explicit custom roots bypass native verification; SystemCertPool additions cannot qualify native acceptance.
- COMPAT-3: Linker change belongs to domacho. Only internally linked CGO-disabled amd64 compatibility binaries synthesize minOS/SDK 11/11. ARM64 remains 12; external linker metadata and all official modern variants stay unchanged.
- COMPAT-4: Official Linux amd64 Go archive SHA256 is d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b. Rebuild owned cmd/link and record explicit internal linking and private tool/cache provenance.
- COMPAT-5: Require native host-root positive and chain comparison, wrong hostname, inside/outside leaf validity at equivalent native dates with issuer valid, unknown self-signed Roots:nil, distinct Go custom-root EKU and native process-local-anchor EKU pairs, repeated/concurrent independent chain ownership. Compare official/custom decisions on supported native amd64/arm64. Actual Big Sur requires both CLIs, serve/bootstrap, signed IPC/resolver, stop/restart/retention and zero owned processes.
- COMPAT-6: No clock/trust-store/shared-toolchain mutations, security downgrade, release-branch input or gate waiver. Retain original failures privately. Modern artifact packaging is unchanged. Maintenance owner is the Service Lasso release owner; every upstream patch requires guard refresh, source review and repeated native qualification before publication.

## Immutable inputs

Official source: go1.26.8.src.tar.gz SHA256 4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e. Broker input 9c1bdb60c4c661c19e4cd45109fdd16544089e6f. Obtain the official Go 1.26.8 Linux distribution's exact archive SHA from go.dev/dl/?mode=json at implementation time; independently verify it. No shared distribution or cached toolchain mutation.

## Exactly four upstream files

1. src/crypto/x509/internal/macos/security.go: remove strong SecTrustCopyCertificateChain declaration/wrapper; restore SecTrustGetCertificateCount(trustObj CFRef) int and SecTrustGetCertificateAtIndex(trustObj CFRef, i int) (CFRef,error), their dynamic imports and trampoline declarations from the documented upstream parent diff. Do not restore unrelated deleted trust-settings functions.
2. src/crypto/x509/internal/macos/security.s: replace chain-copy trampoline with count/index trampolines. Keep SecTrustEvaluateWithError trampoline unchanged.
3. src/crypto/x509/root_darwin.go, Certificate.systemVerify: after successful SecTrustEvaluateWithError, get count, iterate index, export each certificate before trustObj release, append verified chain. Remove copy-array CFRelease only. Preserve error mapping, empty-chain failure, Go VerifyHostname, checkChainForKeyUsage and all upstream verification logic. Count/index return borrowed references; keep trustObj alive and never release borrowed certificates separately. Null or export failure must fail closed.
4. src/cmd/link/internal/ld/macho.go: review minimum OS/SDK metadata adjustment in domacho LC_BUILD_VERSION construction, currently version=12<<16 for sys.ARM64,sys.AMD64. Compatibility artifact must explicitly identify 11 minimum only for qualified architectures. SDK field semantics must be justified; matching earlier Go 11.0 emitted metadata is one reviewable option, not permission to misstate an actual external SDK. Modern upstream artifacts retain their original metadata. Adjust corresponding linker minOS test expectation in owned compatibility verification without widening the four-file production delta.

Static legacy chain access on both Darwin slices is simplest and avoids introducing optional symbol lookup into trust code. Existing older APIs remain supported-by-availability but deprecated. A dual weak-linked path is an alternative requiring separate resolver/ABI/null-lookup proof; merely branching by OS with a strong import cannot prevent dyld failure.

## Build strategy

Copy verified official Go 1.26.8 Linux distribution into an owned private directory. Verify pristine sources match official source hashes and the expected four file preimages. Apply the separately hashed four-file patch with exact-context/hash guards. Do not rewrite compiler/runtime unrelated source. Recompile cmd/link only using the owned official Linux Go 1.26.8 distribution, with GOTOOLCHAIN=local, explicit owned GOROOT, private GOCACHE and GOMODCACHE. Place newly compiled linker in the owned tool directory; do not install it into a shared GOROOT. Cross-building with this copied distribution compiles the patched x509 stdlib from source using the private cache, so no old precompiled x509 artifact can mask the delta. Record pristine archive/source hashes, patch hash, patched source/linker hashes, resolved tool paths, build command/env, Broker SHA, dependencies and both binary/archive hashes. This is an accurate custom Go variant based on maintained upstream 1.26.8; the release metadata must say so, even if runtime.Version retains the upstream string.

CI must compare official and compatibility decisions on supported native darwin/amd64 and darwin/arm64; Big Sur Intel acceptance is additional. Publish only a separate darwin-amd64-macos11 compatibility artifact; modern universal slices retain official Go and minOS 12. ARM64 compatibility evaluation retains minOS 12. Current patched APIs/runtime/linker source are identical between 1.26.6 and 1.26.8; this observation never waives future upgrade inspection.

## Gates and maintenance

Conceptual architect/security review approved the narrow trust-chain retrieval design conditionally; this active spec incorporates those conditions. A fresh final implementation/evidence review remains required. Acceptance on actual Big Sur: both --help commands, Broker serve/bootstrap, resolver, signed IPC, original Core/Admin flow, restart/stop/ownership, trusted HTTPS through untouched host roots, rejection of wrong hostname, untrusted leaf, expired leaf and bad EKU, correct chain data and memory lifetimes. System-root matching means testing an otherwise valid chain under actual host roots against native SecTrust behavior; explicit process-local custom roots alone do not prove that boundary. Negative local fixtures and VerifyOptions.CurrentTime tests avoid trust-store or clock mutation. Do not weaken TLS settings.

Each upstream security update requires archive/source checksum refresh, exact patch preimage guards, source-change review, rebuilding owned linker, isolated stdlib compilation and repeated exact-candidate native/negative TLS tests. Named maintenance owner and failing gates are required. Go 1.26 is supported only until two newer major releases exist; an owned successor plan is necessary before its upstream support ends. No official macOS 11 support, GA, or operating-system security reassessment is implied.

API reference: https://developer.apple.com/documentation/security/sectrustgetcertificateatindex(_:_:)?language=objc explicitly requires prior SecTrustEvaluateWithError and describes the borrowed chain access. Upstream delta: https://go.googlesource.com/go/+/937368f84e545db15d3f39c2b33a267ba8ead4a4%5E%21/
