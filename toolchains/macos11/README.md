# Explicit maintained-Go Intel macOS 11 variant

This is a custom compatibility variant based on maintained official Go 1.26.8.
It restores evaluated native certificate-chain enumeration through borrowed legacy
Apple references and sets synthesized internal Intel minOS/SDK metadata to 11/11.
It does not claim official Go support for macOS 11. ARM64 remains minOS 12, and
the ordinary universal macOS artifact continues to use the official toolchain.

Use `scripts/build-macos11-compat.sh /absolute/new/owned/directory` on Linux amd64,
from a clean exact candidate checkout, then set `SERVICE_LASSO_RELEASE_VERSION` to
the exact preselected candidate tag and run `scripts/package-macos11-compat.sh`
with that directory. The compatibility manifest pins that tag before packaging,
receipt verification, checksums and attestation; it does not use a latest channel.
The builder downloads and verifies both official archives,
checks raw source equality and four-file preimages, verifies a pinned patch hash,
rebuilds private cmd/link and records build commands, effective environment, source
tree, source/patch/linker/binary hashes and private tool-selection logs. No shared
Go installation is changed. Each security update requires deliberate source guard
and patch inspection plus repeated native gates; automatic patch fuzz is forbidden.

Compatibility asset: `secretsbroker-darwin-amd64-macos11.tar.gz`; explicitly select
`service-darwin-amd64-macos11.json` only for Intel hosts. The default service manifest
selects official modern artifacts. Compatibility files include a read-only Intel
macOS version helper, provenance and a clearly labeled profile statement.

Native acceptance uses untouched host roots with `Roots:nil`, exact Apple ordered
DER comparison, wrong hostname, inside/outside leaf validity dates with valid issuers,
unknown self-signed rejection and 101 independent concurrent verifications. Custom
Go-root EKU checks and native process-local anchor EKU checks are separate policy
rows. Certificate acquisition disables verification only for capturing public DER;
Apple verification and default Go HTTPS supply the actual trust decisions.

The development publisher retains Windows/Linux/modern macOS security and released
harness gates, adds native Intel/ARM comparisons, and waits at the existing owner
protected `development-candidate` environment. The owner obtains the run's exact
compatibility files and records all actual Big Sur CLI, Broker, signed IPC, Core/Admin,
retention/restart/stop and zero-process evidence before posting the native receipt.
Receipt format is `BROKER188_NATIVE_RECEIPT` on the first line and JSON on the next;
the verifier in `scripts/verify-macos11-receipt.py` defines the strict schema. It binds
actual GitHub author ID 170312, full candidate SHA, workflow run ID, every named
compatibility asset digest, linker/binary digests, Intel macOS 11 version and all
sixteen required boolean gates. Missing, mismatched or false gates block publication.
The validated receipt is included in the asset inventory/checksums/attestation.

Development publication creates an immutable prerelease with `--latest=false`.
It does not declare GA. Full published consumer tutorial acceptance remains distinct.

The signed resolution gate means canonical Core first-run Broker enrollment and
actual Core signed Unix IPC resolution of a nonempty SecretRef. Both CLI gates
verify their existing help/linkage contracts only. The legacy OpenClaw exec CLI
does not carry the required identity lease; it is not used by Todo and remains
explicitly unqualified in deferred [issue #190](https://github.com/service-lasso/lasso-secretsbroker/issues/190).
Empty-input success is never evidence of functional secret resolution. A future
OpenClaw repair requires its own per-request identity blueprint and must preserve
Broker authentication.
