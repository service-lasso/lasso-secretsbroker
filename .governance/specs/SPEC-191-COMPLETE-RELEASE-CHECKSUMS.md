# Complete compatibility release checksum inventory

Active Development specification for issue #191.

- CHECKSUM-1: Official releases retain exactly seven payloads. Compatibility releases require exactly thirteen payloads: those seven plus the compatibility archive, SBOM, profile, toolchain provenance, trust probe and native receipt. No partial compatibility set is accepted.
- CHECKSUM-2: Write and verify reject missing, unexpected, duplicate, path, symlink and tampered evidence. The publisher explicitly requires the compatibility inventory, including when all compatibility files are missing.
- CHECKSUM-3: After immutable publication, download every public asset into a fresh directory and verify the downloaded checksum manifest against all thirteen downloaded payloads. Preserve existing receipt, security, native and attestation gates.
- CHECKSUM-4: The defective 2026.10.5-17fb426 release stays immutable. A replacement candidate needs fresh original gates and native/public consumer qualification; source tests do not establish published acceptance. Issue #190 remains deferred.
