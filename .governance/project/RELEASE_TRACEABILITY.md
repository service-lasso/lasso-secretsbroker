# Issue 188 traceability

Issue: https://github.com/service-lasso/lasso-secretsbroker/issues/188

Active spec: ../specs/SPEC-188-MACOS11-COMPATIBILITY.md COMPAT-1 through COMPAT-6.

State: prerequisites complete; implementation and all native/security/runtime gates pending. No candidate publication or technical readiness claim.

## Issue 194 native profile correction

SPEC-194 IPC-1/2 source contracts: scripts/macos11-compat-profile.py,
scripts/package-macos11-compat.sh and verify/macos11/test_profile.py.
IPC-3 receipt/publication boundary: scripts/verify-macos11-receipt.py,
verify/macos11/test_receipt.py and release-development workflow.
Current scope/evidence/required parent gates: ISSUE-194-QUALIFICATION.md.
Raw producer-profile Core integration remains qualification-incomplete; curated
lesson runtime overlays do not satisfy it. Prior native binary and checksum
evidence is retained without promoting it to raw-profile acceptance.
