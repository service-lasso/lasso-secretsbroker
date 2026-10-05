# Core native IPC compatibility profile

Status: active Development; Broker issue #194. Supplements SPEC-188 COMPAT-5/7/8.

- IPC-1: The explicit Intel macOS 11 producer manifest selects production/auto
  transport, preserves Core-owned credentials/socket selection, and declares
  process health without TCP endpoints, HTTP health, or listener interpolation.
  Core 2026.9.22-f3de461 performs its authenticated IPC probe after process start;
  process health alone is not readiness evidence. Default service.json and all
  official artifacts remain unchanged.
- IPC-2: Packaging emits identical archive and public compatibility manifests,
  pinned to the exact candidate SHA/tag and compatibility archive. Regression
  tests cover inherited HTTP removal, default preservation and tag rejection.
- IPC-3: The existing 16-gate native receipt additionally binds the unchanged
  produced manifest digest to original published Core/Admin canonical bootstrap,
  signed SecretRef lookup, restart and full Core reopen/secret retention. Only
  the candidate artifact acquisition API selector may differ before publication;
  curated lesson runtime/transport overlays cannot qualify the raw profile.
  Repeat with the pristine public profile after publication, verify all 13 public
  checksums, and retain prior immutable releases and failed raw-profile evidence.

Published Core inspected from integrity-verified npm package
@service-lasso/service-lasso@2026.9.22-f3de461, gitHead
f3de46166c03d3feca5b27fa72f941e0ce8472ae. runtime/broker/runtime.js
brokerBaseEnvironment supplies production/auto and credential-specific native
socket identity. server/index.js POST /api/setup/bootstrap separately requires
successful start and authenticated brokerRuntime.probe(). No Core edits or
authentication weakening are in scope.

Source tests are partial proof only. Fresh independent source review and the
parent-owned hosted candidate/native/public qualification remain mandatory.
