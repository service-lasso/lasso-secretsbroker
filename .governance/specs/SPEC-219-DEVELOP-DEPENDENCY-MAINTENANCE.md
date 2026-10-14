# Develop dependency maintenance (#219)

Mode: Development. Owner: this merge-maintenance session, authorized 2026-10-15.

## Requirements and acceptance

- DEP-1: Recreate Broker PRs #205-#211 on separate issue branches from the latest develop, targeting develop. Apply only the requested version or immutable action pin to the current files; do not import release-branch history.
- DEP-2: go-winio v0.6.3 and x/sys v0.49.0 retain the corresponding donor go.sum entries. Other module requirements remain unchanged.
- DEP-3: download-artifact 8.0.2, upload-artifact 7.0.2 and CodeQL autobuild/init/analyze 4.38.3 use the exact donor commit pins. Preserve current workflow commands, publication guards, inputs and artifact contracts.
- DEP-4: Set both Dependabot ecosystems to target develop. Future dependency work follows the normal branch boundary.
- DEP-5: Review every scoped diff, run git diff --check, push each commit, create and attach replacement PRs, merge matching exact heads, and verify landing on develop.

CI is explicitly excluded by the owner. This maintenance does not establish tests, build, runtime, native, release, publication or deployment qualification. Core release PR #1577 is outside scope.

## Replacement mapping

| Original | Update | Requirement |
| --- | --- | --- |
| #205 | go-winio v0.6.3 | DEP-2 |
| #206 | x/sys v0.49.0 | DEP-2 |
| #207 | download-artifact 8.0.2 | DEP-3 |
| #208 | CodeQL autobuild 4.38.3 | DEP-3 |
| #209 | CodeQL init 4.38.3 | DEP-3 |
| #210 | upload-artifact 7.0.2 | DEP-3 |
| #211 | CodeQL analyze 4.38.3 | DEP-3 |

Replacement PR URLs are recorded in issue #219 and their PR descriptions.
