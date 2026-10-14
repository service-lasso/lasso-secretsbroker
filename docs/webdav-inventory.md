# RAM WebDAV inventory

Active development, issue #198; user request 2026-10-08.

WDI-1: GET `/v1/file-grants/status` requires the existing local operator credential.
Return metadata only: listener availability, capacity/used bytes, active grant
and file totals, service/workspace ownership, filenames, sizes, creation time,
completed GET count, bytes written and last completed read. No values, tokens,
token hashes, capability URLs or instance credentials appear.

WDI-2: complete successful GET writes increment downloads. HEAD, OPTIONS,
PROPFIND, denied requests and failed writes do not. Served bytes count bytes
accepted by the HTTP writer, not proof the client saved the file. Counters belong
to active grants and reset on rotation, revocation and Broker restart. Metadata
remains in RAM and is never persisted.

WDI-3: bounded offset pagination (100 files by default, maximum 200) keeps
responses below the protected IPC budget. Concurrent grant changes can alter
pages; refresh observes the current inventory.

WDI-4: Service Admin uses Core's workspace-read management proxy. The UI lists
metadata and usage; it offers no upload or secret download. Positive and
negative tests verify accounting, auth, bounds, rotation, revocation and privacy.

Verification: the first full Go suite and vet passed on Windows; the latest
full Broker package test passed on native Ubuntu with actual contract fixtures.
A Windows full rerun hit unchanged retention audit Access denied (#199); that
retention test passed three focused repetitions. RAM positive/negative
tests passed on Ubuntu; native Windows UNC reads passed. Core's authenticated
management route matrix passed over Unix IPC and Windows named pipes. Real Echo
consumption on Ubuntu matched completed downloads and byte counts, and stop
removed its inventory. Source-built evidence does not qualify a published
package or deployment. Canonical API schemas/fixtures include the route.
