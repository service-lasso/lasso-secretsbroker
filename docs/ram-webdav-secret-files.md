# RAM secret-file delivery

**DAV-6 (#201):** owner-corrected provisioning receives declared selector/ref
bindings and secret-free file templates. Authorize all referenced secrets with
the existing service/workspace/peer-bound lease, resolve internally, render
once without recursively substituting secret values, enforce rendered bounds,
and return a WebDAV directory with the grant. Missing/denied/locked required or
used refs fail without replacing a prior grant. Values never appear in the
grant response, metadata or persisted output. Legacy rendered-file inputs remain
compatible, while Core's new default uses Broker resolution. Verify actual Echo
reads through the returned path and negative authorization/rendering cases.

DAV-6 verification: targeted RAM/contract tests, vet and pinned gosec passed on
Windows; RAM tests passed as an actual Linux executable on Ubuntu. Real Core
and the complete prepared Echo manifest consumed the file through the returned
path, advanced safe counters and denied a missing required ref before spawn.
The full Windows suite retained its previously tracked event-retention failure
(`TestOperationalEventsRetainFilterAndStayMetadataOnly`, issue #199); this is
not a full-suite green claim. Legacy rendered credentials remain literal when
bindings are omitted; explicit bindings request Broker-owned provisioning.

Issue #196; companion Core issue #1732. Approved owner requirements, 2026-10-08.

**DAV-1:** Broker owns plaintext file bytes in RAM only. Core submits scoped refs
and secret-free templates. Broker resolves and renders internally, returning the
WebDAV directory. DAV-6 supersedes the original Core-rendered delivery contract.
`POST /v1/file-grants` additionally consumes a fresh resolve launch lease bound
to the service/workspace and, in production, the actual IPC peer. No public
WebDAV route can create, change or delete files.

**DAV-2:** A grant belongs to service/workspace/instance. Fresh creation atomically
replaces that instance's prior grant with a cryptographically random 256-bit
capability. Store only its SHA-256 digest. Grants and bytes disappear on Broker
restart; Core recreates them before fresh app launch. Stop/failure revokes the
exact grant through authenticated IPC, without revoking a successor grant.

**DAV-3:** Bind a separate read-only listener to `127.0.0.1:0`. Reject non-loopback
peers, foreign Host, browser Origin, forwarded headers, traversal and write
methods. GET, HEAD, OPTIONS and depth 0/1 PROPFIND expose only the authenticated
grant. Never log request URLs or persist contents/tokens. Responses prohibit
caching. The consuming service's subsequent handling is outside this contract.

**DAV-4:** Limit file count, individual bytes, total grant bytes, aggregate live
bytes and grant count. Bound HTTP headers, request bodies and read/write times.
Invalid replacement leaves the previous grant usable. No disk fallback.

**DAV-5:** Support `Authorization: Bearer <token>` at `/files/<relative-path>` and
capability paths `/<token>/<relative-path>` for native WebDAV clients. Grant API
returns base URL and token through IPC only. Windows may use
`\\127.0.0.1@<port>\DavWWWRoot\<token>\`; Linux DAV clients use the returned
HTTP URL or `dav://127.0.0.1:<port>/<token>/`. No drive mapping is required.
WebDAV URLs require a DAV/HTTP capable client; they are not POSIX filesystem paths.
Windows UNC consumption requires the operating system's WebClient support.

Acceptance: real loopback HTTP file consumption, grant isolation, rotation,
exact revocation, restart loss, invalid input/bounds and auth/peer/origin/Host/
traversal/write denial; authenticated API authorization and secret-free persisted
state. Source checks do not claim packaged release, deployment, application
storage behaviour or independent assurance.

Source qualification, 2026-10-08: one full Go suite run and vet passed on Windows.
A later full repeat failed two unchanged event-retention/migration cases; both
then passed three consecutive focused repetitions. New RAM and contract cases
passed separately. This records repeatability limits rather than a wholly green
latest full-suite claim.
Real loopback HTTP grant tests also passed as a Linux executable on Ubuntu.
An explicit native Windows `os.ReadFile` through the token UNC path passed with
the existing WebClient, without drive mapping or machine configuration changes.
Core's actual managed-child integration passed with a production Broker,
peer-bound Unix socket and current encrypted-vault values on Ubuntu.
