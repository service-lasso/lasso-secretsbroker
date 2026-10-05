# Issue 188 work ledger
- [x] Isolated current develop checkout and typed branch, primary preserved.
- [x] Review-approved architecture promoted into active SPEC-188.
- [x] Guarded owned four-file maintained-Go patch and linker rebuild.
- [ ] Exact binary provenance and native TLS qualification.
- [ ] Actual Big Sur signed IPC/bootstrap/resolver/lifecycle proof.
- [ ] Fresh review, protected develop publication, published consumer acceptance.

Source implementation and fail-closed identity tests are present in draft PR #189.
Initial actual Big Sur TLS/lifecycle diagnostics passed; they do not qualify a later
candidate SHA. Final source review, exact-head native qualification and publication
remain open. All source commits are immediately pushed; owned outputs are ignored.

# Issue 191 work ledger
- [x] CHECKSUM-1/2: exact inventory implementation and negative tests.
- [x] CHECKSUM-3: public downloaded inventory readback.
- [ ] CHECKSUM-4: fresh review and replacement candidate qualification (parent release lane).

Issue #191 source evidence: Windows `go test ./cmd/releasechecksums` and `go vet ./cmd/releasechecksums` passed, including symlink cases without skips. CHECKSUM-3 is implemented but its public execution and CHECKSUM-4 remain pending replacement publication. Fresh review is the next parent-owned gate. This isolated issue branch remains retained for its open PR; no merge/publication or acceptance claim is made.
