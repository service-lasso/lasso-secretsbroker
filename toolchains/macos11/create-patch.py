#!/usr/bin/env python3
"""Produce the reviewed four-file patch from exact verified official archives."""
import hashlib, json, pathlib, sys, tarfile, difflib

root, source_archive, destination = map(pathlib.Path, sys.argv[1:])
if hashlib.sha256(source_archive.read_bytes()).hexdigest() != "4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e":
    raise SystemExit("Official source archive mismatch")
changes = {}
paths = ["src/crypto/x509/internal/macos/security.go", "src/crypto/x509/internal/macos/security.s", "src/crypto/x509/root_darwin.go", "src/cmd/link/internal/ld/macho.go"]
with tarfile.open(source_archive) as archive:
    for path in paths:
        pristine = archive.extractfile("go/" + path).read()
        if (root / path).read_bytes() != pristine:
            raise SystemExit("Official distribution/source mismatch: " + path)
        changes[path] = pristine.decode()
p = paths[0]
start = changes[p].index("//go:cgo_import_dynamic x509_SecTrustCopyCertificateChain")
changes[p] = changes[p][:start] + '''//go:cgo_import_dynamic x509_SecTrustGetCertificateCount SecTrustGetCertificateCount "/System/Library/Frameworks/Security.framework/Versions/A/Security"

func SecTrustGetCertificateCount(trustObj CFRef) int {
	return int(syscall(abi.FuncPCABI0(x509_SecTrustGetCertificateCount_trampoline), uintptr(trustObj), 0, 0, 0, 0, 0))
}
func x509_SecTrustGetCertificateCount_trampoline()

//go:cgo_import_dynamic x509_SecTrustGetCertificateAtIndex SecTrustGetCertificateAtIndex "/System/Library/Frameworks/Security.framework/Versions/A/Security"

// SecTrustGetCertificateAtIndex returns a borrowed reference. The caller must
// evaluate its private trust object first and copy DER before releasing it.
func SecTrustGetCertificateAtIndex(trustObj CFRef, i int) (CFRef, error) {
	ret := syscall(abi.FuncPCABI0(x509_SecTrustGetCertificateAtIndex_trampoline), uintptr(trustObj), uintptr(i), 0, 0, 0, 0)
	if ret == 0 {
		return 0, errors.New("x509: invalid borrowed certificate object")
	}
	return CFRef(ret), nil
}
func x509_SecTrustGetCertificateAtIndex_trampoline()
'''
p = paths[1]
changes[p] = changes[p].replace('TEXT ·x509_SecTrustCopyCertificateChain_trampoline(SB),NOSPLIT,$0-0\n\tJMP x509_SecTrustCopyCertificateChain(SB)', 'TEXT ·x509_SecTrustGetCertificateCount_trampoline(SB),NOSPLIT,$0-0\n\tJMP x509_SecTrustGetCertificateCount(SB)\nTEXT ·x509_SecTrustGetCertificateAtIndex_trampoline(SB),NOSPLIT,$0-0\n\tJMP x509_SecTrustGetCertificateAtIndex(SB)')
p = paths[2]
old = '''	chainRef, err := macos.SecTrustCopyCertificateChain(trustObj)
	if err != nil {
		return nil, err
	}
	defer macos.CFRelease(chainRef)
	for i := 0; i < macos.CFArrayGetCount(chainRef); i++ {
		certRef := macos.CFArrayGetValueAtIndex(chainRef, i)
'''
new = '''	// This trust object is private to this invocation and has been evaluated.
	// Chain entries are borrowed; exportCertificate copies DER while trustObj
	// remains alive. Never release borrowed certificate references separately.
	count := macos.SecTrustGetCertificateCount(trustObj)
	for i := 0; i < count; i++ {
		certRef, err := macos.SecTrustGetCertificateAtIndex(trustObj, i)
		if err != nil {
			return nil, err
		}
'''
if changes[p].count(old) != 1:
    raise SystemExit("Chain retrieval source context drift")
changes[p] = changes[p].replace(old, new)
p = paths[3]
old = '\t\t\t\tversion = 12<<16 | 0<<8 | 0<<0 // 12.0.0\n'
if changes[p].count(old) != 1:
    raise SystemExit("Linker source context drift")
changes[p] = changes[p].replace(old, old + '\t\t\t\t// Custom maintained-Go macOS 11 Intel profile: synthesized metadata\n\t\t\t\t// for internal linking only; no external SDK version is asserted.\n\t\t\t\tif ctxt.Arch.Family == sys.AMD64 {\n\t\t\t\t\tversion = 11 << 16 // minOS and synthetic SDK 11.0.0\n\t\t\t\t}\n')
manifest, patch = {}, []
for path, updated in changes.items():
    original = (root / path).read_bytes()
    manifest[path] = {"before": hashlib.sha256(original).hexdigest(), "after": hashlib.sha256(updated.encode()).hexdigest()}
    patch.extend(difflib.unified_diff(original.decode().splitlines(True), updated.splitlines(True), "a/" + path, "b/" + path))
destination.mkdir(parents=True, exist_ok=True)
(destination / "go1.26.8.patch").write_text("".join(patch))
(destination / "source-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n")
