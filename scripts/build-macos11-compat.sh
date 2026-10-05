#!/usr/bin/env bash
# Separate custom profile; package.sh continues to use the official toolchain.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OWNED="${1:?supply a new owned absolute build directory}"
case "$OWNED" in /*) ;; *) echo 'Owned directory must be absolute' >&2; exit 2;; esac
test ! -e "$OWNED"
mkdir -p "$OWNED"
curl -fL https://go.dev/dl/go1.26.8.linux-amd64.tar.gz -o "$OWNED/go.tar.gz"
echo "d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b  $OWNED/go.tar.gz" | sha256sum -c -
tar -xzf "$OWNED/go.tar.gz" -C "$OWNED"
python3 - "$OWNED/go" "$ROOT/toolchains/macos11/source-hashes.json" before <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
for name,hashes in json.load(open(sys.argv[2])).items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=hashes[sys.argv[3]]:
        raise SystemExit('Upstream source drift: '+name)
PY
patch --batch --fuzz=0 -p1 -d "$OWNED/go" < "$ROOT/toolchains/macos11/go1.26.8.patch"
python3 - "$OWNED/go" "$ROOT/toolchains/macos11/source-hashes.json" after <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
for name,hashes in json.load(open(sys.argv[2])).items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=hashes[sys.argv[3]]:
        raise SystemExit('Patched source mismatch: '+name)
PY
export GOTOOLCHAIN=local GOROOT="$OWNED/go" GOCACHE="$OWNED/cache" GOMODCACHE="$OWNED/modcache"
export PATH="$GOROOT/bin:$PATH"
test "$(go version)" = 'go version go1.26.8 linux/amd64'
go build -trimpath -o "$GOROOT/pkg/tool/linux_amd64/link.owned" cmd/link
mv "$GOROOT/pkg/tool/linux_amd64/link.owned" "$GOROOT/pkg/tool/linux_amd64/link"
mkdir -p "$OWNED/artifacts"
cd "$ROOT"
for entry in secretsbroker secretsbroker-resolve; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags=-linkmode=internal -o "$OWNED/artifacts/$entry" "./cmd/$entry"
done
python3 - "$ROOT" "$OWNED" <<'PY'
import hashlib,json,pathlib,subprocess,sys,os
root,owned=map(pathlib.Path,sys.argv[1:])
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
files=[root/'toolchains/macos11/go1.26.8.patch',root/'go.mod',root/'go.sum',owned/'go.tar.gz',owned/'go/pkg/tool/linux_amd64/link']+list((owned/'artifacts').iterdir())
doc={'profile':'custom-maintained-go1.26.8-darwin-amd64-macos11','sourceSHA256':'4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e','candidateSHA':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'environment':{k:os.environ[k] for k in ('GOTOOLCHAIN','GOROOT','GOCACHE','GOMODCACHE')},'linkFlags':'-linkmode=internal','CGO_ENABLED':'0','hashes':{str(p.relative_to(root)) if p.is_relative_to(root) else str(p):sha(p) for p in files},'sourceFiles':json.load(open(root/'toolchains/macos11/source-hashes.json')),'goEnvironment':json.loads(subprocess.check_output(['go','env','-json'],text=True))}
(owned/'artifacts/provenance.json').write_text(json.dumps(doc,indent=2)+'\n')
PY
echo "Candidate binaries and provenance: $OWNED/artifacts"
