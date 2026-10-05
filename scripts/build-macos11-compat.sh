#!/usr/bin/env bash
# Separate custom profile; package.sh continues to use the official toolchain.
set -euo pipefail
# Ignore ambient Go configuration, overlays, tool wrappers and cross-build flags.
unset GOOS GOARCH GOAMD64 GOARM64 GOFLAGS GOEXPERIMENT GOCOMPILEDEBUG GOTOOLDIR CC CXX FC AR LD CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS
export GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
export GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org GOPRIVATE= GONOPROXY= GONOSUMDB=
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
test -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" || { echo 'Build requires a clean immutable checkout' >&2; exit 2; }
CANDIDATE_SHA="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
export CANDIDATE_SHA SOURCE_TREE
OWNED="${1:?supply a new owned absolute build directory}"
case "$OWNED" in /*) ;; *) echo 'Owned directory must be absolute' >&2; exit 2;; esac
test ! -e "$OWNED"
mkdir -p "$OWNED"
curl -fL https://go.dev/dl/go1.26.8.linux-amd64.tar.gz -o "$OWNED/go.tar.gz"
echo "d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b  $OWNED/go.tar.gz" | sha256sum -c -
tar -xzf "$OWNED/go.tar.gz" -C "$OWNED"
curl -fL https://go.dev/dl/go1.26.8.src.tar.gz -o "$OWNED/go.src.tar.gz"
echo "4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e  $OWNED/go.src.tar.gz" | sha256sum -c -
echo "170a7b026b48999929a02c4a724a878f7837ee6fe62d829cfe0a276312a5e9f3  $ROOT/toolchains/macos11/go1.26.8.patch" | sha256sum -c -
python3 - "$OWNED/go" "$OWNED/go.src.tar.gz" "$ROOT/toolchains/macos11/source-hashes.json" <<'PY'
import pathlib,sys,tarfile,json
root=pathlib.Path(sys.argv[1])
with tarfile.open(sys.argv[2]) as archive:
    for name in json.load(open(sys.argv[3])):
        if (root/name).read_bytes()!=archive.extractfile('go/'+name).read():
            raise SystemExit('Distribution/source disagreement: '+name)
PY
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
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -x -work -trimpath -o "$GOROOT/pkg/tool/linux_amd64/link.owned" cmd/link 2> "$OWNED/linker-build.log"
mv "$GOROOT/pkg/tool/linux_amd64/link.owned" "$GOROOT/pkg/tool/linux_amd64/link"
mkdir -p "$OWNED/artifacts"
cd "$ROOT"
for entry in secretsbroker secretsbroker-resolve; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -x -work -trimpath -ldflags=-linkmode=internal -o "$OWNED/artifacts/$entry" "./cmd/$entry" 2> "$OWNED/$entry-build.log"
done
test "$(git -C "$ROOT" rev-parse HEAD)" = "$CANDIDATE_SHA"
test -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" || { echo 'Checkout changed during build' >&2; exit 2; }
python3 - "$ROOT" "$OWNED" <<'PY'
import hashlib,json,pathlib,subprocess,sys,os
root,owned=map(pathlib.Path,sys.argv[1:])
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
files=[root/'toolchains/macos11/go1.26.8.patch',root/'go.mod',root/'go.sum',owned/'go.tar.gz',owned/'go.src.tar.gz',owned/'go/pkg/tool/linux_amd64/link',owned/'linker-build.log',owned/'secretsbroker-build.log',owned/'secretsbroker-resolve-build.log']+list((owned/'artifacts').iterdir())
allowed=('GOTOOLCHAIN','GOROOT','GOCACHE','GOMODCACHE','GOENV','GOFLAGS','GOWORK','GOOS','GOARCH','GOAMD64','CGO_ENABLED','GOPROXY','GOSUMDB','GOPRIVATE','GONOPROXY','GONOSUMDB')
builds=[{'command':'go build -x -work -trimpath -o GOROOT/pkg/tool/linux_amd64/link.owned cmd/link','environment':{'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0'}}]+[{'command':f'go build -x -work -trimpath -ldflags=-linkmode=internal -o artifacts/{entry} ./cmd/{entry}','environment':{'GOOS':'darwin','GOARCH':'amd64','CGO_ENABLED':'0'}} for entry in ('secretsbroker','secretsbroker-resolve')]
doc={'profile':'custom-maintained-go1.26.8-darwin-amd64-macos11','sourceSHA256':'4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e','candidateSHA':os.environ['CANDIDATE_SHA'],'sourceTree':os.environ['SOURCE_TREE'],'builds':builds,'environment':{k:os.environ[k] for k in allowed},'linkFlags':'-linkmode=internal','CGO_ENABLED':'0','hashes':{str(p.relative_to(root)) if p.is_relative_to(root) else str(p):sha(p) for p in files},'sourceFiles':json.load(open(root/'toolchains/macos11/source-hashes.json')),'goEnvironment':json.loads(subprocess.check_output(['go','env','-json',*allowed],text=True))}
(owned/'artifacts/provenance.json').write_text(json.dumps(doc,indent=2)+'\n')
PY
echo "Candidate binaries and provenance: $OWNED/artifacts"
