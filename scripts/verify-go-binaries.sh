#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: verify-go-binaries.sh <output-path> <binary> <binary> [...]" >&2
  exit 2
fi

OUTPUT_PATH="$1"
shift
SCANNER="golang.org/x/vuln/cmd/govulncheck@v1.6.0"
mkdir -p "$(dirname "$OUTPUT_PATH")"

tmp_json="${OUTPUT_PATH}.tmp"
tmp_dir="$(mktemp -d)"
cleanup() { rm -f "$tmp_json"; rm -rf "$tmp_dir"; }
trap cleanup EXIT

scan_binary() {
  local binary="$1"
  go run "$SCANNER" -mode=binary "$binary"
}

printf '{\n  "schema": "secretsbroker.go-vulnerability-binary-verification.v1",\n  "status": "verified",\n  "scanner": "%s",\n  "goVersion": "%s",\n  "binaries": [\n' "$SCANNER" "$(go version)" > "$tmp_json"
separator=""
for binary in "$@"; do
  if [[ ! -f "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v lipo >/dev/null 2>&1; then
    architectures="$(lipo -archs "$binary" 2>/dev/null || true)"
    if [[ "$(wc -w <<<"$architectures" | tr -d ' ')" -gt 1 ]]; then
      for architecture in $architectures; do
        thin_binary="$tmp_dir/$(basename "$binary").$architecture"
        lipo "$binary" -thin "$architecture" -output "$thin_binary"
        scan_binary "$thin_binary"
      done
    else
      scan_binary "$binary"
    fi
  else
    scan_binary "$binary"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$binary" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$binary" | awk '{print $1}')"
  fi
  printf '%s    {"name":"%s","sha256":"%s","status":"verified_no_reachable_vulnerabilities"}' "$separator" "$(basename "$binary")" "$digest" >> "$tmp_json"
  separator=$',\n'
done
printf '\n  ]\n}\n' >> "$tmp_json"
mv "$tmp_json" "$OUTPUT_PATH"
trap - EXIT

echo "Go binary vulnerability verification passed"
