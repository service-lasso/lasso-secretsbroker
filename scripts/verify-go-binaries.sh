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
cleanup() { rm -f "$tmp_json"; }
trap cleanup EXIT

printf '{\n  "schema": "secretsbroker.go-vulnerability-binary-verification.v1",\n  "status": "verified",\n  "scanner": "%s",\n  "goVersion": "%s",\n  "binaries": [\n' "$SCANNER" "$(go version)" > "$tmp_json"
separator=""
for binary in "$@"; do
  if [[ ! -f "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
  fi
  go run "$SCANNER" -mode=binary "$binary"
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
