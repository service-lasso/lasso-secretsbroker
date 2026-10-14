$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$version = '2.7.1'
$cache = Join-Path $root '.tmp\openbao-e2e'
$asset = "openbao_${version}_windows_amd64.zip"
$sha256 = 'e3b3335918a78cc730bb07014c4191c80fe5eb376f3f1a708185acf8bc0109ac'

New-Item -ItemType Directory -Force -Path $cache | Out-Null
$archive = Join-Path $cache $asset
if (-not (Test-Path $archive)) {
  Invoke-WebRequest -Uri "https://github.com/openbao/openbao/releases/download/v$version/$asset" -OutFile $archive
}

$actual = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLower()
if ($actual -ne $sha256) {
  throw "OpenBao archive digest mismatch: expected $sha256, got $actual"
}

$extract = Join-Path $cache 'bin'
if (-not (Test-Path $extract)) {
  Expand-Archive -Path $archive -DestinationPath $extract -Force
}
$bin = Get-ChildItem $extract -Recurse -Filter 'bao.exe' | Select-Object -First 1
if (-not $bin) {
  throw 'bao.exe not found in the OpenBao archive'
}

$env:OPENBAO_E2E_BIN = $bin.FullName
Push-Location $root
try {
  go test ./cmd/secretsbroker -run '^TestOpenBaoProxyE2E$' -count=1 -v
}
finally {
  Pop-Location
}
