$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$staging = Join-Path $dist 'secretsbroker-win32'
$zipPath = Join-Path $dist 'secretsbroker-win32.zip'

New-Item -ItemType Directory -Force -Path $dist | Out-Null
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Force -Path $staging | Out-Null

Push-Location $root
try {
  $env:GOOS = 'windows'
  $env:GOARCH = 'amd64'
  go build -trimpath -o (Join-Path $staging 'secretsbroker.exe') ./cmd/secretsbroker
  if ($LASTEXITCODE -ne 0) {
    throw "secretsbroker build failed with exit code $LASTEXITCODE."
  }
  go build -trimpath -o (Join-Path $staging 'secretsbroker-resolve.exe') ./cmd/secretsbroker-resolve
  if ($LASTEXITCODE -ne 0) {
    throw "secretsbroker-resolve build failed with exit code $LASTEXITCODE."
  }
}
finally {
  Pop-Location
  Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
}

Copy-Item -Recurse -Force (Join-Path $root 'config') (Join-Path $staging 'config')
Copy-Item -Force (Join-Path $root 'service.json') (Join-Path $staging 'service.json')

Push-Location $root
try {
  go run ./cmd/sbom --output (Join-Path $staging 'sbom.cdx.json') --platform win32
}
finally {
  Pop-Location
}
Copy-Item -Force (Join-Path $staging 'sbom.cdx.json') (Join-Path $dist 'secretsbroker-win32.cdx.json')

if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Push-Location $root
try {
  go run ./cmd/releasearchive --source $staging --output $zipPath --format zip
}
finally {
  Pop-Location
}
Write-Host "Created $zipPath"
