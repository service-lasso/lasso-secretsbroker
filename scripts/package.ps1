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
  go build -o (Join-Path $staging 'secretsbroker.exe') ./cmd/secretsbroker
}
finally {
  Pop-Location
  Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
}

Copy-Item -Recurse -Force (Join-Path $root 'config') (Join-Path $staging 'config')
Copy-Item -Force (Join-Path $root 'service.json') (Join-Path $staging 'service.json')

if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zipPath
Write-Host "Created $zipPath"
