$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
  foreach ($path in @('service.json', 'verify\service-harness.json', 'cmd\secretsbroker\main.go', 'go.mod')) {
    if (-not (Test-Path (Join-Path $root $path))) {
      throw "Missing required file: $path"
    }
  }

  $service = Get-Content (Join-Path $root 'service.json') -Raw | ConvertFrom-Json
  if ($service.id -ne '@secretsbroker') {
    throw 'service.json id mismatch'
  }

  $contract = Get-Content (Join-Path $root 'verify\service-harness.json') -Raw | ConvertFrom-Json
  if ($contract.serviceId -ne '@secretsbroker') {
    throw 'service-harness.json serviceId mismatch'
  }

  go test ./...

  $tmp = Join-Path $root '.tmp\test'
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  $exe = Join-Path $tmp 'secretsbroker.exe'
  go build -o $exe ./cmd/secretsbroker

  $status = & $exe status | ConvertFrom-Json
  if ($status.serviceId -ne '@secretsbroker') {
    throw 'status serviceId mismatch'
  }
  if ($status.state -ne 'setup_needed') {
    throw 'default status state mismatch'
  }

  $port = 17891
  $proc = Start-Process -FilePath $exe -ArgumentList @('serve', '--listen', "127.0.0.1:$port") -PassThru -WindowStyle Hidden
  try {
    $ok = $false
    for ($i = 0; $i -lt 20; $i++) {
      try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health" -TimeoutSec 1
        if ($health.ok -and $health.serviceId -eq '@secretsbroker') { $ok = $true; break }
      } catch {
        Start-Sleep -Milliseconds 250
      }
    }
    if (-not $ok) { throw 'health endpoint did not become ready' }
  }
  finally {
    if (-not $proc.HasExited) {
      Stop-Process -Id $proc.Id -Force
      $proc.WaitForExit()
    }
  }

  Write-Host 'Secrets Broker tests passed (Windows)'
}
finally {
  Pop-Location
}
