param(
  [string]$OpenBaoBin = $env:OPENBAO_BIN,
  [string]$BrokerBin = ""
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OpenBaoBin) {
  $candidate = Join-Path (Split-Path $root -Parent) 'lasso-openbao\dist\openbao-win32\runtime\bao.exe'
  if (Test-Path -LiteralPath $candidate) { $OpenBaoBin = $candidate }
}
if (-not $OpenBaoBin -or -not (Test-Path -LiteralPath $OpenBaoBin)) {
  throw 'Set OPENBAO_BIN or pass -OpenBaoBin with a packaged bao executable.'
}

function Wait-Http([string]$Uri, [int]$Attempts = 80) {
  for ($i = 0; $i -lt $Attempts; $i++) {
    try { return Invoke-RestMethod -Uri $Uri -TimeoutSec 2 }
    catch { Start-Sleep -Milliseconds 250 }
  }
  throw "Timed out waiting for $Uri"
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('broker-openbao-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$baoPort = if ($env:OPENBAO_E2E_PORT) { [int]$env:OPENBAO_E2E_PORT } else { 18200 }
$brokerPort = if ($env:BROKER_E2E_PORT) { [int]$env:BROKER_E2E_PORT } else { 17892 }
$baoUrl = "http://127.0.0.1:$baoPort"
$brokerUrl = "http://127.0.0.1:$brokerPort"
$storePath = Join-Path $temp 'store.json'
$auditPath = Join-Path $temp 'audit.jsonl'
$sourcesPath = Join-Path $temp 'sources.json'
$brokerBinary = if ($BrokerBin) { $BrokerBin } else { Join-Path $temp 'secretsbroker.exe' }
$bao = $null
$broker = $null

Push-Location $root
try {
  if (-not $BrokerBin) {
    go build -o $brokerBinary ./cmd/secretsbroker
    if ($LASTEXITCODE -ne 0) { throw 'Broker build failed.' }
  }

  $bao = Start-Process -FilePath $OpenBaoBin `
    -ArgumentList 'server', '-dev', '-dev-root-token-id=openbao-root', "-dev-listen-address=127.0.0.1:$baoPort" `
    -PassThru -RedirectStandardOutput (Join-Path $temp 'openbao.out') -RedirectStandardError (Join-Path $temp 'openbao.err')
  Wait-Http "$baoUrl/v1/sys/health" | Out-Null
  $vaultHeaders = @{ 'X-Vault-Token' = 'openbao-root' }
  try {
    Invoke-RestMethod -Method Post -Uri "$baoUrl/v1/sys/mounts/secret" -Headers $vaultHeaders -ContentType 'application/json' -Body '{"type":"kv","options":{"version":"2"}}' | Out-Null
  } catch {
    if (-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -notin @(400, 409)) { throw }
  }
  Invoke-RestMethod -Method Post -Uri "$baoUrl/v1/secret/data/services/api/API_TOKEN" -Headers $vaultHeaders -ContentType 'application/json' -Body '{"data":{"value":"openbao-e2e-value"}}' | Out-Null

  @{
    sources = @(
      @{
        sourceId = 'openbao-e2e'
        kind = 'openbao'
        enabled = $true
        address = $baoUrl
        token = 'openbao-root'
        refs = @{
          'services/api/API_TOKEN' = @{ path = 'secret/data/services/api/API_TOKEN'; field = 'value' }
        }
      }
    )
  } | ConvertTo-Json -Depth 8 | ForEach-Object { [System.IO.File]::WriteAllText($sourcesPath, $_, [System.Text.UTF8Encoding]::new($false)) }

  $broker = Start-Process -FilePath $brokerBinary `
    -ArgumentList 'serve', '--listen', "127.0.0.1:$brokerPort", '--state', 'ready', '--master-key', 'e2e-master-key', '--api-token', 'broker-token', '--store', $storePath, '--audit', $auditPath, '--wrapper', (Join-Path $temp 'wrapper.json'), '--sources', $sourcesPath, '--mode', 'development' `
    -PassThru -RedirectStandardOutput (Join-Path $temp 'broker.out') -RedirectStandardError (Join-Path $temp 'broker.err')
  Start-Sleep -Seconds 1
  if ($broker.HasExited) {
    Get-Content (Join-Path $temp 'broker.err') -ErrorAction SilentlyContinue | Select-Object -Last 30
    throw "Broker exited before listening (code $($broker.ExitCode))."
  }
  try { Wait-Http "$brokerUrl/health" | Out-Null } catch { Get-Content (Join-Path $temp 'broker.out') -ErrorAction SilentlyContinue | Select-Object -Last 30; Get-Content (Join-Path $temp 'broker.err') -ErrorAction SilentlyContinue | Select-Object -Last 30; throw }
  $apiHeaders = @{ Authorization = 'Bearer broker-token' }

  $read = Invoke-RestMethod -Method Get -Uri "$brokerUrl/v1/kv/data/services/api/API_TOKEN" -Headers $apiHeaders
  if ($read.data.data.value -ne 'openbao-e2e-value') {
    throw "Broker read did not return the OpenBao value: $($read | ConvertTo-Json -Compress)"
  }

  Invoke-RestMethod -Method Post -Uri "$brokerUrl/v1/kv/data/services/api/NEW_TOKEN" -Headers $apiHeaders -ContentType 'application/json' -Body '{"data":{"value":"openbao-written"}}' | Out-Null
  $direct = Invoke-RestMethod -Method Get -Uri "$baoUrl/v1/secret/data/services/api/NEW_TOKEN" -Headers $vaultHeaders
  if ($direct.data.data.value -ne 'openbao-written') {
    throw 'Broker KV write did not reach the real OpenBao server.'
  }
  if ((Test-Path -LiteralPath $storePath) -and (Select-String -Path $storePath -Pattern 'NEW_TOKEN' -Quiet)) {
    throw 'Broker KV write also appeared in the local store.'
  }

  Write-Host 'OpenBao-first broker e2e passed: read=openbao-e2e-value write=openbao-written'
} finally {
  if ($broker) { Stop-Process -Id $broker.Id -Force -ErrorAction SilentlyContinue }
  if ($bao) { Stop-Process -Id $bao.Id -Force -ErrorAction SilentlyContinue }
  Pop-Location
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}






