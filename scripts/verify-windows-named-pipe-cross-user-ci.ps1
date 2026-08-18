param(
  [string]$OutputDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output\verify\windows-named-pipe-cross-user')
)

$ErrorActionPreference = 'Stop'

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
  throw 'The hosted cross-user named-pipe verifier must run on Windows.'
}

$suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$userName = "slbci-$suffix"
$qualifiedUser = "$env:COMPUTERNAME\$userName"
$password = $null

try {
  $randomBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(24)
  $password = [Convert]::ToBase64String($randomBytes) + 'aA1!'
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
  New-LocalUser `
    -Name $userName `
    -Password $securePassword `
    -AccountNeverExpires `
    -PasswordNeverExpires `
    -UserMayNotChangePassword | Out-Null

  $env:SECRETSBROKER_CROSS_USER_DENIED_USER = $qualifiedUser
  $env:SECRETSBROKER_CROSS_USER_PASSWORD = $password

  & (Join-Path $PSScriptRoot 'verify-windows-named-pipe-cross-user.ps1') -OutputDir $OutputDir
  if ($LASTEXITCODE -ne 0) {
    throw "Cross-user named-pipe verifier exited with code $LASTEXITCODE."
  }

  $summary = Get-ChildItem -LiteralPath $OutputDir -Filter summary.json -Recurse |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
  if (-not $summary) {
    throw 'Cross-user named-pipe verifier did not emit summary.json.'
  }
  $result = Get-Content -LiteralPath $summary.FullName -Raw | ConvertFrom-Json
  if ($result.status -ne 'passed' -or $result.deniedUser -ne $qualifiedUser) {
    throw 'Cross-user named-pipe verifier did not produce the expected denial evidence.'
  }

  Write-Host "Hosted Windows cross-user denial proof passed for ephemeral principal $qualifiedUser."
}
finally {
  Remove-Item Env:SECRETSBROKER_CROSS_USER_DENIED_USER -ErrorAction SilentlyContinue
  Remove-Item Env:SECRETSBROKER_CROSS_USER_PASSWORD -ErrorAction SilentlyContinue
  $password = $null
  if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $userName
  }
}
