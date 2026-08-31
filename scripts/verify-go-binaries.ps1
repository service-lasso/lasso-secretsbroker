param(
  [Parameter(Mandatory = $true)]
  [string]$BrokerPath,
  [Parameter(Mandatory = $true)]
  [string]$ResolverPath,
  [string]$OutputPath = '.\output\verify\go-vulnerability-binaries.json'
)

$ErrorActionPreference = 'Stop'
$scanner = 'golang.org/x/vuln/cmd/govulncheck@v1.7.0'
$results = @()
foreach ($path in @($BrokerPath, $ResolverPath)) {
  $resolved = [IO.Path]::GetFullPath($path)
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "binary not found: $resolved"
  }
  & go run $scanner -mode=binary $resolved
  if ($LASTEXITCODE -ne 0) {
    throw "govulncheck rejected $([IO.Path]::GetFileName($resolved))"
  }
  $results += [ordered]@{
    name = [IO.Path]::GetFileName($resolved)
    sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    status = 'verified_no_reachable_vulnerabilities'
  }
}

$output = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($output)) | Out-Null
[ordered]@{
  schema = 'secretsbroker.go-vulnerability-binary-verification.v1'
  status = 'verified'
  scanner = $scanner
  goVersion = (& go version)
  verifiedAt = [DateTime]::UtcNow.ToString('o')
  binaries = $results
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $output -Encoding utf8

Write-Host 'Go binary vulnerability verification passed'
