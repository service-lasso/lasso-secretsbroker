param(
  [string]$DeniedUser = $env:SECRETSBROKER_CROSS_USER_DENIED_USER,
  [string]$DeniedPasswordEnvVar = 'SECRETSBROKER_CROSS_USER_PASSWORD',
  [string]$OutputDir = (Join-Path (Split-Path -Parent $PSScriptRoot) '.work-agent\logs\windows-named-pipe-cross-user'),
  [int]$ConnectTimeoutMs = 2000
)

$ErrorActionPreference = 'Stop'

$isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
if (-not $isWindowsHost) {
  throw 'Windows named-pipe cross-user verification must run on Windows.'
}

$root = Split-Path -Parent $PSScriptRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $OutputDir $timestamp
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

function Write-SafeJson {
  param(
    [string]$Path,
    [hashtable]$Value
  )
  $Value | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $Path
}

function Invoke-NamedPipeHttp {
  param(
    [string]$PipePath,
    [string]$RequestPath,
    [int]$TimeoutMs
  )

  $pipeName = $PipePath -replace '^\\\\\.\\pipe\\', ''
  $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
  try {
    $client.Connect($TimeoutMs)
    $client.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Byte
    $writer = [System.IO.StreamWriter]::new($client, [System.Text.Encoding]::ASCII, 1024, $true)
    $writer.NewLine = "`r`n"
    $writer.Write("GET $RequestPath HTTP/1.1`r`nHost: secretsbroker.local`r`nConnection: close`r`n`r`n")
    $writer.Flush()
    $reader = [System.IO.StreamReader]::new($client, [System.Text.Encoding]::ASCII)
    return $reader.ReadToEnd()
  }
  finally {
    $client.Dispose()
  }
}

$passwordValue = if ($DeniedPasswordEnvVar) { [Environment]::GetEnvironmentVariable($DeniedPasswordEnvVar) } else { $null }
if ([string]::IsNullOrWhiteSpace($DeniedUser) -or [string]::IsNullOrEmpty($passwordValue)) {
  Write-SafeJson -Path (Join-Path $runDir 'blocked.json') -Value @{
    status = 'blocked'
    reason = 'missing_cross_user_credentials'
    deniedUserProvided = -not [string]::IsNullOrWhiteSpace($DeniedUser)
    passwordEnvVar = $DeniedPasswordEnvVar
    nextAction = 'Set SECRETSBROKER_CROSS_USER_DENIED_USER and the password environment variable named by -DeniedPasswordEnvVar, then rerun on an integration Windows host.'
  }
  throw 'Missing alternate Windows user credentials for cross-user named-pipe denial verification.'
}

$securePassword = ConvertTo-SecureString $passwordValue -AsPlainText -Force
$credential = [pscredential]::new($DeniedUser, $securePassword)
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentSID = $current.User.Value
$pipePath = "\\.\pipe\service-lasso-secretsbroker-cross-user-$([Guid]::NewGuid().ToString('N'))"
$tmp = Join-Path $root '.tmp\cross-user-named-pipe'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$exe = Join-Path $tmp 'secretsbroker.exe'

Push-Location $root
try {
  go build -o $exe ./cmd/secretsbroker

  $stdout = Join-Path $runDir 'broker.out.log'
  $stderr = Join-Path $runDir 'broker.err.log'
  $proc = Start-Process -FilePath $exe -ArgumentList @(
    'serve',
    '--mode', 'production',
    '--transport', 'windows-named-pipe',
    '--named-pipe', $pipePath,
    '--named-pipe-allow-admin=false',
    '--named-pipe-allow-local-system=false'
  ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

  try {
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
      try {
        $response = Invoke-NamedPipeHttp -PipePath $pipePath -RequestPath '/health' -TimeoutMs $ConnectTimeoutMs
        if ($response -match 'HTTP/1\.1 200') {
          $ready = $true
          break
        }
      }
      catch {
        Start-Sleep -Milliseconds 250
      }
    }
    if (-not $ready) {
      throw 'Broker named-pipe health endpoint did not become reachable for the broker user.'
    }

    $childScript = Join-Path $runDir 'denied-client.ps1'
    $childOut = Join-Path $runDir 'denied-client.out.json'
    $childErr = Join-Path $runDir 'denied-client.err.log'
    @"
`$ErrorActionPreference = 'Stop'
`$pipePath = '$pipePath'
`$pipeName = `$pipePath -replace '^\\\\\.\\pipe\\', ''
try {
  `$client = [System.IO.Pipes.NamedPipeClientStream]::new('.', `$pipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
  `$client.Connect($ConnectTimeoutMs)
  `$client.Dispose()
  @{ status = 'failed'; reason = 'denied_user_connected'; pipe = `$pipePath } | ConvertTo-Json -Depth 4
  exit 10
}
catch [System.UnauthorizedAccessException] {
  @{ status = 'passed'; reason = 'connect_unauthorized'; pipe = `$pipePath } | ConvertTo-Json -Depth 4
  exit 0
}
catch {
  `$message = `$_.Exception.Message
  if (`$message -match 'Access is denied|Unauthorized') {
    @{ status = 'passed'; reason = 'connect_access_denied'; pipe = `$pipePath } | ConvertTo-Json -Depth 4
    exit 0
  }
  @{ status = 'blocked'; reason = 'unexpected_connect_error'; error = `$message; pipe = `$pipePath } | ConvertTo-Json -Depth 4
  exit 20
}
"@ | Set-Content -Encoding utf8 $childScript

    $child = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
      '-NoLogo',
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $childScript
    ) -Credential $credential -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $childOut -RedirectStandardError $childErr

    $childResult = if (Test-Path $childOut) { Get-Content $childOut -Raw | ConvertFrom-Json } else { $null }
    if ($child.ExitCode -ne 0 -or $null -eq $childResult -or $childResult.status -ne 'passed') {
      Write-SafeJson -Path (Join-Path $runDir 'summary.json') -Value @{
        status = 'failed'
        brokerUser = $current.Name
        brokerUserSID = $currentSID
        deniedUser = $DeniedUser
        childExitCode = $child.ExitCode
        childResult = $childResult
        pipe = $pipePath
      }
      throw "Denied user process did not produce the expected access-denied result; child exit code $($child.ExitCode)."
    }

    Write-SafeJson -Path (Join-Path $runDir 'summary.json') -Value @{
      status = 'passed'
      brokerUser = $current.Name
      brokerUserSID = $currentSID
      deniedUser = $DeniedUser
      deniedResult = $childResult
      pipe = $pipePath
      proof = 'Alternate Windows principal could not connect to a strict broker-owned named pipe.'
    }
    Write-Host "Windows named-pipe cross-user denial verification passed. Evidence: $runDir"
  }
  finally {
    if ($proc -and -not $proc.HasExited) {
      Stop-Process -Id $proc.Id -Force
      $proc.WaitForExit()
    }
  }
}
finally {
  Pop-Location
}
