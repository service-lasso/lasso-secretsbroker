# Exercise actual native nonzero exits, including helpers that leave output.
$ErrorActionPreference = 'Stop'
$source = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('broker-203-exit-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$oldPath = $env:PATH
$oldHarness = $env:SERVICE_LASSO_HARNESS_BIN
try {
  $bin = New-Item -ItemType Directory -Path (Join-Path $fixture 'bin')
  @'
@echo off
echo helper fail=%BROKER_TEST_FAIL% args=[%~1][%~2][%~3][%~4][%~5][%~6]>> "%BROKER_TEST_CALLS%"
if "%~1"=="build" goto build
if "%~2"=="./cmd/sbom" goto sbom
if "%~2"=="./cmd/releasearchive" goto archive
exit /b 99
:build
echo synthetic binary> "%~4"
exit /b 0
:sbom
echo selected=sbom>> "%BROKER_TEST_CALLS%"
echo synthetic sbom> "%~4"
if "%BROKER_TEST_FAIL%"=="sbom" goto fail_sbom
exit /b 0
:fail_sbom
echo exiting=23>> "%BROKER_TEST_CALLS%"
exit /b 23
:archive
echo selected=archive>> "%BROKER_TEST_CALLS%"
echo partial archive> "%~6"
if "%BROKER_TEST_FAIL%"=="archive" goto fail_archive
exit /b 0
:fail_archive
echo exiting=29>> "%BROKER_TEST_CALLS%"
exit /b 29
'@ | Set-Content -LiteralPath (Join-Path $bin.FullName 'go.cmd')
  @'
@echo off
echo %1>> "%BROKER_TEST_CALLS%"
if "%1"=="validate-contract" if "%BROKER_TEST_FAIL%"=="validate" exit /b 31
if "%1"=="run" if "%BROKER_TEST_FAIL%"=="run" exit /b 37
exit /b 0
'@ | Set-Content -LiteralPath (Join-Path $bin.FullName 'harness.cmd')
  $env:PATH = $bin.FullName + [IO.Path]::PathSeparator + $oldPath
  $env:SERVICE_LASSO_HARNESS_BIN = Join-Path $bin.FullName 'harness.cmd'
  foreach ($case in @('sbom', 'archive', 'validate', 'run', 'success')) {
    $root = Join-Path $fixture $case
    New-Item -ItemType Directory -Path $root, (Join-Path $root 'scripts'), (Join-Path $root 'config'), (Join-Path $root 'verify') | Out-Null
    Copy-Item -LiteralPath (Join-Path $source 'scripts/package.ps1'), (Join-Path $source 'scripts/verify.ps1') -Destination (Join-Path $root 'scripts')
    '{}' | Set-Content (Join-Path $root 'service.json')
    '{"artifact":{"path":"unused"}}' | Set-Content (Join-Path $root 'verify/service-harness.json')
    $env:BROKER_TEST_FAIL = $case
    $env:BROKER_TEST_CALLS = Join-Path $root 'calls.txt'
    # Establish the real native exit before asking the copied production script
    # to propagate it. Separate output prevents this preflight from satisfying
    # any package/archive assertion below.
    if ($case -in @('sbom', 'archive')) {
      $command = if ($case -eq 'sbom') { './cmd/sbom' } else { './cmd/releasearchive' }
      $preflight = Join-Path $root 'preflight-output'
      if ($case -eq 'sbom') {
        & (Join-Path $bin.FullName 'go.cmd') run $command --output $preflight
      } else {
        & (Join-Path $bin.FullName 'go.cmd') run $command --source unused --output $preflight
      }
      $nativeExit = $LASTEXITCODE
      $expectedExit = @{sbom=23;archive=29}[$case]
      "native exit=$nativeExit expected=$expectedExit" | Set-Content (Join-Path $root 'preflight.log')
      if ($nativeExit -ne $expectedExit) { throw "Fixture native preflight failed in $case : $nativeExit" }
    }
    $failure = $null
    try {
      if ($case -in @('sbom', 'archive', 'success')) {
        & (Join-Path $root 'scripts/package.ps1') *> (Join-Path $root 'output.log')
      } else {
        & (Join-Path $root 'scripts/verify.ps1') *> (Join-Path $root 'output.log')
      }
    } catch { $failure = $_ }
    if ($case -eq 'success') {
      if ($failure -or !(Test-Path (Join-Path $root 'dist/secretsbroker-win32.zip'))) { throw 'Successful native helpers did not produce candidate' }
    } else {
      $expected = @{sbom=23;archive=29;validate=31;run=37}[$case]
      if (!$failure -or "$failure" -notmatch "exit code $expected") { throw "Lost native failure in $case : $failure" }
      if ($case -eq 'archive' -and (Test-Path (Join-Path $root 'dist/secretsbroker-win32.zip'))) { throw 'Failed archive remained available' }
      if ($case -eq 'validate' -and (Get-Content $env:BROKER_TEST_CALLS) -contains 'run') { throw 'Harness ran after failed contract validation' }
      if ((Get-Content (Join-Path $root 'output.log') -Raw) -match 'Created ') { throw 'Failure reported candidate success' }
    }
    Write-Output "PASS $case"
  }
} finally {
  $env:PATH = $oldPath
  $env:SERVICE_LASSO_HARNESS_BIN = $oldHarness
  Remove-Item Env:BROKER_TEST_FAIL, Env:BROKER_TEST_CALLS -ErrorAction SilentlyContinue
  # Retain the isolated original logs for qualification readback.
  Write-Output "Fixture evidence: $fixture"
}
