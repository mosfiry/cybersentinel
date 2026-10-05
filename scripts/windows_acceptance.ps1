[CmdletBinding()]
param(
    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This acceptance script must run on Windows; Linux results do not certify the Windows product."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$runtimeDir = Join-Path $env:TEMP ("CyberSentinel-llama-b11146-" + [Guid]::NewGuid().ToString("N"))
Push-Location $repoRoot
try {
    Write-Host "Running focused Python regressions..."
    python -m pytest -q tests/test_local_model_catalog.py tests/test_local_model_manager.py tests/test_local_model_downloader.py tests/test_local_model_acceptance_harness.py tests/test_desktop_client.py
    if ($LASTEXITCODE -ne 0) { throw "Focused Python regression suite failed ($LASTEXITCODE)." }

    Write-Host "Running Desktop syntax and contract tests..."
    Push-Location (Join-Path $repoRoot "desktop")
    try {
        npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed ($LASTEXITCODE)." }
        npm run check
        if ($LASTEXITCODE -ne 0) { throw "Desktop syntax check failed ($LASTEXITCODE)." }
        node --check (Join-Path $repoRoot "web/app.js")
        if ($LASTEXITCODE -ne 0) { throw "Browser renderer syntax check failed ($LASTEXITCODE)." }
        npm run icon
        if ($LASTEXITCODE -ne 0) { throw "Desktop icon fixture generation failed ($LASTEXITCODE)." }
        npm run test:desktop
        if ($LASTEXITCODE -ne 0) { throw "Desktop contract tests failed ($LASTEXITCODE)." }
    }
    finally { Pop-Location }

    Write-Host "Downloading the pinned llama.cpp Windows CPU runtime to an isolated temporary path..."
    python (Join-Path $repoRoot "scripts/download_llama_runtime.py") --output $runtimeDir
    if ($LASTEXITCODE -ne 0) { throw "Pinned llama.cpp runtime download/verification failed ($LASTEXITCODE)." }

    $acceptanceArgs = @(
        (Join-Path $repoRoot "scripts/local_model_acceptance.py"),
        "--runtime-dir", $runtimeDir
    )
    if ($KeepArtifacts) { $acceptanceArgs += "--keep-artifacts" }
    Write-Host "Downloading the pinned Qwen3 4B model, running direct local inference and an Owner-authenticated status-tool mission, and verifying provider binding, tool scope, trajectory, evidence, and persistence..."
    python @acceptanceArgs
    if ($LASTEXITCODE -ne 0) { throw "Real-model Windows acceptance failed ($LASTEXITCODE)." }

    if (-not $KeepArtifacts -and (Test-Path $runtimeDir)) {
        Remove-Item -LiteralPath $runtimeDir -Recurse -Force
    }
    Write-Host "PASS: actual Windows CPU runtime, verified Qwen artifact, local inference, Owner-authenticated mission, status-tool evidence lineage, persistence, and runtime shutdown were exercised."
}
finally {
    Pop-Location
}
