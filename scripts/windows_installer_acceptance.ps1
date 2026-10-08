[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [Parameter(Mandatory = $true)][string]$InstallRoot,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [ValidateSet("smoke", "full")][string]$Mode = "smoke",
    [switch]$RunSourceTreeE2ESupplemental,
    [string]$ExpectedSha256 = "",
    [long]$ExpectedSizeBytes = 0,
    [string]$ExpectedSourceCommit = ""
)

$ErrorActionPreference = "Stop"
$started = [DateTime]::UtcNow
$report = [ordered]@{
    schema = "cybersentinel-windows-native-installer-acceptance-v1"
    status = "FAIL"
    mode = $Mode
    started_at_utc = $started.ToString("o")
    environment = [ordered]@{
        os = [Environment]::OSVersion.VersionString
        runner_os = $env:RUNNER_OS
        runner_arch = $env:RUNNER_ARCH
        image_os = $env:ImageOS
        image_version = $env:ImageVersion
        interactive_user_session = $false
    }
    installer = [ordered]@{}
    installation = [ordered]@{}
    application_launch = [ordered]@{}
    installed_desktop_ui = [ordered]@{}
    full_mission_e2e = [ordered]@{ status = "NOT_RUN" }
    source_tree_e2e_supplemental = [ordered]@{ status = "NOT_RUN"; provenance = "checkout_source_not_installed_backend" }
    local_model_file = [ordered]@{}
    cleanup = [ordered]@{}
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$installDirectory = Join-Path $InstallRoot "CyberSentinel"
$profileRoot = Join-Path $env:RUNNER_TEMP ("cybersentinel-disposable-profile-" + [Guid]::NewGuid().ToString("N"))
$outputJson = Join-Path $EvidenceDirectory "installer-acceptance.json"
$uiJson = Join-Path $EvidenceDirectory "desktop-ui-acceptance.json"
$e2eJson = Join-Path $EvidenceDirectory "full-e2e-acceptance.json"
$e2eState = $null
$exePath = Join-Path $installDirectory "CyberSentinel.exe"
$applicationProcess = $null
$originalAppData = $env:APPDATA
$originalLocalAppData = $env:LOCALAPPDATA

function Save-Report {
    param([string]$Path, [object]$Value)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Stop-ApplicationTree {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return $true }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            & taskkill.exe /PID $Process.Id /T /F | Out-Null
            Start-Sleep -Seconds 2
        }
        $Process.Refresh()
        return $Process.HasExited
    }
    catch { return $false }
}

function Get-NormalizedWindowsProductVersion {
    param([string]$Version)
    $baseVersion = [string](($Version -split '-', 2)[0])
    $segments = $baseVersion.Split('.')
    if ($segments.Count -eq 3) { return "$baseVersion.0" }
    return $baseVersion
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw "This acceptance path requires a native Windows runner."
    }
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw "Installer file not found."
    }
    New-Item -ItemType Directory -Force -Path $EvidenceDirectory, $InstallRoot, $profileRoot | Out-Null
    $installerItem = Get-Item -LiteralPath $InstallerPath
    $installerHash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sidecarPath = "$InstallerPath.sha256"
    $sidecarPresent = Test-Path -LiteralPath $sidecarPath -PathType Leaf
    $sidecarHash = $null
    if ($sidecarPresent) {
        $sidecarLine = (Get-Content -LiteralPath $sidecarPath -Raw).Trim()
        $sidecarHash = (($sidecarLine -split '\s+')[0]).ToLowerInvariant()
    }
    $candidateManifestPath = Join-Path (Split-Path -Parent $InstallerPath) "installer-manifest.json"
    $candidateManifest = if (Test-Path -LiteralPath $candidateManifestPath -PathType Leaf) {
        Get-Content -LiteralPath $candidateManifestPath -Raw | ConvertFrom-Json
    } else { $null }
    $expectedVersion = (Get-Content -LiteralPath (Join-Path $repoRoot "VERSION") -Raw).Trim()
    if ($candidateManifest -and $candidateManifest.version) {
        $expectedVersion = [string]$candidateManifest.version
    }
    $sourceCommitMatches = if ([string]::IsNullOrWhiteSpace($ExpectedSourceCommit)) { $true } else {
        $null -ne $candidateManifest -and $candidateManifest.source_commit -eq $ExpectedSourceCommit
    }
    $manifestDigestMatches = if ($null -eq $candidateManifest) { [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) } else {
        $candidateManifest.sha256 -eq $installerHash -and $candidateManifest.size_bytes -eq $installerItem.Length
    }
    $report.installer = [ordered]@{
        filename = $installerItem.Name
        size_bytes = [long]$installerItem.Length
        sha256 = $installerHash
        expected_product_version = $expectedVersion
        expected_size_bytes = $ExpectedSizeBytes
        expected_sha256 = $ExpectedSha256.ToLowerInvariant()
        sha256_sidecar = [ordered]@{ present = $sidecarPresent; digest = $sidecarHash; matches_executable = ($sidecarHash -eq $installerHash) }
        candidate_manifest = [ordered]@{
            present = ($null -ne $candidateManifest)
            source_commit = if ($candidateManifest) { $candidateManifest.source_commit } else { $null }
            expected_source_commit = $ExpectedSourceCommit
            source_commit_matches = $sourceCommitMatches
            digest_and_size_match = $manifestDigestMatches
        }
        integrity_pass = (($ExpectedSizeBytes -le 0 -or $installerItem.Length -eq $ExpectedSizeBytes) -and
                          ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $installerHash -eq $ExpectedSha256.ToLowerInvariant()) -and
                          (-not $sidecarPresent -or $sidecarHash -eq $installerHash) -and
                          ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $sidecarPresent) -and
                          $sourceCommitMatches -and $manifestDigestMatches)
    }
    if (-not $report.installer.integrity_pass) { throw "Installer size or SHA-256 did not match the required value." }

    New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
    if ($installDirectory -match '\s') { throw "NSIS acceptance install path must not contain spaces." }
    $env:APPDATA = $profileRoot
    $env:LOCALAPPDATA = Join-Path $profileRoot "Local"
    New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA | Out-Null
    $installerProcess = Start-Process -FilePath $InstallerPath -ArgumentList "/S /D=$installDirectory" -PassThru
    if (-not $installerProcess.WaitForExit(600000)) {
        Stop-Process -Id $installerProcess.Id -Force -ErrorAction SilentlyContinue
        throw "Silent installer exceeded the 600-second bound."
    }
    $installerProcess.Refresh()
    $installerExitCode = $installerProcess.ExitCode
    $env:APPDATA = $originalAppData
    $env:LOCALAPPDATA = $originalLocalAppData
    $installDeadline = [DateTime]::UtcNow.AddSeconds(90)
    while (-not (Test-Path -LiteralPath $exePath -PathType Leaf) -and [DateTime]::UtcNow -lt $installDeadline) {
        Start-Sleep -Milliseconds 500
    }
    $installed = Test-Path -LiteralPath $exePath -PathType Leaf
    $fileVersion = if ($installed) { (Get-Item -LiteralPath $exePath).VersionInfo } else { $null }
    $expectedWindowsProductVersion = Get-NormalizedWindowsProductVersion $expectedVersion
    $fileVersionMatches = $null -ne $fileVersion -and [string]$fileVersion.FileVersion -eq $expectedVersion
    $productVersionMatches = $null -ne $fileVersion -and
        ([string]$fileVersion.ProductVersion -eq $expectedVersion -or
         [string]$fileVersion.ProductVersion -eq $expectedWindowsProductVersion) -and
        $fileVersionMatches
    $report.installation = [ordered]@{
        silent_installer_exit_code = $installerExitCode
        install_directory = $installDirectory
        installed_executable_exists = $installed
        executable_size_bytes = if ($installed) { (Get-Item -LiteralPath $exePath).Length } else { 0 }
        product_version = if ($fileVersion) { $fileVersion.ProductVersion } else { $null }
        file_version = if ($fileVersion) { $fileVersion.FileVersion } else { $null }
        expected_file_version = $expectedVersion
        expected_normalized_windows_product_version = $expectedWindowsProductVersion
        file_version_matches_expected = $fileVersionMatches
        product_version_matches_expected = $productVersionMatches
    }
    if ($installerExitCode -ne 0 -or -not $installed -or -not $productVersionMatches) { throw "Silent installation or normalized ProductVersion/FileVersion consistency check failed." }

    Get-CimInstance Win32_Process -Filter "Name = 'CyberSentinel.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($installDirectory, [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object { & taskkill.exe /PID $_.ProcessId /T /F | Out-Null }
    Start-Sleep -Seconds 2

    $tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $tcpListener.Start()
    $cdpPort = [int]$tcpListener.LocalEndpoint.Port
    $tcpListener.Stop()
    $cdpUrl = "http://127.0.0.1:$cdpPort"
    $env:APPDATA = $profileRoot
    $env:LOCALAPPDATA = Join-Path $profileRoot "Local"
    $applicationProcess = Start-Process -FilePath $exePath -ArgumentList @(
        "--disable-gpu", "--remote-debugging-port=$cdpPort", "--remote-allow-origins=*"
    ) -PassThru
    $env:APPDATA = $originalAppData
    $env:LOCALAPPDATA = $originalLocalAppData

    $debugEndpointReady = $false
    $debugVersion = $null
    $launchDeadline = [DateTime]::UtcNow.AddSeconds(150)
    while ([DateTime]::UtcNow -lt $launchDeadline) {
        $applicationProcess.Refresh()
        if ($applicationProcess.HasExited) { break }
        try {
            $debugVersion = Invoke-RestMethod -Uri "$cdpUrl/json/version" -TimeoutSec 3
            if ($debugVersion.Browser) { $debugEndpointReady = $true; break }
        }
        catch { Start-Sleep -Seconds 2 }
    }
    Start-Sleep -Seconds 8
    $applicationProcess.Refresh()
    $windowHandle = if (-not $applicationProcess.HasExited) { [string]$applicationProcess.MainWindowHandle } else { "0" }
    $windowTitle = if (-not $applicationProcess.HasExited) { $applicationProcess.MainWindowTitle } else { "" }
    $report.application_launch = [ordered]@{
        process_id = $applicationProcess.Id
        process_alive_after_startup = (-not $applicationProcess.HasExited)
        main_window_handle = $windowHandle
        main_window_title = $windowTitle
        cdp_endpoint_ready = $debugEndpointReady
        cdp_browser = if ($debugVersion) { $debugVersion.Browser } else { $null }
        startup_bound_seconds = 150
    }
    if ($applicationProcess.HasExited -or -not $debugEndpointReady) {
        throw "Installed Desktop did not stay running with a reachable renderer within the 150-second bound."
    }

    $python = (Get-Command python -ErrorAction Stop).Source
    $uiArgs = @(
        (Join-Path $repoRoot "scripts/windows_desktop_acceptance.py"),
        "--cdp-port", [string]$cdpPort,
        "--expected-version", $expectedVersion,
        "--profile-root", $profileRoot,
        "--mode", $Mode,
        "--output", $uiJson
    )
    if ($Mode -eq "full") { $uiArgs += @("--model-timeout-seconds", "2400") }
    & $python @uiArgs
    $uiExitCode = $LASTEXITCODE
    if (Test-Path -LiteralPath $uiJson -PathType Leaf) {
        $uiReport = Get-Content -LiteralPath $uiJson -Raw | ConvertFrom-Json
        $report.installed_desktop_ui = $uiReport
        $report.installed_desktop_ui | Add-Member -NotePropertyName python_exit_code -NotePropertyValue $uiExitCode -Force
    }
    else {
        $report.installed_desktop_ui = [ordered]@{ status = "FAIL"; python_exit_code = $uiExitCode; error = "UI acceptance report was not created." }
    }

    $installedModelInferencePassed = $report.installed_desktop_ui.model_manager.real_inference_completed -eq $true
    $installedOwnerAuthenticationPassed = $report.installed_desktop_ui.owner_authentication.first_run_authenticated -eq $true
    if ($Mode -eq "full" -and $installedModelInferencePassed -and $installedOwnerAuthenticationPassed) {
        $modelId = [string]$report.installed_desktop_ui.model_manager.qwen3_4b.model_id
        $modelFiles = @(Get-ChildItem -LiteralPath $profileRoot -Filter "Qwen3-4B-Q4_K_M.gguf" -File -Recurse -ErrorAction SilentlyContinue)
        if ($modelFiles.Count -ne 1) {
            $report.local_model_file = [ordered]@{ matches_in_disposable_profile = $modelFiles.Count }
            throw "Expected exactly one Qwen3 4B model under the disposable application profile."
        }
        $modelPath = $modelFiles[0].FullName
        $runtimePath = Join-Path $installDirectory "resources\llama"
        if (Test-Path -LiteralPath $modelPath -PathType Leaf) {
            $modelFile = Get-Item -LiteralPath $modelPath
            $modelHash = (Get-FileHash -LiteralPath $modelPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $expectedModelHash = [string]$report.installed_desktop_ui.model_manager.qwen3_4b.sha256
            $expectedModelSize = [long]$report.installed_desktop_ui.model_manager.qwen3_4b.size_bytes
            $report.local_model_file = [ordered]@{
                exists = $true
                path = $modelPath
                size_bytes = [long]$modelFile.Length
                sha256 = $modelHash
                expected_size_bytes = $expectedModelSize
                expected_sha256 = $expectedModelHash
                integrity_pass = ($modelFile.Length -eq $expectedModelSize -and $modelHash -eq $expectedModelHash.ToLowerInvariant())
            }
            if (-not $report.local_model_file.integrity_pass) {
                throw "Downloaded Qwen model size or SHA-256 does not match the application catalog."
            }
        }
        else {
            $report.local_model_file = [ordered]@{ exists = $false; path = $modelPath }
            throw "Qwen3 4B model file is missing from the installed app profile after Model Manager acceptance."
        }
        $report.installed_desktop_ui.model_manager.qwen3_4b |
            Add-Member -NotePropertyName file_sha256_recomputed_from_disk -NotePropertyValue $report.local_model_file.sha256 -Force
        $runtimeBinary = Join-Path $runtimePath "llama-server.exe"
        if (Test-Path -LiteralPath $runtimeBinary -PathType Leaf) {
            $runtimeItem = Get-Item -LiteralPath $runtimeBinary
            $runtimeEvidence = [ordered]@{
                path = $runtimeBinary
                size_bytes = [long]$runtimeItem.Length
                sha256 = (Get-FileHash -LiteralPath $runtimeBinary -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $report.installed_desktop_ui.model_manager |
                Add-Member -NotePropertyName local_runtime_binary -NotePropertyValue $runtimeEvidence -Force
        }
        else {
            $report.installed_desktop_ui.model_manager |
                Add-Member -NotePropertyName local_runtime_binary -NotePropertyValue ([ordered]@{ exists = $false; path = $runtimeBinary }) -Force
            throw "The installed application is missing its bundled llama-server.exe."
        }
        $report.full_mission_e2e = $report.installed_desktop_ui.installed_app_mission
        if ($RunSourceTreeE2ESupplemental) {
            $e2eState = Join-Path $env:RUNNER_TEMP ("cybersentinel-source-e2e-state-" + [Guid]::NewGuid().ToString("N"))
            $e2eArgs = @(
                (Join-Path $repoRoot "scripts/run_full_e2e_gate_acceptance.py"),
                "--runtime-dir", $runtimePath,
                "--model-file", $modelPath,
                "--artifact", $e2eJson,
                "--state-dir", $e2eState
            )
            & $python @e2eArgs
            $e2eExitCode = $LASTEXITCODE
            if (Test-Path -LiteralPath $e2eJson -PathType Leaf) {
                $report.source_tree_e2e_supplemental = Get-Content -LiteralPath $e2eJson -Raw | ConvertFrom-Json
                $report.source_tree_e2e_supplemental | Add-Member -NotePropertyName python_exit_code -NotePropertyValue $e2eExitCode -Force
                $report.source_tree_e2e_supplemental | Add-Member -NotePropertyName provenance -NotePropertyValue "checkout_source_and_installed_llama_cpp_runtime_model; not installed backend" -Force
            }
            else {
                $report.source_tree_e2e_supplemental = [ordered]@{ status = "FAIL"; python_exit_code = $e2eExitCode; provenance = "checkout_source_not_installed_backend"; error = "Supplemental source-tree E2E report was not created." }
            }
        }
    }
    elseif ($Mode -eq "full") {
        if ($report.installed_desktop_ui.installed_app_mission) {
            $report.full_mission_e2e = $report.installed_desktop_ui.installed_app_mission
        }
        else {
            $report.full_mission_e2e = [ordered]@{ status = "BLOCKED"; provenance = "installed_backend_not_reached"; reason = "Installed UI/Qwen acceptance did not reach a Mission report." }
        }
    }

    $uiPass = $report.installed_desktop_ui.status -eq "PASS"
    $installedMissionPass = ($Mode -eq "smoke") -or ($report.full_mission_e2e.status -eq "PASS")
    $sourceSupplementPass = (-not $RunSourceTreeE2ESupplemental) -or ($report.source_tree_e2e_supplemental.status -eq "PASS")
    $report.status = if ($uiPass -and $installedMissionPass -and $sourceSupplementPass) { "PASS" } else { "FAIL" }
}
catch {
    $report.status = "FAIL"
    $report.error_type = $_.Exception.GetType().FullName
    $report.error = [string]$_.Exception.Message
    if ($Mode -eq "full" -and $report.full_mission_e2e.status -eq "NOT_RUN") {
        $report.full_mission_e2e = [ordered]@{ status = "BLOCKED"; reason = "Acceptance stopped before the full mission stage." }
    }
}
finally {
    $env:APPDATA = $originalAppData
    $env:LOCALAPPDATA = $originalLocalAppData
    $processStopped = Stop-ApplicationTree -Process $applicationProcess
    $report.cleanup.application_process_tree_stopped = $processStopped
    if ($report.installation.installed_executable_exists -and (Test-Path -LiteralPath $installDirectory)) {
        try {
            Remove-Item -LiteralPath $installDirectory -Recurse -Force
            $report.cleanup.install_directory_removed = -not (Test-Path -LiteralPath $installDirectory)
        }
        catch { $report.cleanup.install_directory_removed = $false; $report.cleanup.install_directory_cleanup_error = $_.Exception.GetType().Name }
    }
    if (Test-Path -LiteralPath $profileRoot) {
        try {
            Remove-Item -LiteralPath $profileRoot -Recurse -Force
            $report.cleanup.disposable_profile_removed = -not (Test-Path -LiteralPath $profileRoot)
        }
        catch { $report.cleanup.disposable_profile_removed = $false; $report.cleanup.disposable_profile_cleanup_error = $_.Exception.GetType().Name }
    }
    if ($Mode -eq "full" -and $e2eState -and (Test-Path -LiteralPath $e2eState)) {
        try {
            Remove-Item -LiteralPath $e2eState -Recurse -Force
            $report.cleanup.full_e2e_state_removed = -not (Test-Path -LiteralPath $e2eState)
        }
        catch { $report.cleanup.full_e2e_state_removed = $false; $report.cleanup.full_e2e_state_cleanup_error = $_.Exception.GetType().Name }
    }
    elseif ($Mode -ne "full" -or -not $e2eState) {
        $report.cleanup.full_e2e_state_removed = $true
    }
    if ($report.status -eq "PASS" -and
        ($report.cleanup.application_process_tree_stopped -ne $true -or
         $report.cleanup.install_directory_removed -ne $true -or
         $report.cleanup.disposable_profile_removed -ne $true -or
         $report.cleanup.full_e2e_state_removed -ne $true)) {
        $report.status = "FAIL"
        $report.cleanup.cleanup_gate_failed = $true
    }
    $report.completed_at_utc = [DateTime]::UtcNow.ToString("o")
    $report.elapsed_seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 3)
    Save-Report -Path $outputJson -Value $report
}

Write-Host ("Windows acceptance {0}: {1}" -f $Mode, $report.status)
Write-Host ("Evidence: {0}" -f $outputJson)
exit 0
