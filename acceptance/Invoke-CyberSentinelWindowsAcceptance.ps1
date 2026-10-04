[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [string]$ExpectedSha256 = "36e4149afa27b996fa487d874476ea3064d82827ce6e8c94ef820bd951eaf36e",

    [string]$EvidenceDirectory = ""
)

$ErrorActionPreference = "Stop"
$ExpectedSourceCommit = "26739d9b01b3b1ff492854e7e21789be20b1be0e"
$ExpectedInstallerName = "CyberSentinel-Setup-5.1.0.exe"
$script:Checks = [System.Collections.Generic.List[object]]::new()
$script:CdpSocket = $null
$script:CdpSequence = 0
$script:AppProcess = $null
$script:Evidence = $null
$script:InstallRoot = $null
$script:ProfileRoot = $null
$script:ProjectName = $null
$script:CanonicalUsername = $null
$script:Password = $null
$script:Port = $null
$script:TranscriptStarted = $false

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Details)
    $script:Checks.Add([pscustomobject]@{
        name = $Name
        status = $Status
        details = $Details
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
    })
}

function Write-Event {
    param([string]$Event, [hashtable]$Data = @{})
    $entry = [ordered]@{ timestamp_utc = [DateTime]::UtcNow.ToString("o"); event = $Event }
    foreach ($key in $Data.Keys) { $entry[$key] = $Data[$key] }
    ($entry | ConvertTo-Json -Depth 12 -Compress) | Add-Content -LiteralPath (Join-Path $script:Evidence "acceptance.jsonl") -Encoding utf8
}

function Get-UiSnapshot {
    $expression = @'
JSON.stringify((() => {
  const visible = (element) => Boolean(element && !element.classList.contains('hidden'));
  const root = document.querySelector('#settingsModelList .model-card')
    ? '#settingsModelList .model-card' : '#setupModelList .model-card';
  const cards = Array.from(document.querySelectorAll(root)).map((card) => {
    const button = card.querySelector('button');
    return {
      title: card.querySelector('h3')?.textContent?.trim() || '',
      description: card.querySelector('p')?.textContent?.trim() || '',
      modelId: button?.dataset?.modelId || '',
      action: button?.dataset?.modelAction || (button?.disabled ? 'disabled' : 'none'),
      buttonText: button?.textContent?.trim() || '',
      disabled: Boolean(button?.disabled),
      stateText: card.querySelector('.model-progress')?.textContent?.trim() || ''
    };
  });
  const externalOrigins = Array.from(new Set(performance.getEntriesByType('resource')
    .map((entry) => { try { const u = new URL(entry.name); return (u.protocol === 'http:' || u.protocol === 'https:') ? u.origin : ''; } catch { return ''; } })
    .filter((origin) => origin && !/^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/i.test(origin))));
  return {
    title: document.title,
    firstRunVisible: visible(document.querySelector('#firstRunOverlay')),
    hardwareText: document.querySelector('#setupHardware')?.textContent?.trim() || '',
    setupCardCount: document.querySelectorAll('#setupModelList .model-card').length,
    managerCardCount: document.querySelectorAll('#settingsModelList .model-card').length,
    modelCards: cards,
    runtimeText: document.querySelector('#runtimeState')?.textContent?.trim() || '',
    authText: document.querySelector('#authState')?.textContent?.trim() || '',
    authMessage: document.querySelector('#authMessage')?.textContent?.trim() || '',
    ownerUsername: document.querySelector('#setupOwnerUsername')?.textContent?.trim() || '',
    loginUsername: document.querySelector('#loginUsername')?.value?.trim() || '',
    ownerMessage: document.querySelector('#ownerSetupMessage')?.textContent?.trim() || '',
    projectText: document.querySelector('#projectList')?.textContent?.trim() || '',
    projectMessage: document.querySelector('#projectMessage')?.textContent?.trim() || '',
    settingsVisible: visible(document.querySelector('#infoPanel')) && (document.querySelector('#infoPanel')?.innerText || '').includes('إدارة النماذج المحلية'),
    externalOrigins,
    resources: performance.getEntriesByType('resource').length
  };
})())
'@
    $json = Invoke-CdpEvaluation -Expression $expression
    return ($json | ConvertFrom-Json)
}

function Invoke-Cdp {
    param([string]$Method, [hashtable]$Parameters = @{})
    if (-not $script:CdpSocket -or $script:CdpSocket.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
        throw "CDP socket is not connected."
    }
    $script:CdpSequence++
    $requestId = $script:CdpSequence
    $request = [ordered]@{ id = $requestId; method = $Method; params = $Parameters }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Depth 20 -Compress))
    $sendSegment = [System.ArraySegment[byte]]::new($bytes, 0, $bytes.Length)
    $script:CdpSocket.SendAsync($sendSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()

    while ($true) {
        $builder = [System.Text.StringBuilder]::new()
        do {
            $buffer = [byte[]]::new(65536)
            $receiveSegment = [System.ArraySegment[byte]]::new($buffer, 0, $buffer.Length)
            $received = $script:CdpSocket.ReceiveAsync($receiveSegment, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($received.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                throw "CDP websocket closed before replying to $Method."
            }
            [void]$builder.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $received.Count))
        } while (-not $received.EndOfMessage)

        $message = $builder.ToString() | ConvertFrom-Json
        if ($null -ne $message.id -and [int]$message.id -eq $requestId) {
            if ($message.error) { throw "CDP $Method failed: $($message.error.message)" }
            return $message
        }
    }
}

function Invoke-CdpEvaluation {
    param([string]$Expression)
    $reply = Invoke-Cdp -Method "Runtime.evaluate" -Parameters @{
        expression = $Expression
        awaitPromise = $true
        returnByValue = $true
        userGesture = $true
    }
    if ($reply.result.exceptionDetails) {
        throw "Renderer evaluation failed: $($reply.result.exceptionDetails.text)"
    }
    return $reply.result.result.value
}

function Wait-ForUi {
    param([scriptblock]$Condition, [int]$TimeoutSeconds = 90, [string]$Description = "UI condition")
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $snapshot = Get-UiSnapshot
        if (& $Condition $snapshot) { return $snapshot }
        Start-Sleep -Milliseconds 700
    } while ([DateTime]::UtcNow -lt $deadline)
    $last = Get-UiSnapshot
    throw "Timed out waiting for $Description. Last UI state: $($last | ConvertTo-Json -Depth 8 -Compress)"
}

function Save-UiScreenshot {
    param([string]$FileName)
    $reply = Invoke-Cdp -Method "Page.captureScreenshot" -Parameters @{ format = "png"; fromSurface = $true; captureBeyondViewport = $false }
    $path = Join-Path $script:Evidence $FileName
    [System.IO.File]::WriteAllBytes($path, [Convert]::FromBase64String([string]$reply.result.data))
    if ((Get-Item -LiteralPath $path).Length -lt 1000) { throw "Screenshot looks empty: $FileName" }
    return $path
}

function Start-InstalledApp {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:AppExe
    $psi.Arguments = "--remote-debugging-port=$($script:Port) --user-data-dir=`"$($script:ProfileRoot)`""
    $psi.WorkingDirectory = $script:InstallRoot
    $psi.UseShellExecute = $true
    $script:AppProcess = [System.Diagnostics.Process]::Start($psi)
    if (-not $script:AppProcess) { throw "Installed CyberSentinel process did not start." }
    Write-Event -Event "app_process_started" -Data @{ process_id = $script:AppProcess.Id; session_id = $script:AppProcess.SessionId; executable = $script:AppExe }
}

function Connect-AppUi {
    param([int]$TimeoutSeconds = 120)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $version = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $version = Invoke-RestMethod -Uri "http://127.0.0.1:$($script:Port)/json/version" -TimeoutSec 3
            break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $version) { throw "Electron DevTools endpoint did not become ready on loopback." }

    $targets = Invoke-RestMethod -Uri "http://127.0.0.1:$($script:Port)/json/list" -TimeoutSec 5
    $target = @($targets | Where-Object { $_.type -eq "page" } | Select-Object -First 1)
    if (-not $target -or -not $target[0].webSocketDebuggerUrl) { throw "No Electron renderer page target was exposed." }
    $script:CdpSocket = [System.Net.WebSockets.ClientWebSocket]::new()
    $script:CdpSocket.ConnectAsync([Uri]$target[0].webSocketDebuggerUrl, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    [void](Invoke-Cdp -Method "Page.enable")
    [void](Invoke-Cdp -Method "Runtime.enable")
    [void](Invoke-Cdp -Method "Page.bringToFront")
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $state = Get-UiSnapshot
            if ($state.title -and $state.runtimeText -match '●') { return $state }
        } catch { }
        Start-Sleep -Milliseconds 700
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "CyberSentinel renderer did not finish loading its UI."
}

function Close-InstalledApp {
    if ($script:AppProcess -and -not $script:AppProcess.HasExited) {
        try {
            $script:AppProcess.Refresh()
            $handle = $script:AppProcess.MainWindowHandle
            if ($handle -ne [IntPtr]::Zero) {
                [void][CyberSentinelAcceptanceNative]::PostMessage($handle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
            } elseif ($script:CdpSocket -and $script:CdpSocket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                try { [void](Invoke-Cdp -Method "Browser.close") } catch { }
            }
            $null = $script:AppProcess.WaitForExit(30000)
        } catch { }
        if (-not $script:AppProcess.HasExited) {
            try { Stop-Process -Id $script:AppProcess.Id -Force -ErrorAction SilentlyContinue } catch { }
            $null = $script:AppProcess.WaitForExit(10000)
        }
    }
    if ($script:CdpSocket) {
        try { $script:CdpSocket.Dispose() } catch { }
        $script:CdpSocket = $null
    }
}

function Get-ModelFingerprint {
    param($Snapshot)
    return (@($Snapshot.modelCards | Sort-Object modelId | ForEach-Object {
        "{0}|{1}|{2}|{3}" -f $_.modelId, $_.title, $_.action, $_.buttonText
    }) -join ";")
}

try {
    if ($env:OS -ne "Windows_NT") { throw "This acceptance script must run on Windows." }
    if ($PSVersionTable.PSVersion.Major -lt 5) { throw "Windows PowerShell 5.1 or PowerShell 7+ is required." }
    if ([Environment]::Is64BitOperatingSystem -ne $true) { throw "The installer is x64; a 64-bit Windows OS is required." }

    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path
    if ([System.IO.Path]::GetFileName($resolvedInstaller) -ne $ExpectedInstallerName) {
        throw "Expected $ExpectedInstallerName; received $([System.IO.Path]::GetFileName($resolvedInstaller))."
    }
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "ExpectedSha256 must be a 64-character SHA-256 hex string." }

    if (-not $EvidenceDirectory) {
        $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        $EvidenceDirectory = Join-Path $PSScriptRoot "evidence-$stamp"
    }
    $script:Evidence = [System.IO.Path]::GetFullPath($EvidenceDirectory)
    New-Item -ItemType Directory -Path $script:Evidence -Force | Out-Null
    Start-Transcript -Path (Join-Path $script:Evidence "powershell-transcript.txt") -Force | Out-Null
    $script:TranscriptStarted = $true

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CyberSentinelAcceptanceNative {
    [DllImport("user32.dll", SetLastError=true)] public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetShortPathName(string longPath, System.Text.StringBuilder shortPath, uint bufferLength);
}
"@

    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $machine = [ordered]@{
        captured_utc = [DateTime]::UtcNow.ToString("o")
        os_caption = $os.Caption
        os_version = $os.Version
        os_build = $os.BuildNumber
        os_architecture = $os.OSArchitecture
        processor_count = [Environment]::ProcessorCount
        physical_memory_bytes = [int64]$computer.TotalPhysicalMemory
        powershell_version = $PSVersionTable.PSVersion.ToString()
        user_interactive = [Environment]::UserInteractive
        current_session_id = (Get-Process -Id $PID).SessionId
        github_runner_name = $env:RUNNER_NAME
        github_runner_os = $env:RUNNER_OS
        github_runner_arch = $env:RUNNER_ARCH
        github_run_id = $env:GITHUB_RUN_ID
        source_commit_expected = $ExpectedSourceCommit
    }
    $machine | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:Evidence "machine.json") -Encoding utf8
    Write-Event -Event "machine_inventory" -Data $machine

    $actualHash = (Get-FileHash -LiteralPath $resolvedInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashOk = $actualHash -eq $ExpectedSha256.ToLowerInvariant()
    Add-Check -Name "Installer SHA-256" -Status $(if ($hashOk) { "PASS" } else { "FAIL" }) -Details "actual=$actualHash expected=$($ExpectedSha256.ToLowerInvariant())"
    if (-not $hashOk) { throw "Installer SHA-256 did not match the pinned value." }

    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedInstaller
    Write-Event -Event "authenticode_inspection" -Data @{ status = [string]$signature.Status; signer = [string]$signature.SignerCertificate.Subject; action = "inspected_only_no_bypass_or_signing" }
    Add-Check -Name "Signature / SmartScreen handling" -Status "PASS" -Details "Authenticode status inspected as $($signature.Status); no signing, unblocking, or SmartScreen bypass was performed."

    $script:InstallRoot = Join-Path $script:Evidence "fresh-install"
    $script:ProfileRoot = Join-Path $script:Evidence "isolated-user-data"
    New-Item -ItemType Directory -Path $script:InstallRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $script:ProfileRoot -Force | Out-Null
    $possibleInstallRoots = @(
        $script:InstallRoot,
        (Join-Path $env:LOCALAPPDATA "Programs\CyberSentinel"),
        (Join-Path $env:LOCALAPPDATA "CyberSentinel"),
        (Join-Path $env:ProgramFiles "CyberSentinel"),
        (Join-Path ${env:ProgramFiles(x86)} "CyberSentinel")
    ) | Where-Object { $_ } | Select-Object -Unique
    $preexisting = @($possibleInstallRoots | ForEach-Object { Join-Path $_ "CyberSentinel.exe" } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($preexisting.Count -gt 0) { throw "An existing CyberSentinel installation was found; no install was attempted: $($preexisting -join ', ')" }
    $shortPathBuffer = [System.Text.StringBuilder]::new(1024)
    $shortPathLength = [CyberSentinelAcceptanceNative]::GetShortPathName($script:InstallRoot, $shortPathBuffer, [uint32]$shortPathBuffer.Capacity)
    $installArgumentPath = $script:InstallRoot
    if ($script:InstallRoot.Contains(" ")) {
        if ($shortPathLength -eq 0 -or $shortPathLength -ge $shortPathBuffer.Capacity) { throw "Cannot form a no-space NSIS install path for: $($script:InstallRoot)" }
        $installArgumentPath = $shortPathBuffer.ToString()
    }
    $installerArguments = "/S /D=$installArgumentPath"
    Write-Event -Event "installer_start" -Data @{ install_directory = $script:InstallRoot; argument_shape = "/S /D=<unquoted path>" }
    $installerProcess = Start-Process -FilePath $resolvedInstaller -ArgumentList $installerArguments -PassThru -Wait
    Write-Event -Event "installer_exit" -Data @{ exit_code = $installerProcess.ExitCode; requested_directory = $script:InstallRoot }
    if ($installerProcess.ExitCode -ne 0) { throw "NSIS installer returned exit code $($installerProcess.ExitCode)." }
    $appCandidates = @(
        (Join-Path $script:InstallRoot "CyberSentinel.exe"),
        (Join-Path $script:InstallRoot "CyberSentinel\CyberSentinel.exe")
    )
    $script:AppExe = $appCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $script:AppExe) {
        $discovered = @($possibleInstallRoots | ForEach-Object {
            if (Test-Path -LiteralPath $_ -PathType Container) {
                Get-ChildItem -LiteralPath $_ -Filter "CyberSentinel.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            }
        } | Where-Object { $_ })
        $script:AppExe = $discovered | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $script:AppExe) {
        $inventory = @($possibleInstallRoots | ForEach-Object {
            if (Test-Path -LiteralPath $_ -PathType Container) {
                [ordered]@{ root = $_; entries = @(Get-ChildItem -LiteralPath $_ -Force -ErrorAction SilentlyContinue | Select-Object -First 20 -ExpandProperty Name) }
            } else { [ordered]@{ root = $_; missing = $true } }
        })
        $uninstallKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $uninstallEntries = @($uninstallKeys | ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue }
        | Where-Object { $_.DisplayName -like "*CyberSentinel*" }
        | Select-Object DisplayName, InstallLocation, DisplayVersion)
        Write-Event -Event "installer_path_diagnostic" -Data @{ requested_directory = $script:InstallRoot; candidate_roots = $inventory; uninstall_registry = $uninstallEntries }
        throw "Installer exited successfully but installed CyberSentinel.exe was not found in requested or standard install paths."
    }
    $actualInstallRoot = Split-Path -Parent $script:AppExe
    Add-Check -Name "Fresh install" -Status "PASS" -Details "Installer exit code 0; installed executable found at $script:AppExe. Requested target honored=$($actualInstallRoot -eq $script:InstallRoot)."
    $script:InstallRoot = $actualInstallRoot

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $script:Port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    $script:ProjectName = "Windows Acceptance $([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))"
    $random = [byte[]]::new(32)
    $randomGenerator = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $randomGenerator.GetBytes($random)
    $randomGenerator.Dispose()
    $script:Password = "CSWinAccept" + [BitConverter]::ToString($random).Replace("-", "")
    [Array]::Clear($random, 0, $random.Length)

    Start-InstalledApp
    $initial = Connect-AppUi
    Start-Sleep -Seconds 2
    $script:AppProcess.Refresh()
    $windowHandle = $script:AppProcess.MainWindowHandle
    $windowVisible = $windowHandle -ne [IntPtr]::Zero -and [CyberSentinelAcceptanceNative]::IsWindowVisible($windowHandle)
    $interactiveDesktop = [Environment]::UserInteractive -and $script:AppProcess.SessionId -gt 0 -and $windowVisible
    Add-Check -Name "Windows interactive GUI session" -Status $(if ($interactiveDesktop) { "PASS" } else { "UNAVAILABLE" }) -Details "UserInteractive=$([Environment]::UserInteractive); SessionId=$($script:AppProcess.SessionId); MainWindowHandle=$windowHandle; IsWindowVisible=$windowVisible."
    Write-Event -Event "window_state" -Data @{ process_id = $script:AppProcess.Id; session_id = $script:AppProcess.SessionId; handle = [string]$windowHandle; visible = [bool]$windowVisible; user_interactive = [Environment]::UserInteractive }
    $runtimeOk = $initial.runtimeText -match '●' -and $initial.runtimeText -notmatch 'تعذر|غير جاهز'
    Add-Check -Name "Installed application launch and local health" -Status $(if ($runtimeOk) { "PASS" } else { "FAIL" }) -Details "Window title=$($initial.title); runtime banner=$($initial.runtimeText)."
    if (-not $runtimeOk) { throw "Installed application UI did not report a healthy local backend." }

    $firstRun = Wait-ForUi -TimeoutSeconds 90 -Description "First Run overlay, hardware details and model catalog" -Condition {
        param($s) $s.firstRunVisible -and $s.setupCardCount -gt 0 -and $s.hardwareText -and $s.hardwareText -notmatch 'جارٍ فحص'
    }
    $qwenFirstRun = @($firstRun.modelCards | Where-Object { ($_.title + " " + $_.modelId + " " + $_.description) -match 'Qwen3.?4B|qwen3-4b' })
    if ($qwenFirstRun.Count -eq 0) {
        $script:QwenCatalogVisible = $false
        throw "First Run opened, but the Qwen3 4B model card was not visible in the UI."
    }
    $script:QwenCatalogVisible = $true
    Add-Check -Name "First Run and hardware detection" -Status "PASS" -Details "First Run overlay is visible; hardware text: $($firstRun.hardwareText)"
    Add-Check -Name "Qwen3 4B catalog visible" -Status "PASS" -Details "Qwen3 4B is displayed in the First Run model catalog; no download/install button was activated."
    $firstScreenshot = Save-UiScreenshot -FileName "01-first-run-hardware-model-catalog.png"
    Write-Event -Event "first_run_snapshot" -Data @{ screenshot = [System.IO.Path]::GetFileName($firstScreenshot); runtime = $firstRun.runtimeText; hardware = $firstRun.hardwareText; model_cards = $firstRun.modelCards }

    $external = @($firstRun.externalOrigins)
    if ($external.Count -eq 0) {
        Add-Check -Name "No external model/provider requests" -Status "PASS" -Details "Renderer resource URLs observed so far are loopback-only; no model download or external provider call was triggered."
    } else {
        Add-Check -Name "No external model/provider requests" -Status "FAIL" -Details "External renderer origins were observed: $($external -join ', ')"
        throw "Unexpected external renderer origin observed; acceptance stopped."
    }

    $passwordJson = ConvertTo-Json -InputObject $script:Password -Compress
    $ownerSetupExpression = "(() => { const p = $passwordJson; const a = document.querySelector('#ownerSetupPassword'); const b = document.querySelector('#ownerSetupConfirm'); const f = document.querySelector('#ownerSetupForm'); if (!a || !b || !f) return JSON.stringify({formReady:false}); a.value = p; b.value = p; a.dispatchEvent(new Event('input',{bubbles:true})); b.dispatchEvent(new Event('input',{bubbles:true})); const d = {formReady:true,passwordLength:a.value.length,confirmationMatches:a.value === b.value,formValid:f.checkValidity()}; f.requestSubmit(); return JSON.stringify(d); })()"
    $ownerFormDiagnostics = [string](Invoke-CdpEvaluation -Expression $ownerSetupExpression) | ConvertFrom-Json
    Write-Event -Event "owner_form_pre_submit" -Data @{ password_length = $ownerFormDiagnostics.passwordLength; confirmation_matches = $ownerFormDiagnostics.confirmationMatches; form_valid = $ownerFormDiagnostics.formValid }
    if (-not $ownerFormDiagnostics.formReady -or -not $ownerFormDiagnostics.confirmationMatches -or -not $ownerFormDiagnostics.formValid) { throw "First Run owner form was unavailable or invalid before submission." }
    $script:CanonicalUsername = [string]$firstRun.ownerUsername
    if ([string]::IsNullOrWhiteSpace($script:CanonicalUsername) -or $firstRun.loginUsername -ne $script:CanonicalUsername) {
        throw "The visible canonical Owner username and login field do not match: visible='$($firstRun.ownerUsername)' login='$($firstRun.loginUsername)'."
    }
    Write-Event -Event "canonical_owner_username_verified" -Data @{ username = $script:CanonicalUsername }
    $ownerReady = Wait-ForUi -TimeoutSeconds 60 -Description "local Owner creation from the First Run form" -Condition {
        param($s) (-not $s.firstRunVisible) -and $s.authText -like "*$($script:CanonicalUsername)*"
    }
    Add-Check -Name "First Run Owner setup and canonical login" -Status "PASS" -Details "Owner '$($script:CanonicalUsername)' was created and authenticated through the visible First Run form; credentials are temporary and are not written to logs."

    $projectJson = ConvertTo-Json -InputObject $script:ProjectName -Compress
    $createProjectExpression = "(() => { const n = document.querySelector('#newProjectToggle'); if (!n) return false; n.click(); const name = document.querySelector('#projectName'); if (!name) return false; name.value = $projectJson; name.dispatchEvent(new Event('input',{bubbles:true})); const form = document.querySelector('#projectForm'); form.requestSubmit(); return true; })()"
    if (-not (Invoke-CdpEvaluation -Expression $createProjectExpression)) { throw "Project creation form could not be reached through the UI." }
    $projectReady = Wait-ForUi -TimeoutSeconds 60 -Description "project creation and persistence marker" -Condition {
        param($s) $s.projectText -like "*$($script:ProjectName)*"
    }
    Add-Check -Name "Local persistence marker" -Status "PASS" -Details "A managed project was created using the application UI: $script:ProjectName"

    $settingsExpression = "(() => { const b = document.querySelector('#settingsLink'); if (!b) return false; b.click(); return true; })()"
    if (-not (Invoke-CdpEvaluation -Expression $settingsExpression)) { throw "Model Manager navigation control is missing." }
    $manager = Wait-ForUi -TimeoutSeconds 60 -Description "Model Manager page and model cards" -Condition {
        param($s) $s.settingsVisible -and $s.managerCardCount -gt 0
    }
    $qwenManager = @($manager.modelCards | Where-Object { ($_.title + " " + $_.modelId + " " + $_.description) -match 'Qwen3.?4B|qwen3-4b' })
    if ($qwenManager.Count -eq 0) { throw "Qwen3 4B is not visible in Model Manager." }
    $script:ModelFingerprint = Get-ModelFingerprint -Snapshot $manager
    Add-Check -Name "Model Manager UI" -Status "PASS" -Details "Settings opened through the app; $($manager.managerCardCount) catalog cards rendered."
    Add-Check -Name "Qwen3 4B model state" -Status "PASS" -Details "Model card visible; action='$($qwenManager[0].action)', button='$($qwenManager[0].buttonText)'. Download/activation was intentionally not started because it would contact an external model host."
    Add-Check -Name "Qwen3 4B download/activation" -Status "NOT_RUN" -Details "The app exposes download as the selection action; it was not activated because the request forbids calls to external model hosts."
    $managerScreenshot = Save-UiScreenshot -FileName "02-model-manager-qwen3-4b.png"
    Write-Event -Event "model_manager_snapshot" -Data @{ screenshot = [System.IO.Path]::GetFileName($managerScreenshot); cards = $manager.modelCards; external_origins = $manager.externalOrigins }

    Close-InstalledApp
    if ($script:AppProcess -and -not $script:AppProcess.HasExited) { throw "CyberSentinel did not close after WM_CLOSE." }
    Add-Check -Name "Close application" -Status "PASS" -Details "Installed application process exited after a normal window-close request."
    Write-Event -Event "app_closed" -Data @{ process_id = $script:AppProcess.Id }

    Start-InstalledApp
    $reopened = Connect-AppUi
    $persisted = Wait-ForUi -TimeoutSeconds 90 -Description "First Run remaining completed after reopen" -Condition {
        param($s) (-not $s.firstRunVisible) -and $s.runtimeText -match '●' -and $s.ownerUsername -eq $script:CanonicalUsername -and $s.loginUsername -eq $script:CanonicalUsername
    }
    if ($persisted.authText -notlike "*$($script:CanonicalUsername)*") {
        if ($persisted.loginUsername -ne $script:CanonicalUsername) {
            throw "The reopened login field does not contain the canonical Owner username."
        }
        $usernameJson = ConvertTo-Json -InputObject $script:CanonicalUsername -Compress
        $loginExpression = "(() => { const u = document.querySelector('#loginUsername'); const p = document.querySelector('#loginPassword'); const f = document.querySelector('#loginForm'); if (!u || !p || !f) return false; u.value = $usernameJson; p.value = $passwordJson; u.dispatchEvent(new Event('input',{bubbles:true})); p.dispatchEvent(new Event('input',{bubbles:true})); f.requestSubmit(); return true; })()"
        if (-not (Invoke-CdpEvaluation -Expression $loginExpression)) { throw "Reopened app login form was unavailable." }
        $persisted = Wait-ForUi -TimeoutSeconds 45 -Description "Owner re-login after restart" -Condition {
            param($s) $s.authText -like "*$($script:CanonicalUsername)*"
        }
    }
    if ($persisted.projectText -notlike "*$($script:ProjectName)*") {
        $persisted = Wait-ForUi -TimeoutSeconds 45 -Description "saved project visible after restart" -Condition {
            param($s) $s.projectText -like "*$($script:ProjectName)*"
        }
    }
    if ($persisted.projectText -notlike "*$($script:ProjectName)*") { throw "Project created before close did not persist after reopening." }
    Add-Check -Name "Close/reopen and local persistence" -Status "PASS" -Details "First Run remained completed, Owner login succeeded, and project '$script:ProjectName' was visible after relaunch."

    if (-not $persisted.settingsVisible) {
        [void](Invoke-CdpEvaluation -Expression $settingsExpression)
        $persisted = Wait-ForUi -TimeoutSeconds 45 -Description "Model Manager after restart" -Condition {
            param($s) $s.settingsVisible -and $s.managerCardCount -gt 0
        }
    }
    $reopenedQwen = @($persisted.modelCards | Where-Object { ($_.title + " " + $_.modelId + " " + $_.description) -match 'Qwen3.?4B|qwen3-4b' })
    if ($reopenedQwen.Count -eq 0) { throw "Qwen3 4B disappeared from Model Manager after restart." }
    $persistedFingerprint = Get-ModelFingerprint -Snapshot $persisted
    $modelStateStable = $persistedFingerprint -eq $script:ModelFingerprint
    Add-Check -Name "Model Manager state persistence" -Status $(if ($modelStateStable) { "PASS" } else { "FAIL" }) -Details "Before/after card state fingerprints match=$modelStateStable; Qwen3 4B remains in the catalog."
    if (-not $modelStateStable) { throw "Model Manager card state changed unexpectedly across restart." }
    $reopenScreenshot = Save-UiScreenshot -FileName "03-reopened-persisted-state.png"
    Write-Event -Event "reopened_snapshot" -Data @{ screenshot = [System.IO.Path]::GetFileName($reopenScreenshot); auth = $persisted.authText; project = $persisted.projectText; cards = $persisted.modelCards }

    $finalExternal = @($persisted.externalOrigins)
    if ($finalExternal.Count -gt 0) { throw "Unexpected external origins after restart: $($finalExternal -join ', ')" }
    if (-not $interactiveDesktop) {
        Add-Check -Name "Windows interactive acceptance gate" -Status "UNAVAILABLE" -Details "App launch/renderer checks ran, but the runner did not expose an interactive visible Windows desktop session."
    } else {
        Add-Check -Name "Windows interactive acceptance gate" -Status "PASS" -Details "Installed Electron window was visible in a non-zero Windows session; UI interaction and screenshots came from the installed build."
    }

    $profileFiles = @(Get-ChildItem -LiteralPath $script:ProfileRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ path = $_.FullName.Substring($script:ProfileRoot.Length).TrimStart('\'); size_bytes = $_.Length } })
    $profileFiles | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:Evidence "persisted-profile-files.json") -Encoding utf8
    Add-Check -Name "Real inference / Mission / GOAL_COMPLETED" -Status "NOT_RUN" -Details "No model was downloaded and no external model host was contacted; Windows inference/Mission execution was not part of this isolated, no-external-request run."
}
catch {
    $detail = $_.Exception.Message
    Add-Check -Name "Acceptance execution" -Status "FAIL" -Details $detail
    Write-Event -Event "acceptance_error" -Data @{ message = $detail; category = $_.FullyQualifiedErrorId }
    Write-Error $detail
}
finally {
    Close-InstalledApp
    $result = [ordered]@{
        product = "CyberSentinel Desktop"
        expected_source_commit = $ExpectedSourceCommit
        expected_installer_sha256 = $ExpectedSha256.ToLowerInvariant()
        checks = @($script:Checks)
        evidence_directory = $script:Evidence
        scope = [ordered]@{
            installed_application_only = $true
            no_product_source_modified = $true
            no_model_download_or_external_inference = $true
            no_smart_screen_bypass_or_signing = $true
            no_tag_or_release = $true
        }
        finished_utc = [DateTime]::UtcNow.ToString("o")
    }
    if ($script:Evidence) {
        $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $script:Evidence "acceptance-result.json") -Encoding utf8
    }
    if ($script:TranscriptStarted) { Stop-Transcript | Out-Null }
}

$failed = @($script:Checks | Where-Object { $_.status -eq "FAIL" })
$unavailable = @($script:Checks | Where-Object { $_.status -eq "UNAVAILABLE" })
Write-Output "EVIDENCE_DIRECTORY=$script:Evidence"
Write-Output "RESULT_FILE=$(Join-Path $script:Evidence 'acceptance-result.json')"
if ($failed.Count -gt 0) { exit 1 }
if ($unavailable.Count -gt 0) { exit 2 }
exit 0
