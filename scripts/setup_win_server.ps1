# setup_win_server.ps1
# Stage 1 of 2: Configure the private network adapter and join win-server to lab.local.
# Vagrant reboots the VM after this script exits (reboot: true in Vagrantfile).
# Stage 2 continues in setup_win_server_tools.ps1.
#
# Reads:
#   C:\vagrant\domain-info.txt              — written by setup_dc_post_reboot.ps1
#   C:\vagrant\fleet-enrollment-token.txt   — written by docker/setup.sh

param()

$LogFile = "C:\Windows\Temp\setup-win-server-stage1.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[win-server] $Message"
}

$PrivateIP      = "192.168.56.51"
$DCIP           = "192.168.56.50"
$DomainInfoFile = "C:\vagrant\domain-info.txt"
$TokenFile      = "C:\vagrant\fleet-enrollment-token.txt"

# ── Guards ────────────────────────────────────────────────────────────────────
if (-not (Test-Path $DomainInfoFile)) {
    Write-Error "domain-info.txt not found. Run 'vagrant up win-dc' first."
    exit 1
}
if (-not (Test-Path $TokenFile)) {
    Write-Error "fleet-enrollment-token.txt not found. Run 'bash docker/setup.sh' first."
    exit 1
}

# Parse domain-info.txt (KEY=VALUE format)
$domainInfo = @{}
Get-Content $DomainInfoFile | ForEach-Object {
    if ($_ -match "^(\w[\w-]*)=(.+)$") { $domainInfo[$Matches[1]] = $Matches[2].Trim() }
}
$DomainName = $domainInfo["DOMAIN"]
$JoinUser   = "$($domainInfo['NETBIOS'])\$($domainInfo['JOIN_USER'])"
$JoinPass   = ConvertTo-SecureString $domainInfo["JOIN_PASS"] -AsPlainText -Force
$JoinCred   = New-Object System.Management.Automation.PSCredential($JoinUser, $JoinPass)

# ── 1. Disable Windows Defender (lab only) ────────────────────────────────────
Write-Log "Disabling Windows Defender..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableIOAVProtection    $true
    Set-MpPreference -DisableScriptScanning    $true
    Add-MpPreference -ExclusionPath "C:\"
    Write-Log "Defender disabled and C:\ excluded."
} catch {
    Write-Log "WARNING: Could not fully disable Defender: $_"
}

# ── 2. Disable sleep/hibernate ────────────────────────────────────────────────
Write-Log "Disabling sleep and hibernate..."
powercfg /change standby-timeout-ac  0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null
Write-Log "Sleep disabled."

# ── 3. Configure static IP on private adapter ─────────────────────────────────
# DNS must point at the DC so domain name resolution works during the join.
Write-Log "Configuring private network adapter ($PrivateIP/24, DNS -> $DCIP)..."
$apipa = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "169.254.*" }
if ($apipa) {
    $idx = $apipa[0].InterfaceIndex
    Remove-NetIPAddress -InterfaceIndex $idx -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute     -InterfaceIndex $idx -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress    -InterfaceIndex $idx -IPAddress $PrivateIP -PrefixLength 24 | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $DCIP
    Write-Log "Adapter configured: $PrivateIP/24, DNS -> $DCIP"
} else {
    Write-Log "WARNING: No APIPA adapter found - adapter may already be configured."
}

# ── 4. Join the domain ────────────────────────────────────────────────────────
Write-Log "Checking domain membership..."
$currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($currentDomain -ieq $DomainName) {
    Write-Log "Already a member of $DomainName - skipping domain join."
} else {
    Write-Log "Joining domain '$DomainName' as $JoinUser ..."
    # Flush DNS and retry — DNS client may not pick up the new server address instantly
    ipconfig /flushdns | Out-Null
    Start-Sleep -Seconds 5
    $maxAttempts = 4
    $joined = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Computer -DomainName $DomainName -Credential $JoinCred -Force -ErrorAction Stop
            Write-Log "Domain join successful (attempt $attempt)."
            $joined = $true
            break
        } catch {
            Write-Log "Domain join attempt $attempt/$maxAttempts failed: $_"
            if ($attempt -lt $maxAttempts) {
                Write-Log "Retrying in 20s..."
                Start-Sleep -Seconds 20
                ipconfig /flushdns | Out-Null
            }
        }
    }
    if (-not $joined) {
        Write-Error "Domain join failed after $maxAttempts attempts. Check DC connectivity and DNS."
        exit 1
    }
}

Write-Log "Stage 1 complete. Vagrant rebooting - Stage 2 continues in setup_win_server_tools.ps1."
Stop-Transcript
exit 0
