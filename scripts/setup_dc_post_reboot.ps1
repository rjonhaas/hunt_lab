# setup_dc_post_reboot.ps1
# Stage 2 of 2: Post-reboot DC configuration.
# Runs after Vagrant reboots win-dc following AD DS promotion.
#
# Tasks:
#   - Wait for Active Directory Web Services to come online
#   - Create domain Organizational Units and lab users
#   - Write C:\vagrant\domain-info.txt for win-server and win11-victim to consume
#   - Install Sysmon (SwiftOnSecurity config)
#   - Install and enroll Elastic Agent with Fleet

param()

$LogFile = "C:\Windows\Temp\setup-dc-stage2.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[win-dc] $Message"
}

$DomainName     = "lab.local"
$NetBIOSName    = "LAB"
$PrivateIP      = "192.168.56.50"
$FleetServer    = "http://192.168.56.10:8220"
$CalderaServer  = "http://192.168.56.10:8888"
$TokenFile      = "C:\vagrant\fleet-enrollment-token.txt"
$DomainInfoFile = "C:\vagrant\domain-info.txt"

$TempDir   = "C:\Windows\Temp\lab-setup"
$SysmonDir = "$TempDir\Sysmon"
$AgentDir  = "$TempDir\ElasticAgent"
New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
New-Item -ItemType Directory -Force -Path $AgentDir  | Out-Null

# ── 1. Ensure the Fleet enrollment token exists ───────────────────────────────
if (-not (Test-Path $TokenFile)) {
    Write-Error "fleet-enrollment-token.txt not found. Run 'bash docker/setup.sh' first."
    exit 1
}

# ── 2. Wait for Active Directory Web Services ─────────────────────────────────
Write-Log "Waiting for Active Directory to become available..."
$maxWait = 180
$waited  = 0
while ($waited -lt $maxWait) {
    try {
        $null = Get-ADDomain -ErrorAction Stop
        Write-Log "Active Directory is ready."
        break
    } catch {
        Write-Log "  AD not ready yet (${waited}s elapsed), retrying in 15s..."
        Start-Sleep -Seconds 15
        $waited += 15
    }
}
if ($waited -ge $maxWait) {
    Write-Error "Active Directory did not become available after ${maxWait}s. Check dcpromo logs."
    exit 1
}

# ── 3. Create Organizational Units ────────────────────────────────────────────
Write-Log "Creating Organizational Units..."
$domainDN = (Get-ADDomain).DistinguishedName   # e.g. DC=lab,DC=local
foreach ($ou in @("Workstations", "Servers", "Employees", "ServiceAccounts", "IT")) {
    $existingObj = Get-ADObject -Filter { Name -eq $ou } -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue
    if (-not $existingObj) {
        New-ADOrganizationalUnit -Name $ou -Path $domainDN
        Write-Log "  Created OU: $ou"
    } else {
        Write-Log "  '$ou' already exists (type: $($existingObj.ObjectClass)) - skipping"
    }
}

# ── 4. Create domain users ────────────────────────────────────────────────────
Write-Log "Creating domain users..."
$DefaultPass = ConvertTo-SecureString "Lab!Password1" -AsPlainText -Force
$users = @(
    @{ Name = "John Smith";    SamAccountName = "jsmith";     OU = "Employees";       Description = "Help Desk Technician" },
    @{ Name = "Alice Johnson"; SamAccountName = "ajohnson";   OU = "IT";              Description = "Systems Administrator" },
    @{ Name = "Bob Williams";  SamAccountName = "bwilliams";  OU = "Employees";       Description = "Finance Analyst" },
    @{ Name = "Carol Davis";   SamAccountName = "cdavis";     OU = "Employees";       Description = "HR Manager" },
    @{ Name = "svc-backup";    SamAccountName = "svc-backup"; OU = "ServiceAccounts"; Description = "Backup Service Account" },
    @{ Name = "svc-deploy";    SamAccountName = "svc-deploy"; OU = "ServiceAccounts"; Description = "Deployment Service Account" }
)
foreach ($u in $users) {
    $ouPath = "OU=$($u.OU),$domainDN"
    $sam = $u.SamAccountName
    if (-not (Get-ADUser -Filter { SamAccountName -eq $sam } -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name              $u.Name `
            -SamAccountName    $u.SamAccountName `
            -UserPrincipalName "$($u.SamAccountName)@$DomainName" `
            -Path              $ouPath `
            -Description       $u.Description `
            -AccountPassword   $DefaultPass `
            -PasswordNeverExpires $true `
            -Enabled           $true
        Write-Log "  Created: $($u.SamAccountName)"
    } else {
        Write-Log "  Already exists: $($u.SamAccountName)  (skipping)"
    }
}
# Give the IT admin Domain Admin rights for realistic attack scenarios
Add-ADGroupMember -Identity "Domain Admins" -Members "ajohnson" -ErrorAction SilentlyContinue
Write-Log "  ajohnson added to Domain Admins."

# ── 5. Write domain-info.txt for member VMs ───────────────────────────────────
Write-Log "Writing domain-info.txt..."
@"
DOMAIN=$DomainName
NETBIOS=$NetBIOSName
DC_IP=$PrivateIP
JOIN_USER=vagrant
JOIN_PASS=vagrant
"@ | Set-Content -Path $DomainInfoFile -Encoding UTF8
Write-Log "domain-info.txt written to C:\vagrant\"

# ── 6. Install Sysmon ─────────────────────────────────────────────────────────
Write-Log "Downloading Sysmon..."
$SysmonZip    = "$SysmonDir\Sysmon.zip"
$SysmonConfig = "$SysmonDir\sysmonconfig.xml"

& curl.exe -fsSL -o $SysmonZip "https://download.sysinternals.com/files/Sysmon.zip" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Sysmon (exit $LASTEXITCODE)"; exit 1 }

Write-Log "Extracting Sysmon..."
Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force

Write-Log "Downloading SwiftOnSecurity Sysmon config..."
& curl.exe -fsSL -o $SysmonConfig `
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Sysmon config (exit $LASTEXITCODE)"; exit 1 }

Write-Log "Installing Sysmon..."
$SysmonExe = if (Test-Path "$SysmonDir\Sysmon64.exe") { "$SysmonDir\Sysmon64.exe" } else { "$SysmonDir\Sysmon.exe" }
$SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$sysArgs   = if ($SysmonSvc) {
    Write-Log "Sysmon already installed - updating config only..."
    @("-c", $SysmonConfig)
} else {
    @("-accepteula", "-i", $SysmonConfig)
}
# Use Start-Process to redirect I/O at the OS level — prevents WinRM EAP=Stop
# from treating Sysmon's stderr output as a fatal NativeCommandError.
$sysmonOut = "$env:TEMP\sysmon-stdout.tmp"
$sysmonErr = "$env:TEMP\sysmon-stderr.tmp"
$p = Start-Process -FilePath $SysmonExe -ArgumentList $sysArgs `
    -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $sysmonOut `
    -RedirectStandardError  $sysmonErr
if ($p.ExitCode -ne 0) {
    $errText = Get-Content $sysmonErr -ErrorAction SilentlyContinue
    Write-Error "Sysmon install failed (exit $($p.ExitCode)): $errText"
    exit 1
}
Write-Log "Sysmon installed."

# ── 7. Install Elastic Agent ──────────────────────────────────────────────────
Write-Log "Reading Fleet enrollment token..."
$EnrollToken = (Get-Content $TokenFile -Raw).Trim()
if ([string]::IsNullOrEmpty($EnrollToken)) {
    Write-Error "Fleet enrollment token is empty. Check 'docker compose logs bootstrap'."
    exit 1
}
Write-Log "Token found."

Write-Log "Downloading Elastic Agent..."
$AgentVersion = "8.19.14"   # Must match ELASTIC_VERSION in docker/.env
$AgentZip     = "$AgentDir\elastic-agent.zip"
$AgentUrl     = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${AgentVersion}-windows-x86_64.zip"

& curl.exe -fsSL -o $AgentZip $AgentUrl 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to download Elastic Agent (exit $LASTEXITCODE)"; exit 1 }

Write-Log "Extracting Elastic Agent..."
Expand-Archive -Path $AgentZip -DestinationPath $AgentDir -Force

$AgentExtracted = (Get-ChildItem -Path $AgentDir -Directory | Select-Object -First 1).FullName
if (-not $AgentExtracted) { Write-Error "Could not find extracted Elastic Agent directory."; exit 1 }

$ExistingAgent = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if ($ExistingAgent) {
    Write-Log "Elastic Agent already installed - skipping (service: $($ExistingAgent.Status))."
} else {
    Write-Log "Installing and enrolling Elastic Agent..."
    # Use Start-Process (same pattern as Sysmon) to redirect elastic-agent's I/O
    # at OS level — prevents WinRM from terminating on stderr writes.
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
        Write-Error "Elastic Agent install failed (exit $($p.ExitCode)): $errText"
        exit 1
    }
    Write-Log "Elastic Agent installed and enrolled."
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Log ""
Write-Log "============================================================"
Write-Log "  Windows Domain Controller provisioning complete!"
Write-Log "  Domain:         $DomainName  (NetBIOS: $NetBIOSName)"
Write-Log "  DC IP:          $PrivateIP"
Write-Log "  Domain Admins:  LAB\vagrant, LAB\ajohnson"
Write-Log "  User password:  Lab!Password1"
Write-Log "  Safe mode pass: Vagrant123!"
Write-Log "  Sysmon:         running as a service"
Write-Log "  Elastic Agent:  enrolled with Fleet at $FleetServer"
Write-Log "  domain-info:    C:\vagrant\domain-info.txt"
Write-Log "============================================================"

Stop-Transcript
exit 0
