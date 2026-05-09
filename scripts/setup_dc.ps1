# setup_dc.ps1
# Stage 1 of 2: Install AD DS + DNS roles and promote win-dc to a domain controller.
# Vagrant reboots the VM after this script exits (reboot: true in Vagrantfile).
# Stage 2 continues in setup_dc_post_reboot.ps1.
#
# Domain:   lab.local  (NetBIOS: LAB)
# DC IP:    192.168.56.50
# DC host:  win-dc

param()

$LogFile = "C:\Windows\Temp\setup-dc-stage1.log"
Start-Transcript -Path $LogFile -Force

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[win-dc] $Message"
}

# Idempotency: if this host is already a DC, Stage 1 has nothing to do.
# Re-running Install-ADDSForest fails, and Vagrant's reboot below would be wasted.
if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
    Write-Host "[win-dc] Already promoted to DC - skipping Stage 1 (idempotent re-run)."
    Stop-Transcript
    exit 0
}

$DomainName   = "lab.local"
$NetBIOSName  = "LAB"
$SafeModePass = ConvertTo-SecureString "Vagrant123!" -AsPlainText -Force
$PrivateIP    = "192.168.56.50"

# 1. Disable Windows Defender (lab only - never do this in production)
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

# 2. Disable sleep/hibernate (prevent auto-suspend in headless lab)
Write-Log "Disabling sleep and hibernate..."
powercfg /change standby-timeout-ac  0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null
Write-Log "Sleep disabled."

# 3. Configure static IP on private network adapter.
# VMware does not auto-configure the host-only adapter on Windows Server.
# DNS must point to self (127.0.0.1) so AD promotion can register DNS records.
Write-Log "Configuring private network adapter ($PrivateIP/24, DNS -> 127.0.0.1)..."
$apipa = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "169.254.*" }
if ($apipa) {
    $idx = $apipa[0].InterfaceIndex
    Remove-NetIPAddress -InterfaceIndex $idx -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute     -InterfaceIndex $idx -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress    -InterfaceIndex $idx -IPAddress $PrivateIP -PrefixLength 24 | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses "127.0.0.1"
    Write-Log "Adapter configured: $PrivateIP/24, DNS -> 127.0.0.1"
} else {
    Write-Log "WARNING: No APIPA adapter found - adapter may already be configured."
}

# 4. Install AD DS and DNS Windows roles
Write-Log "Installing AD-Domain-Services and DNS roles..."
$result = Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools
Write-Log "Feature install: Success=$($result.Success), RestartNeeded=$($result.RestartNeeded)"

# 5. Configure WinRM basic auth (persists through DC promotion reboot).
# After DC promotion, NTLM negotiate over port-forwarding fails to authenticate
# 'vagrant' as the new domain account 'LAB\vagrant'. Basic auth resolves it correctly.
Write-Log "Enabling WinRM basic auth for post-promotion Vagrant reconnect..."
cmd /c 'winrm set winrm/config/service/auth @{Basic="true"}' | Out-Null
cmd /c 'winrm set winrm/config/service @{AllowUnencrypted="true"}' | Out-Null
Write-Log "WinRM basic auth enabled."

# 6. Promote to domain controller.
# -NoRebootOnCompletion:$true suppresses the automatic reboot so Vagrant can
# reboot at the right time (via reboot: true in the Vagrantfile).
Write-Log "Promoting win-dc to DC for domain '$DomainName'..."
Import-Module ADDSDeployment

$promoteResult = Install-ADDSForest `
    -DomainName                    $DomainName `
    -DomainNetbiosName             $NetBIOSName `
    -DomainMode                    "WinThreshold" `
    -ForestMode                    "WinThreshold" `
    -DatabasePath                  "C:\Windows\NTDS" `
    -LogPath                       "C:\Windows\NTDS" `
    -SysvolPath                    "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword $SafeModePass `
    -InstallDns:$true `
    -NoRebootOnCompletion:$true `
    -Force:$true

Write-Log "Promotion status: $($promoteResult.Status)"
Write-Log "Stage 1 complete. Vagrant will now reboot win-dc. Stage 2 continues in setup_dc_post_reboot.ps1."

Stop-Transcript
exit 0
