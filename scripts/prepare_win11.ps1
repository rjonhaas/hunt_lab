# The Service Control Manager reads this value at boot. Vagrant reboots the
# guest after this provisioner, before installing Elastic Agent.
$ErrorActionPreference = 'Stop'
$control = 'HKLM:\SYSTEM\CurrentControlSet\Control'
$current = Get-ItemProperty -Path $control -Name ServicesPipeTimeout -ErrorAction SilentlyContinue
if (-not $current -or $current.ServicesPipeTimeout -lt 120000) {
    New-ItemProperty -Path $control -Name ServicesPipeTimeout -PropertyType DWord -Value 120000 -Force | Out-Null
}
Write-Host '[win-victim] Allowing at least 120 seconds for services to start; guest reboot follows.'
