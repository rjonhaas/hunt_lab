# Fail provisioning if the Windows host is missing required lab components.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    $computer = Get-CimInstance Win32_ComputerSystem
    if (-not $computer.PartOfDomain -or $computer.Domain -ine 'lab.local') {
        throw 'Host is not joined to lab.local. Check the domain-join log and reboot.'
    }
    foreach ($name in @('Sysmon64', 'Elastic Agent')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            throw "Required service '$name' is not running."
        }
        Write-Host "[verify] $name is running."
    }
    [xml]$sysmon = Get-Content 'C:\Windows\Temp\lab-setup\Sysmon\sysmonconfig.xml' -Raw
    $rule = $sysmon.SelectNodes('//FileCreate[@onmatch="include"]/TargetFilename') |
        Where-Object { $_.InnerText -eq 'C:\WarWagonTraining\' -and $_.GetAttribute('condition') -eq 'begin with' }
    if (-not $rule) { throw 'Workshop file-creation logging rule is missing.' }
    $task = Get-ScheduledTask -TaskName 'WindowsSecurityUpdate' -ErrorAction Stop
    if ($task.State -ne 'Running' -or -not (Get-Process svhost -ErrorAction SilentlyContinue)) {
        throw 'Sandcat is not running. Check deploy-caldera-agent.log.'
    }
    Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -ErrorAction Stop
    Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null
    if (-not (Get-ChildItem 'C:\AtomicRedTeam\atomics' -Directory -Filter 'T*' -ErrorAction Stop)) {
        throw 'Atomic Red Team technique definitions are missing.'
    }
    Write-Host '[verify] Domain, Windows services, Sandcat and Atomic Red Team checks passed.'
    exit 0
} catch {
    Write-Host "[verify] FAILED: $($_.Exception.Message)"
    exit 1
}
