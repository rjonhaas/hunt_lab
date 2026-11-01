# Run elevated on the selected lab target BEFORE the exercise.
# Extend the existing lab Sysmon configuration; do not replace it with a minimal one.
param(
    [string]$ConfigPath = 'C:\Windows\Temp\lab-setup\Sysmon\sysmonconfig.xml',
    [string]$SysmonPath = 'C:\Windows\Sysmon64.exe'
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw 'Supply the existing Sysmon configuration path.' }
if (-not (Test-Path -LiteralPath $SysmonPath)) { throw 'Supply the installed Sysmon executable path.' }
[xml]$config = Get-Content -LiteralPath $ConfigPath -Raw
$filter = $config.SelectSingleNode('/Sysmon/EventFiltering')
if (-not $filter) { throw 'Unsupported Sysmon configuration layout.' }
$root = 'C:\WarWagonTraining\'
$existing = $config.SelectNodes('//FileCreate[@onmatch="include"]/TargetFilename') | Where-Object { $_.InnerText -eq $root }
if (-not $existing) {
    $backup = "$ConfigPath.before-war-wagon-$(Get-Date -Format yyyyMMddHHmmss).xml"
    Copy-Item -LiteralPath $ConfigPath -Destination $backup -ErrorAction Stop
    $group = $config.CreateElement('RuleGroup')
    $group.SetAttribute('name', 'WarWagonTraining')
    $group.SetAttribute('groupRelation', 'or')
    $create = $config.CreateElement('FileCreate')
    $create.SetAttribute('onmatch', 'include')
    $target = $config.CreateElement('TargetFilename')
    $target.SetAttribute('condition', 'begin with')
    $target.InnerText = $root
    [void]$create.AppendChild($target)
    [void]$group.AppendChild($create)
    [void]$filter.AppendChild($group)
    $config.Save($ConfigPath)
}
# Redirect native stderr so WinRM does not treat Sysmon's informational banner as failure.
$out = Join-Path $env:TEMP 'ww-sysmon-config-out.txt'
$err = Join-Path $env:TEMP 'ww-sysmon-config-err.txt'
$process = Start-Process -FilePath $SysmonPath -ArgumentList @('-c', ('"' + $ConfigPath + '"')) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
if ($process.ExitCode -ne 0) { throw "Sysmon rejected configuration; inspect $err and restore the timestamped backup." }
Write-Output 'Sysmon accepted the exercise-directory file-create rule; existing rules preserved.'
