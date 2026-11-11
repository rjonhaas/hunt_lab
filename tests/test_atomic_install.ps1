# Run with PowerShell 5.1 or later; no Pester or VM required.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/install_atomic_red_team.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "Installer parse failed: $errors" }
# Load helpers only, never execute the installation during a unit test.
$ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false) |
    ForEach-Object { Invoke-Expression $_.Extent.Text }
function Assert($condition, $message) { if (-not $condition) { throw $message } }
function Start-Sleep { param($Seconds) }
$script:attempts = 0
Invoke-InstallRetry 'Transient download' {
    $script:attempts++
    if ($script:attempts -lt 3) { throw 'temporary gallery outage' }
}
Assert ($script:attempts -eq 3) 'Transient dependency failure did not recover.'
$script:attempts = 0; $failed = $false
try { Invoke-InstallRetry 'Persistent download' { $script:attempts++; throw 'gallery unavailable' } }
catch { $failed = $_.Exception.Message -eq 'gallery unavailable' }
Assert ($failed -and $script:attempts -eq 3) 'Persistent error was swallowed or retries were unbounded.'
function Test-Path { param($Path, $PathType) return ($Path -in $script:files) }
$script:files = @('C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1')
Assert (-not (Test-AtomicInstallation)) 'Partial install incorrectly accepted as complete.'
$script:files += 'C:\AtomicRedTeam\atomics\T1059.001\T1059.001.yaml'
Assert (Test-AtomicInstallation) 'Complete installation not recognized.'
$script:moduleInstalls = 0; $script:repositoryRegistered = $false
function Get-Module { param([switch]$ListAvailable, $Name) if ($script:moduleInstalls -ge 3) { [pscustomobject]@{ Name = 'powershell-yaml' } } }
function Get-PSRepository { param($Name, $ErrorAction) if ($script:repositoryRegistered) { [pscustomobject]@{ Name = 'PSGallery' } } }
function Register-PSRepository { param([switch]$Default, $ErrorAction) $script:repositoryRegistered = $true }
function Get-PackageProvider { param($Name, [switch]$ListAvailable, $ErrorAction) [pscustomobject]@{ Version = [version]'2.8.5.208' } }
function Install-Module {
    param($Name, $Repository, $Scope, [switch]$Force, $ErrorAction)
    Assert ($Repository -eq 'PSGallery' -and $Scope -eq 'AllUsers') 'Dependency installed in wrong scope/repository.'
    $script:moduleInstalls++
    if ($script:moduleInstalls -lt 3) { throw 'No match found during temporary gallery failure' }
}
Install-YamlDependency
Assert ($script:repositoryRegistered -and $script:moduleInstalls -eq 3) 'Dependency bootstrap did not recover from missing repository/transient gallery failure.'
Install-YamlDependency
Assert ($script:moduleInstalls -eq 3) 'Healthy dependency was installed again.'
Write-Host 'PASS: bounded recovery, failure propagation, partial-install detection, dependency bootstrap and reuse.'
