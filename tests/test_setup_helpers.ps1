# Run with Windows PowerShell 5.1; no Pester dependency or VMs required.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$LogDir = Join-Path $env:TEMP ('war-wagon-tests-' + [guid]::NewGuid())
New-Item -ItemType Directory $LogDir | Out-Null
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Write-Log($Msg) { Write-Host $Msg }
function Write-Warn($Msg) { Write-Host $Msg }
try {
    foreach ($path in @('setup.ps1', 'scripts\setup_helpers.ps1')) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $path), [ref]$tokens, [ref]$errors) | Out-Null
        Assert ($errors.Count -eq 0) "Parse errors in $path"
    }
    . (Join-Path $root 'scripts\setup_helpers.ps1')
    $vagrantExe = Join-Path $PSHOME 'powershell.exe'
    $code = Invoke-VagrantProcess -Arguments @('-NoProfile', '-Command', '"Write-Output test-output; exit 7"') -LogName 'exit-code' -TimeoutSeconds 20
    Assert ($code -eq 7) "Native exit code was lost: $code"
    $code = Invoke-VagrantProcess -Arguments @('-NoProfile', '-Command', '"Start-Sleep -Seconds 20"') -LogName 'timeout' -TimeoutSeconds 1
    Assert ($code -eq 124) 'Timeout did not stop the command.'

    $MachineOrder = @('docker-host', 'win-dc', 'win-server', 'win11-victim')
    $From = 'win11-victim'; $StageTimeout = 30
    $script:calls = @(); $script:mode = 'download'
    function Start-Sleep { param($Seconds) }
    function Invoke-VagrantProcess {
        param($Arguments, $LogName, $TimeoutSeconds)
        $script:calls += ($Arguments -join ' ')
        $message = ''
        if ($Arguments[0] -eq 'status') {
            $state = if ($script:mode -eq 'missing') { 'not_created' } else { 'poweroff' }
            Set-Content (Join-Path $LogDir "$LogName.stdout.log") "1,$($Arguments[1]),state,$state"
            Set-Content (Join-Path $LogDir "$LogName.stderr.log") ''
            return 0
        }
        if ($script:mode -eq 'fatal') { $message = 'guest script failed' }
        elseif ($script:calls.Count -eq 1 -and $script:mode -eq 'winrm_raw') { $message = "execution expired (Timeout::Error)`nfrom plugins/communicators/winrm/communicator.rb:109" }
        elseif ($script:mode -eq '503') { $message = 'error while downloading the metadata. URL returned error: 503' }
        elseif ($script:mode -eq '404') { $message = 'error while downloading the metadata. URL returned error: 404' }
        elseif ($script:calls.Count -eq 1 -and $script:mode -eq 'download') { $message = 'An error occurred while downloading the remote file.' }
        elseif ($script:calls.Count -eq 1 -and $script:mode -eq 'winrm') { $message = 'Vagrant timed out while attempting to connect via WinRM.' }
        Set-Content (Join-Path $LogDir "$LogName.stdout.log") $message
        Set-Content (Join-Path $LogDir "$LogName.stderr.log") ''
        if ($message) { return 23 }; return 0
    }
    $script:mode = 'success'
    Invoke-LabMachine 'docker-host'
    Assert ($script:calls.Count -eq 2 -and $script:calls[1] -match '--no-provision') 'Resume did not start prerequisite without provisioning.'
    $script:calls = @(); $script:mode = 'fatal'; $failed = $false
    try { Invoke-LabMachine 'win-dc' } catch { $failed = $true }
    Assert ($failed -and $script:calls.Count -eq 2) 'Prerequisite startup failure was swallowed.'
    $script:calls = @(); $script:mode = 'missing'; $failed = $false
    try { Invoke-LabMachine 'win-dc' } catch { $failed = $_.Exception.Message -match 'Resume: .\\setup.ps1 -From win-dc' }
    Assert ($failed -and $script:calls.Count -eq 1) 'Missing prerequisite was created without provisioning.'
    $script:calls = @(); $script:mode = 'download'
    Invoke-LabMachine 'win11-victim'
    Assert ($script:calls.Count -eq 2) 'Download was not retried.'
    $script:calls = @(); $script:mode = 'winrm'
    Invoke-LabMachine 'win11-victim'
    Assert ($script:calls.Count -eq 3 -and $script:calls[1] -eq 'reload win11-victim') 'WinRM recovery did not reload before retry.'
    Assert ($script:calls[0] -match '--no-destroy-on-error') 'Failed VMs must be preserved.'
    $script:calls = @(); $script:mode = 'winrm_raw'
    Invoke-LabMachine 'win11-victim'
    Assert ($script:calls.Count -eq 3 -and $script:calls[1] -eq 'reload win11-victim') 'Raw WinRM timeout did not recover.'
    $script:calls = @(); $script:mode = 'fatal'; $failed = $false
    try { Invoke-LabMachine 'win11-victim' } catch { $failed = $_.Exception.Message -match 'Resume:' }
    Assert ($failed -and $script:calls.Count -eq 1) 'Guest failure was retried or swallowed.'
    foreach ($status in @('503', '404')) {
        $script:calls = @(); $script:mode = $status; $failed = $false
        try { Invoke-LabMachine 'win11-victim' } catch { $failed = $_.Exception.Message -match 'Resume:' }
        $expected = if ($status -eq '503') { 3 } else { 1 }
        Assert ($failed -and $script:calls.Count -eq $expected) "HTTP $status used the wrong retry policy."
    }
    Write-Host 'PASS: parsing, native exit codes, timeout, resume, download retry, WinRM recovery, fatal errors.'
} finally {
    Remove-Item $LogDir -Recurse -Force
}
