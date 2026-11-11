# Windows host command execution, logging, timeout and retry helpers.
function Invoke-VagrantProcess {
    param([string[]]$Arguments, [string]$LogName, [int]$TimeoutSeconds = 10800)
    $stdout = Join-Path $LogDir "$LogName.stdout.log"
    $stderr = Join-Path $LogDir "$LogName.stderr.log"
    $process = Start-Process -FilePath $vagrantExe -ArgumentList $Arguments -PassThru `
        -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    # Keep the native handle open so Windows PowerShell 5.1 retains ExitCode.
    $null = $process.Handle
    $readers = @()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        foreach ($path in @($stdout, $stderr)) {
            $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
            $readers += [IO.StreamReader]::new($stream)
        }
        while (-not $process.WaitForExit(1000)) {
            foreach ($reader in $readers) {
                $text = $reader.ReadToEnd()
                if ($text) { Write-Host $text -NoNewline }
            }
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                & taskkill.exe /PID $process.Id /T /F | Out-Null
                Write-Host "[setup] Command timed out. Logs: $stdout, $stderr"
                return 124
            }
        }
        $process.WaitForExit()
        foreach ($reader in $readers) {
            $text = $reader.ReadToEnd()
            if ($text) { Write-Host $text -NoNewline }
        }
        return $process.ExitCode
    } finally {
        foreach ($reader in $readers) { $reader.Dispose() }
        $process.Dispose()
    }
}

function Invoke-LabMachine {
    param([string]$Machine)
    if ([array]::IndexOf($MachineOrder, $Machine) -lt [array]::IndexOf($MachineOrder, $From)) {
        Write-Log "Skipping completed machine $Machine (resume from $From)."
        return
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $name = "$Machine-attempt-$attempt"
        $code = Invoke-VagrantProcess -Arguments @('up', $Machine, '--provider', 'vmware_desktop', '--provision', '--no-destroy-on-error') -LogName $name -TimeoutSeconds $StageTimeout
        if ($code -eq 0) { return }
        $text = Get-Content (Join-Path $LogDir "$name.*.log") -Raw
        if ($attempt -lt 3 -and -not ($text -match 'URL returned error: (401|403|404)') -and ($text -match 'error occurred while downloading|error while downloading the metadata|Could not resolve host|Failed to connect|SSL connect error')) {
            Write-Warn "Download interrupted; retrying $Machine in 10 seconds."
            Start-Sleep -Seconds 10
        } elseif ($attempt -lt 3 -and ($text -match 'timed out while attempting to connect via WinRM|WinRM.*connection refused|(?s)Timeout::Error.*plugins/communicators/winrm/')) {
            Write-Warn "Reloading $Machine after a WinRM connection failure."
            $reload = Invoke-VagrantProcess -Arguments @('reload', $Machine) -LogName "$Machine-reload-$attempt" -TimeoutSeconds 900
            if ($reload -ne 0) { throw "Recovery failed. Logs: $LogDir. Resume: .\setup.ps1 -From $Machine" }
        } else {
            throw "$Machine failed (exit $code; 124 means timeout). Logs: $LogDir. Resume: .\setup.ps1 -From $Machine"
        }
    }
}
