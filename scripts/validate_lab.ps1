# Run the shared read-only readiness check using Python in the services VM.
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    & vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'
    $code = $LASTEXITCODE
} finally { Pop-Location }
exit $code
