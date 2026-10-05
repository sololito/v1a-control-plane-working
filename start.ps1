Write-Host "Starting ODIVORA Home Connectivity Server..." -ForegroundColor Green
Set-Location $PSScriptRoot
if (Test-Path "venv\Scripts\Activate.ps1") {
    & "venv\Scripts\Activate.ps1"
} elseif (Test-Path ".venv\Scripts\Activate.ps1") {
    & ".venv\Scripts\Activate.ps1"
}
python run_server.py
