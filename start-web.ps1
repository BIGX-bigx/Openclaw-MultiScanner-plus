$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "Starting Openclaw-MultiScanner web console..."
Write-Host "URL: http://127.0.0.1:8765/"
Write-Host "Tip: run 'python .\tools\doctor.py' first if you want an environment check."

python .\tools\clawmatrix_web.py --host 127.0.0.1 --port 8765
