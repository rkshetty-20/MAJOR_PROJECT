# AOD-IPS Launcher Script
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Starting AOD-IPS Full System" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

$psExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path $psExe)) { $psExe = "powershell" }

# 1. Start Backend
Write-Host "`n[1/2] Launching Backend Server in new window..." -ForegroundColor Green
Start-Process $psExe -ArgumentList "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", "cd '$root\backend'; if (Test-Path '.\venv\Scripts\Activate.ps1') { .\venv\Scripts\Activate.ps1 }; python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"

# 2. Start Frontend
Write-Host "[2/2] Launching Frontend Server in new window..." -ForegroundColor Green
Start-Process $psExe -ArgumentList "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", "`$env:PATH = 'C:\Program Files\nodejs;' + `$env:PATH; cd '$root\frontend'; npm run dev"

Write-Host "`n====================================================" -ForegroundColor Yellow
Write-Host "Both services are running!" -ForegroundColor Yellow
Write-Host "• Backend API Docs: http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "• Frontend SOC UI:  http://localhost:5173" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor Yellow
