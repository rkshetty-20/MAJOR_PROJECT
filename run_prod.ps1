# AOD-IPS LAN Demo Launcher
# Builds the dashboard, then serves the UI and the API from one origin on port 8000
# so any device on the local network can open it. No cloud account required.
$ErrorActionPreference = "Continue"

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

# npm is not on PATH in every shell; add the default install location.
$nodeDir = "C:\Program Files\nodejs"
if (Test-Path $nodeDir) { $env:PATH = "$nodeDir;" + $env:PATH }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "npm not found. Install Node.js or fix `$nodeDir in this script." -ForegroundColor Red
    exit 1
}

$python = Join-Path $root "backend\venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "Backend virtualenv not found at $python" -ForegroundColor Red
    Write-Host "Create it with: python -m venv backend\venv; backend\venv\Scripts\pip install -r backend\requirements.txt" -ForegroundColor Yellow
    exit 1
}

$port = 8000

# Prefer the interface that carries the default route: that is the address other
# devices on the network can actually reach. APIPA (169.254.x) and loopback are skipped.
$lanIp = $null
$defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric | Select-Object -First 1
if ($defaultRoute) {
    $lanIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $defaultRoute.ifIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
        Select-Object -First 1).IPAddress
}
if (-not $lanIp) {
    $lanIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
        Select-Object -First 1).IPAddress
}
if (-not $lanIp) { $lanIp = "127.0.0.1" }

$otherIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne $lanIp } |
    Select-Object -ExpandProperty IPAddress)

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "[1/2] Building production dashboard..." -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
Push-Location (Join-Path $root "frontend")
npm run build
$buildExit = $LASTEXITCODE
Pop-Location
if ($buildExit -ne 0) {
    Write-Host "Frontend build failed. Aborting." -ForegroundColor Red
    exit 1
}

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "[2/2] Starting AOD-IPS on all network interfaces" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Yellow
Write-Host "  This machine : http://localhost:$port" -ForegroundColor White
Write-Host "  LAN access   : http://${lanIp}:$port" -ForegroundColor White
Write-Host "  API docs     : http://${lanIp}:$port/docs" -ForegroundColor White
Write-Host "  Health       : http://${lanIp}:$port/health" -ForegroundColor White
if ($otherIps.Count -gt 0) {
    Write-Host "  Also bound to: $($otherIps -join ', ') (port $port)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "If other devices cannot connect, allow the port through Windows Firewall" -ForegroundColor DarkYellow
Write-Host "(run in an Administrator PowerShell):" -ForegroundColor DarkYellow
Write-Host "  New-NetFirewallRule -DisplayName 'AOD-IPS $port' -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow" -ForegroundColor DarkGray
Write-Host "`nPress Ctrl+C to stop.`n" -ForegroundColor DarkGray

Push-Location (Join-Path $root "backend")
& $python -m uvicorn app.main:app --host 0.0.0.0 --port $port
Pop-Location
