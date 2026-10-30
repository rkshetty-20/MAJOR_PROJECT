@echo off
echo ====================================================
echo Starting AOD-IPS in LAN demo mode
echo ====================================================
echo.
set PATH=C:\Program Files\nodejs;%PATH%
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_prod.ps1"
pause
