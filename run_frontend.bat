@echo off
echo ====================================================
echo Starting FraudGuard / AOD-IPS Frontend (Vite + React)
echo ====================================================
cd /d "%~dp0frontend"
echo.
echo Frontend Dashboard: http://localhost:5173
echo.
call npm run dev
pause
