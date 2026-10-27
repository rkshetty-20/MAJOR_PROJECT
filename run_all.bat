@echo off
echo ====================================================
echo Starting Full AOD-IPS System
echo ====================================================
echo.
echo [1/2] Launching Backend Server in new window...
start "AOD-IPS Backend (FastAPI)" cmd /k "cd /d ""%~dp0backend"" && if exist venv\Scripts\activate.bat call venv\Scripts\activate.bat && python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"

echo [2/2] Launching Frontend Server in new window...
start "AOD-IPS Frontend (React)" cmd /k "set PATH=C:\Program Files\nodejs;%PATH% && cd /d ""%~dp0frontend"" && npm run dev"

echo.
echo ====================================================
echo Both services are starting up!
echo - Backend API and Docs: http://127.0.0.1:8000/docs
echo - SOC Frontend UI:    http://localhost:5173
echo ====================================================
echo.
pause
