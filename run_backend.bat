@echo off
echo ====================================================
echo Starting FraudGuard / AOD-IPS FastAPI Backend Server
echo ====================================================
cd /d "%~dp0backend"
call "venv\Scripts\activate.bat"
echo.
echo Backend API URL: http://127.0.0.1:8000
echo Swagger UI Docs: http://127.0.0.1:8000/docs
echo.
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
pause
