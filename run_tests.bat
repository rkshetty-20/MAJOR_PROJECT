@echo off
echo ====================================================
echo Running FraudGuard Backend and Frontend Tests
echo ====================================================
echo.
echo [1/2] Running Backend Pytest Suite...
cd /d "%~dp0backend"
call "venv\Scripts\activate.bat"
python -m pytest -v
if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Some backend tests had errors or failures.
) else (
    echo.
    echo [SUCCESS] All backend tests completed successfully!
)

echo.
echo ----------------------------------------------------
echo [2/2] Running Frontend Vitest Suite...
echo ----------------------------------------------------
cd /d "%~dp0frontend"
call npm test
if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Some frontend tests had errors or failures.
) else (
    echo.
    echo [SUCCESS] Frontend tests completed successfully!
)

echo.
echo ====================================================
echo Test Execution Complete.
echo ====================================================
pause
