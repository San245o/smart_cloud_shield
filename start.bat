@echo off
setlocal
title Smart Cloud Shield Launcher

echo ========================================================
echo        Smart Cloud Shield - Startup Script
echo ========================================================
echo.

cd /d "%~dp0"

:: 1. Check for Virtual Environment
if not exist "venv\Scripts\python.exe" (
    echo [!] Virtual environment not found. Creating 'venv'...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment. Ensure Python is installed.
        pause
        exit /b 1
    )
    echo [*] Installing dependencies from requirements.txt...
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)

:: 2. Set Windows Pure-Python & Security Environment Variables
set DISABLE_SQLALCHEMY_CEXT=1
set SHOW_OTP=1
set DEMO_MODE=0

:: 3. Seed Database If Not Present
if not exist "instance\scs.db" (
    echo [*] Database not found. Initializing and seeding demo data...
    python seed.py
)

echo.
echo ========================================================
echo [*] Application starting on: http://127.0.0.1:5000
echo [*] Demo Logins: admin, alice, bob, carol (Pass: Pass@12345)
echo [*] Press Ctrl+C in this window to stop the server
echo ========================================================
echo.

:: 4. Start the Application
python app.py

pause
