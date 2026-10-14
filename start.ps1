# Smart Cloud Shield - PowerShell Launcher
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       Smart Cloud Shield - Startup Script" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 1. Check & Activate Virtual Environment
$VenvPython = Join-Path $ScriptDir "venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[!] Virtual environment not found. Creating 'venv'..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
    & "$VenvPython" -m pip install -r requirements.txt
}

# 2. Environment Variables
$env:DISABLE_SQLALCHEMY_CEXT = "1"
$env:SHOW_OTP = "0"
$env:DEMO_MODE = "0"

# 3. Seed Database If Missing
$DbFile = Join-Path $ScriptDir "instance\scs.db"
if (-not (Test-Path $DbFile)) {
    Write-Host "[*] Database not found. Initializing and seeding demo data..." -ForegroundColor Yellow
    & "$VenvPython" seed.py
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "[*] Application starting on: http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "[*] Demo Logins: admin, alice, bob, carol (Pass: Pass@12345)" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to stop the server" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

# 4. Launch App
& "$VenvPython" app.py
