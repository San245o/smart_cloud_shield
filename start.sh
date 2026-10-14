#!/usr/bin/env bash
# Smart Cloud Shield - Linux/macOS/WSL Launcher
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "========================================================"
echo "       Smart Cloud Shield - Startup Script"
echo "========================================================"
echo ""

# 1. Virtual Environment
if [ ! -d "venv" ]; then
    echo "[!] Creating virtual environment 'venv'..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# 2. Environment Variables
export SHOW_OTP=1
export DEMO_MODE=0

# 3. Seed Database If Missing
if [ ! -f "instance/scs.db" ]; then
    echo "[*] Database not found. Initializing and seeding demo data..."
    python seed.py
fi

echo ""
echo "========================================================"
echo "[*] Application starting on: http://127.0.0.1:5000"
echo "[*] Demo Logins: admin, alice, bob, carol (Pass: Pass@12345)"
echo "[*] Press Ctrl+C to stop the server"
echo "========================================================"
echo ""

# 4. Start Flask App
python app.py
