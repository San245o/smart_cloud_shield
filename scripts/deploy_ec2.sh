#!/usr/bin/env bash
# Smart Cloud Shield — AWS EC2 / Linux VPS Deployment Script
set -e

echo "=== 1. Updating System Packages ==="
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install -y python3-pip python3-venv nginx git libgomp1

echo "=== 2. Setting Up Python Environment ==="
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt gunicorn

echo "=== 3. Seeding Database & Classifying Sample Files ==="
python seed.py

echo "=== 4. Testing Application ==="
python -m pytest -q tests

echo "=== 5. Starting Gunicorn Systemd Service ==="
cat << 'EOF' | sudo tee /etc/systemd/system/scs.service
[Unit]
Description=Smart Cloud Shield Daemon
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/smart_cloud_shield
Environment="PATH=/home/ubuntu/smart_cloud_shield/venv/bin"
ExecStart=/home/ubuntu/smart_cloud_shield/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable scs
sudo systemctl restart scs

echo "=== Deployment Complete! Smart Cloud Shield is running locally on port 5000 ==="
