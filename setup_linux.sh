#!/usr/bin/env bash
# Linux migration setup for titan-lab (run inside WSL as greenbird)
set -euo pipefail

PROJECT=/home/greenbird/titan-lab
cd "$PROJECT"

echo "=== [1/3] Python version ==="
python3 --version

echo "=== [2/3] Creating venv ==="
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q

echo "=== [3/3] Installing requirements ==="
./venv/bin/pip install -r requirements.txt -q

echo "=== DONE ==="
./venv/bin/python -c "import titan; print('titan import OK')"
