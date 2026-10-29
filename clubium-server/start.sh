#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -q -r requirements.txt
python bootstrap.py
exec python -m uvicorn app:app --host 127.0.0.1 --port 8000
