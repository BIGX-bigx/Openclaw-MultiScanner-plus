#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Starting Openclaw-MultiScanner web console..."
echo "URL: http://127.0.0.1:8765/"
echo "Tip: run 'python3 tools/doctor.py' first if you want an environment check."

python3 tools/clawmatrix_web.py --host 127.0.0.1 --port 8765
