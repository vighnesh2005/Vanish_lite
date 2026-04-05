#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Building vanish binary..."
make all

echo "[2/5] Python syntax checks..."
python3 -m py_compile admin_panel/server.py

echo "[3/5] Admin panel unit checks..."
python3 scripts/test_admin_panel.py

echo "[4/5] Frontend asset checks..."
rg -n "api/presets|api/start/validate|api/start/dry-run|api/session/report" admin_panel/static/app.js >/dev/null

echo "[5/5] Integration mode tests..."
if [[ "${EUID}" -eq 0 ]]; then
  scripts/test_modes_integration.sh
else
  echo "Skipping integration mode tests (requires root)."
  echo "Run separately for full coverage: sudo scripts/test_modes_integration.sh"
fi

echo "All checks completed."
