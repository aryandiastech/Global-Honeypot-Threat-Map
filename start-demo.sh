#!/usr/bin/env sh
# One-click local demo (macOS / Linux / Git Bash). No AWS account needed.
#   ./start-demo.sh            simulated live traffic
#   ./start-demo.sh --cowrie   also tail a real Cowrie honeypot (docker compose in honeypots/cowrie)
set -e
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python || true)
[ -n "$PY" ] || { echo "Missing Python 3.10+ (https://www.python.org/downloads/)"; exit 1; }
command -v npm >/dev/null || { echo "Missing Node.js LTS (https://nodejs.org/)"; exit 1; }
[ -f frontend/.env ] || { cp frontend/.env.example frontend/.env; echo "Created frontend/.env - add your Mapbox token (see DEMO.md)."; }
grep -q '^VITE_MAPBOX_TOKEN=pk\.' frontend/.env || echo "Note: VITE_MAPBOX_TOKEN is empty - the globe needs it (see DEMO.md)."
[ -d frontend/node_modules ] || npm --prefix frontend install

EXTRA=""
[ "$1" = "--cowrie" ] && EXTRA="--cowrie-log honeypots/cowrie/logs/cowrie.json"
"$PY" demo/server.py --live $EXTRA &
BACKEND=$!
trap 'kill $BACKEND 2>/dev/null' EXIT INT TERM
echo "Backend: http://localhost:8000/events?limit=5   Dashboard: http://localhost:5173"
npm --prefix frontend run dev
