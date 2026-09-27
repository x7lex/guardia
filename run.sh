#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT/.venv/bin/python"
WEB="$ROOT/hackthehill3-website-final/website/scanly"

if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" ]]; then
  echo "Python 3 is required. Install Python 3.11+ and try again." >&2
  exit 1
fi
if [[ ! -d "$WEB/node_modules" ]]; then
  echo "Website dependencies are missing. Run: npm ci --prefix hackthehill3-website-final/website/scanly" >&2
  exit 1
fi

cd "$ROOT"
exec "$PYTHON" scripts/desktop.py
