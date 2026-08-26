#!/usr/bin/env sh
set -eu

workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
backend="$workspace/backend"
venv="$backend/.venv"

if [ ! -x "$venv/bin/python" ]; then
  python3 -m venv "$venv"
fi

if [ "${FORENSCOPE_SKIP_INSTALL:-0}" != "1" ]; then
  "$venv/bin/python" -m pip install --upgrade pip
  "$venv/bin/python" -m pip install -e "$backend[dev]"
fi

cd "$backend"
exec "$venv/bin/python" -m pytest "$@"
