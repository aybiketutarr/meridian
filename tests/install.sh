#!/usr/bin/env sh
# Thin wrapper kept for compatibility: the installer itself is install.py (Linux, macOS and Windows).
#   ./install.sh                install / update          ./install.sh --lang tr     messages in Turkish
#   ./install.sh --uninstall    same as: meridian --uninstall
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
for PY in python3 python; do
  if command -v "$PY" >/dev/null 2>&1 && "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    exec "$PY" "$DIR/install.py" "$@"
  fi
done
echo "Python 3.10 or newer is required (https://www.python.org/downloads/)." >&2
exit 1
