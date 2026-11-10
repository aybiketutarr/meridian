#!/usr/bin/env sh
# Installs the `meridian` command and a menu entry for the current user (no root needed).
# Usage:  ./install.sh            install / update
#         ./install.sh --uninstall
set -eu
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
APP="$DATA/meridian-app"
BIN="$HOME/.local/bin"
DESK="$DATA/applications"

if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "$APP" "$BIN/meridian" "$DESK/meridian.desktop"
  echo "Meridian removed. (Scan history in $DATA/meridian was kept.)"
  exit 0
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }
command -v nmap >/dev/null 2>&1 || echo "Note: nmap not found. Install it (sudo apt install nmap) for real scans; sample-data mode works without it."

mkdir -p "$APP" "$BIN" "$DESK"
cp "$DIR/server.py" "$DIR/index.html" "$APP/"

cat > "$BIN/meridian" <<LAUNCHER
#!/usr/bin/env sh
exec python3 "$APP/server.py" "\$@"
LAUNCHER
chmod +x "$BIN/meridian"

cat > "$DESK/meridian.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=Meridian
Comment=Network scanner UI on top of nmap
Exec=$BIN/meridian
Terminal=false
Categories=Network;Security;
ENTRY

echo "Installed. Run:  meridian"
echo "For OS detection / traceroute run:  sudo -E \"$BIN/meridian\""
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Add $BIN to your PATH to run it as just 'meridian'." ;; esac
