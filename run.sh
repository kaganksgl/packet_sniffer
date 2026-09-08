#!/usr/bin/env bash
# Launcher used by the desktop shortcut.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build on first run so the shortcut works straight after a checkout. A build
# failure must be visible: launched from a desktop icon there is no terminal to
# print to, and dying here would just look like nothing happened.
if [ ! -x "$APP_DIR/sniffer" ] || [ "$APP_DIR/packet_sniffer.c" -nt "$APP_DIR/sniffer" ]; then
    if ! build_output="$(make -C "$APP_DIR" 2>&1)"; then
        message="The packet sniffer failed to build:

$(printf '%s\n' "$build_output" | tail -20)"
        if command -v kdialog >/dev/null 2>&1; then
            kdialog --error "$message" || true
        elif command -v zenity >/dev/null 2>&1; then
            zenity --error --no-markup --text="$message" || true
        else
            printf '%s\n' "$message" >&2
        fi
    fi
fi

exec python3 "$APP_DIR/sniffer_gui.py" "$@"
