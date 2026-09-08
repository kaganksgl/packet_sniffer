#!/usr/bin/env bash
# Build the sniffer and install the desktop launcher.
#
#   ./install.sh            build, install the shortcut, use the bundled icon
#   ./install.sh --no-icon  same, but drop the icon and fall back to a stock one
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_FILE="packet-sniffer.desktop"
APPS_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"

WANT_ICON=1
[ "${1:-}" = "--no-icon" ] && WANT_ICON=0

echo "==> Building the sniffer"
make -C "$APP_DIR"

if [ "$WANT_ICON" = 1 ] && [ -f "$APP_DIR/packet-sniffer.svg" ]; then
    echo "==> Installing the icon"
    mkdir -p "$ICON_DIR"
    cp "$APP_DIR/packet-sniffer.svg" "$ICON_DIR/packet-sniffer.svg"
    # Tk cannot read SVG, so keep a PNG copy for the app window's own icon.
    rsvg-convert -w 128 -h 128 "$APP_DIR/packet-sniffer.svg" -o "$APP_DIR/packet-sniffer-128.png" 2>/dev/null \
        || magick -background none "$APP_DIR/packet-sniffer.svg" -resize 128x128 "$APP_DIR/packet-sniffer-128.png" 2>/dev/null \
        || echo "    (no SVG renderer found - the window will use the default icon)"
    ICON="packet-sniffer"
else
    echo "==> Removing the icon, falling back to the stock network symbol"
    rm -f "$ICON_DIR/packet-sniffer.svg" "$APP_DIR/packet-sniffer-128.png"
    ICON="network-wired"
fi

echo "==> Writing $DESKTOP_FILE"
cat > "$APP_DIR/$DESKTOP_FILE" <<DESKTOP
[Desktop Entry]
Type=Application
Version=1.0
Name=Packet Sniffer
GenericName=Network Packet Capture
Comment=Capture and inspect TCP/UDP packets
Exec="$APP_DIR/run.sh"
Path=$APP_DIR
Icon=$ICON
Terminal=false
Categories=Network;Monitor;
Keywords=packet;sniffer;network;capture;tcpdump;
StartupNotify=true
DESKTOP
chmod +x "$APP_DIR/$DESKTOP_FILE"

echo "==> Installing launcher to the application menu"
mkdir -p "$APPS_DIR"
cp "$APP_DIR/$DESKTOP_FILE" "$APPS_DIR/$DESKTOP_FILE"
chmod +x "$APPS_DIR/$DESKTOP_FILE"
update-desktop-database "$APPS_DIR" 2>/dev/null || true
gtk-update-icon-cache -qtf "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
kbuildsycoca6 --noincremental 2>/dev/null || kbuildsycoca5 --noincremental 2>/dev/null || true

echo "==> Installing shortcut to $DESKTOP_DIR"
mkdir -p "$DESKTOP_DIR"
cp "$APP_DIR/$DESKTOP_FILE" "$DESKTOP_DIR/$DESKTOP_FILE"
chmod +x "$DESKTOP_DIR/$DESKTOP_FILE"
# Plasma and GNOME only launch desktop files they consider trusted.
gio set "$DESKTOP_DIR/$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
kwriteconfig6 --file "$DESKTOP_DIR/$DESKTOP_FILE" --group "Desktop Entry" \
    --key "X-KDE-AuthorizeExecute" true 2>/dev/null || true

if getcap "$APP_DIR/sniffer" 2>/dev/null | grep -q cap_net_raw; then
    echo "==> Capture permission already granted"
else
    echo "==> Granting raw-socket capability (asks for authentication once)"
    echo "    Skip this if you would rather authenticate on every capture."
    pkexec setcap cap_net_raw,cap_net_admin+ep "$APP_DIR/sniffer" \
        || echo "    Skipped - the app will use pkexec per capture instead."
fi

# The capability travels with the file, so anyone who can run the binary can
# capture traffic. Keep it out of reach of other accounts on this machine.
chmod 750 "$APP_DIR/sniffer"

echo
echo "Done. Launch it from the desktop shortcut, the application menu, or:"
echo "  $APP_DIR/run.sh"
