#!/bin/sh
# Installs process-watcher as a systemd service. Run as root from the
# directory that contains the binary for this architecture:
#
#   sudo ./packaging/install.sh ./dist/process-watcher-linux-amd64
#
# It does not start the service: edit /etc/process-watcher/config.yaml first
# and run "process-watcher doctor".
set -eu

BIN="${1:?usage: install.sh <path to the process-watcher binary>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 1; }
[ -f "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }

install -m 0755 -o root -g root "$BIN" /usr/local/bin/process-watcher
install -d -m 0755 -o root -g root /etc/process-watcher
if [ ! -e /etc/process-watcher/config.yaml ]; then
  install -m 0600 -o root -g root "$HERE/config/process-watcher.yaml" /etc/process-watcher/config.yaml
else
  echo "keeping the existing /etc/process-watcher/config.yaml"
fi
install -m 0644 -o root -g root "$HERE/systemd/process-watcher.service" /etc/systemd/system/process-watcher.service
systemctl daemon-reload

echo
echo "Installed. Next steps:"
echo "  1. edit /etc/process-watcher/config.yaml"
echo "  2. process-watcher doctor"
echo "  3. systemctl enable --now process-watcher"
