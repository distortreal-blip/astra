#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-/opt/astra/bin}"
CONF_DIR="${CONF_DIR:-/etc/astra}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

echo "Installing ASTRA systemd units..."
sudo mkdir -p "$BIN_DIR" "$CONF_DIR"

sudo cp "$ROOT_DIR/systemd/astra-entry.service" "$SYSTEMD_DIR/"
sudo cp "$ROOT_DIR/systemd/astra-relay.service" "$SYSTEMD_DIR/"
sudo cp "$ROOT_DIR/systemd/astra-exit.service" "$SYSTEMD_DIR/"
sudo cp "$ROOT_DIR/systemd/astra-client.service" "$SYSTEMD_DIR/"

sudo cp "$ROOT_DIR/configs/"*.json "$CONF_DIR/"

echo "Copying binaries (build if missing)..."
if [ ! -x "$ROOT_DIR/cmd/astra-entry/astra-entry" ] && [ ! -x "$ROOT_DIR/bin/astra-entry" ]; then
  (cd "$ROOT_DIR" && go build -o "$ROOT_DIR/bin/astra-entry" ./cmd/astra-entry)
  (cd "$ROOT_DIR" && go build -o "$ROOT_DIR/bin/astra-relay" ./cmd/astra-relay)
  (cd "$ROOT_DIR" && go build -o "$ROOT_DIR/bin/astra-exit" ./cmd/astra-exit)
  (cd "$ROOT_DIR" && go build -o "$ROOT_DIR/bin/astra-client" ./cmd/astra-client)
fi

sudo cp "$ROOT_DIR/bin/astra-entry" "$BIN_DIR/"
sudo cp "$ROOT_DIR/bin/astra-relay" "$BIN_DIR/"
sudo cp "$ROOT_DIR/bin/astra-exit" "$BIN_DIR/"
sudo cp "$ROOT_DIR/bin/astra-client" "$BIN_DIR/"
if [ -f "$ROOT_DIR/bin/astra-tun-client" ]; then
  sudo cp "$ROOT_DIR/bin/astra-tun-client" "$BIN_DIR/"
fi

sudo systemctl daemon-reload
sudo systemctl enable --now astra-entry astra-relay astra-exit astra-client

echo "Done. Configs in $CONF_DIR, binaries in $BIN_DIR."
