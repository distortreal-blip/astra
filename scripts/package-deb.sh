#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(cat "$ROOT_DIR/VERSION")}"
ARCH="${ARCH:-amd64}"
PKG="astra_${VERSION}_${ARCH}"
OUT_DIR="$ROOT_DIR/dist/deb"
WORK_DIR="$ROOT_DIR/dist/.pkgdeb/$PKG"

mkdir -p "$WORK_DIR/DEBIAN" \
         "$WORK_DIR/opt/astra/bin" \
         "$WORK_DIR/etc/astra" \
         "$WORK_DIR/etc/systemd/system"

cat > "$WORK_DIR/DEBIAN/control" <<EOF
Package: astra
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: ASTRA Team
Description: ASTRA adaptive VPN protocol
EOF

cp "$ROOT_DIR/bin/astra-client" "$WORK_DIR/opt/astra/bin/"
cp "$ROOT_DIR/bin/astra-entry" "$WORK_DIR/opt/astra/bin/"
cp "$ROOT_DIR/bin/astra-relay" "$WORK_DIR/opt/astra/bin/"
cp "$ROOT_DIR/bin/astra-exit" "$WORK_DIR/opt/astra/bin/"
cp "$ROOT_DIR/bin/astra-lab" "$WORK_DIR/opt/astra/bin/"

cp "$ROOT_DIR/configs/"*.json "$WORK_DIR/etc/astra/"
cp "$ROOT_DIR/systemd/"*.service "$WORK_DIR/etc/systemd/system/"

mkdir -p "$OUT_DIR"
dpkg-deb --build "$WORK_DIR" "$OUT_DIR/${PKG}.deb"
echo "DEB created: $OUT_DIR/${PKG}.deb"
