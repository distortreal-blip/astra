#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT_DIR/dist"
mkdir -p "$DIST"

build_target() {
  local goos="$1"
  local goarch="$2"
  local outdir="$DIST/astra-${goos}-${goarch}"
  mkdir -p "$outdir/bin" "$outdir/configs" "$outdir/systemd"

  echo "Building $goos/$goarch..."
  GOOS="$goos" GOARCH="$goarch" go build -o "$outdir/bin/astra-client" "$ROOT_DIR/cmd/astra-client"
  GOOS="$goos" GOARCH="$goarch" go build -o "$outdir/bin/astra-entry" "$ROOT_DIR/cmd/astra-entry"
  GOOS="$goos" GOARCH="$goarch" go build -o "$outdir/bin/astra-relay" "$ROOT_DIR/cmd/astra-relay"
  GOOS="$goos" GOARCH="$goarch" go build -o "$outdir/bin/astra-exit" "$ROOT_DIR/cmd/astra-exit"
  GOOS="$goos" GOARCH="$goarch" go build -o "$outdir/bin/astra-lab" "$ROOT_DIR/cmd/astra-lab"

  cp -r "$ROOT_DIR/configs"/* "$outdir/configs/"
  cp -r "$ROOT_DIR/systemd"/* "$outdir/systemd/"
  cp "$ROOT_DIR/README.md" "$outdir/"

  (cd "$DIST" && tar -czf "astra-${goos}-${goarch}.tar.gz" "astra-${goos}-${goarch}")
}

build_target linux amd64
build_target linux arm64

echo "Artifacts created in $DIST"
