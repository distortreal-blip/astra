#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(cat "$ROOT_DIR/VERSION")}"
ARCH="${ARCH:-x86_64}"
OUT_DIR="$ROOT_DIR/dist/rpm"
TOPDIR="$ROOT_DIR/dist/.pkgrpm"

mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$OUT_DIR"

TARBALL="$TOPDIR/SOURCES/astra-${VERSION}.tar.gz"
tar -czf "$TARBALL" -C "$ROOT_DIR" bin configs systemd README.md VERSION

SPEC="$TOPDIR/SPECS/astra.spec"
cat > "$SPEC" <<EOF
Name: astra
Version: $VERSION
Release: 1%{?dist}
Summary: ASTRA adaptive VPN protocol
License: MIT
BuildArch: $ARCH

%description
ASTRA adaptive VPN protocol.

%install
mkdir -p %{buildroot}/opt/astra/bin
mkdir -p %{buildroot}/etc/astra
mkdir -p %{buildroot}/etc/systemd/system
cp -r %{_sourcedir}/bin/* %{buildroot}/opt/astra/bin/
cp -r %{_sourcedir}/configs/* %{buildroot}/etc/astra/
cp -r %{_sourcedir}/systemd/* %{buildroot}/etc/systemd/system/

%files
/opt/astra/bin/*
/etc/astra/*
/etc/systemd/system/*.service

%changelog
* Thu Jan 01 1970 ASTRA Team - $VERSION-1
- Initial release
EOF

rpmbuild --define "_topdir $TOPDIR" -bb "$SPEC"
cp "$TOPDIR/RPMS/$ARCH/"*.rpm "$OUT_DIR/"
echo "RPM created in $OUT_DIR"
