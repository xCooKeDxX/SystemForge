#!/usr/bin/env bash
# Builds SystemForge-Setup-<version>.msi from a published win-x64 folder.
#   ./build-msi.sh <publish folder> <version> [out dir]
# Needs msitools (wixl, wixl-heat). Signing happens afterwards with sign.ps1 on Windows.
set -euo pipefail
PUB=${1:?publish folder}; VER=${2:?version}; OUT=${3:-.}
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
# Every file under the publish folder becomes a component; the main exe is referenced by the shortcut.
find "$PUB" -type f | sort | wixl-heat -p "$PUB/" --component-group AppFiles --var var.Pub --directory-ref INSTALLDIR > "$TMP/files.wxs"
sed -e "s/@VERSION@/$VER/g" "$HERE/SystemForge.wxs" > "$TMP/SystemForge.wxs"
wixl -D Pub="$PUB" -D Here="$HERE" -a x64 -o "$OUT/SystemForge-Setup-$VER.msi" "$TMP/SystemForge.wxs" "$TMP/files.wxs"
rm -rf "$TMP"
sha256sum "$OUT/SystemForge-Setup-$VER.msi" | awk '{print $1}' > "$OUT/SystemForge-Setup-$VER.msi.sha256"
echo "built $OUT/SystemForge-Setup-$VER.msi"
