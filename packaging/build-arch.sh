#!/usr/bin/env bash
# Build the Arch Linux package (.pkg.tar.zst) into packaging/dist/.
#
# Requires: makepkg (pacman), a Go toolchain (>= 1.26), git.
# Extra makepkg flags pass through, e.g.:  ./build-arch.sh --nocheck
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
distdir="$here/dist"

if ! command -v makepkg >/dev/null 2>&1; then
	echo "error: makepkg not found — this must run on Arch Linux (pacman)." >&2
	exit 1
fi

mkdir -p "$distdir"

# makepkg rewrites the pkgver= line in PKGBUILD from pkgver(), so back the file
# up and restore it to keep the tracked source pristine. Also tidy makepkg's
# work dirs — the Go module cache is created read-only, so chmod before rm.
pkgbuild_bak="$(mktemp)"
cp -p "$here/PKGBUILD" "$pkgbuild_bak"
cleanup() {
	cp -p "$pkgbuild_bak" "$here/PKGBUILD"
	rm -f "$pkgbuild_bak"
	chmod -R u+w "$here/src" 2>/dev/null || true
	rm -rf "$here/src" "$here/pkg"
}
trap cleanup EXIT

cd "$here"
PKGDEST="$distdir" makepkg -f "$@"

echo
echo "Built Arch package(s) in $distdir:"
ls -1 "$distdir"/*.pkg.tar.* 2>/dev/null || echo "  (none found)"
