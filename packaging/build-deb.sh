#!/usr/bin/env bash
# Build the Debian package (.deb) into packaging/dist/.
#
# Requires: dpkg-buildpackage (dpkg-dev), a Go toolchain (>= 1.26), git.
# Extra dpkg-buildpackage flags pass through, e.g.:
#   DEB_BUILD_OPTIONS=nocheck ./build-deb.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
distdir="$here/dist"

if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
	echo "error: dpkg-buildpackage not found — install dpkg-dev." >&2
	exit 1
fi

mkdir -p "$distdir"

# dpkg-buildpackage needs debian/ at the source-tree root, so symlink it in
# transiently and always clean up — even on failure/interrupt.
cleanup() {
	# Remove the transient root symlink and the binary the build drops there.
	rm -f "$repo/debian" "$repo/picosignet"
	chmod -R u+w "$here/debian/_build" 2>/dev/null || true
	rm -rf "$here/debian/_build" "$here/debian/picosignet" "$here/debian/files"
	rm -f "$here/debian"/*.substvars 2>/dev/null || true
}
trap cleanup EXIT
ln -sfn packaging/debian "$repo/debian"

cd "$repo"
# -b: binary-only, -us -uc: unsigned, -d: skip the build-dependency check so
# this also builds on non-Debian hosts (e.g. Arch) where golang-go/git are not
# registered as dpkg packages.
dpkg-buildpackage -b -us -uc -d "$@"

# Artifacts land next to the source tree; move them into dist/.
shopt -s nullglob
moved=0
for f in "$repo/.."/picosignet_*.deb "$repo/.."/picosignet_*.buildinfo "$repo/.."/picosignet_*.changes; do
	mv "$f" "$distdir"/
	moved=1
done

echo
if [ "$moved" = 1 ]; then
	echo "Built Debian package(s) in $distdir:"
	ls -1 "$distdir"/*.deb 2>/dev/null || echo "  (none found)"
else
	echo "warning: no build artifacts found in $(cd "$repo/.." && pwd)" >&2
	exit 1
fi
