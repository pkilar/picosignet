# Distribution packaging

Native OS packages for the **host `picosignet` CLI** — the bridge daemon and
provisioning/management tool from `host/`. Neither package includes the RP2350
firmware, which is cross-built and flashed to the device directly (`make uf2` /
`make flash-uf2`; see [`../docs/PROVISIONING.md`](../docs/PROVISIONING.md)).

Both packages install the same layout:

- the `picosignet` binary (`/usr/bin/picosignet`),
- a udev rule (`60-picosignet.rules`) so the CLI can open the device's CDC-ACM
  serial port without root, and
- the licenses and `docs/*.md`.

The udev rule is shared: both `PKGBUILD` and `debian/rules` install the single
`packaging/60-picosignet.rules` file.

## Layout

| Path                   | Purpose                                                       |
| ---------------------- | ------------------------------------------------------------- |
| `build-arch.sh`        | One-command Arch build → `dist/*.pkg.tar.zst`.                |
| `build-deb.sh`         | One-command Debian build → `dist/*.deb`.                      |
| `PKGBUILD` / `.SRCINFO`| Arch Linux (`makepkg`) package.                               |
| `debian/`              | Debian/Ubuntu (`dpkg-buildpackage`) package.                  |
| `60-picosignet.rules`  | udev rule, shared by both packages.                           |

## Building

The quickest path is the per-distro build scripts, which produce finished
packages in `packaging/dist/` (gitignored) and clean up all intermediate build
artifacts:

```sh
packaging/build-arch.sh          # -> packaging/dist/picosignet-git-*.pkg.tar.zst
packaging/build-deb.sh           # -> packaging/dist/picosignet_*.deb
```

Both run `go vet`/`go test` and build a hardened (PIE, `-trimpath`) binary.
Extra flags pass through — `packaging/build-arch.sh --nocheck`, or
`DEB_BUILD_OPTIONS=nocheck packaging/build-deb.sh` — to skip the test phase. The
sections below cover the equivalent manual invocations.

## Arch Linux

VCS (`-git`) package that builds the CLI from GitHub `HEAD` (there are no release
tags yet, so `pkgver()` derives `r<count>.<sha>`).

```sh
cd packaging
makepkg -si            # build, then install with pacman
```

`makepkg` fetches the Go module dependencies during `prepare()`, runs
`go vet`/`go test` in `check()`, and builds a hardened (PIE, `-trimpath`) binary.
Skip the tests with `makepkg -si --nocheck`. Regenerate `.SRCINFO` after editing
`PKGBUILD` with `makepkg --printsrcinfo > .SRCINFO`.

## Debian / Ubuntu

`debian/` is a native package that builds straight from this tree. It is
deliberately **debhelper-free** — `debian/rules` needs only `dpkg-dev` and a Go
toolchain (>= 1.26), so it builds anywhere Go is available rather than requiring
a matching `debhelper-compat`.

`dpkg-buildpackage` expects `debian/` at the source-tree root, so symlink (or
copy) it up from `packaging/` first:

```sh
ln -sfn packaging/debian debian
dpkg-buildpackage -b -us -uc          # binary-only, unsigned
rm debian                             # remove the symlink
```

The resulting `.deb` lands in the parent directory; install it with
`sudo apt install ../picosignet_*.deb` (or `sudo dpkg -i`). The build runs
`go vet`/`go test`; skip them with `DEB_BUILD_OPTIONS=nocheck`. Clean build
artifacts with `debian/rules clean` (via the symlink).

The version derives from `debian/changelog`
(`0.0.0~git<date>.<sha>`); bump it with a new changelog entry per build, or wire
it to `git describe` once releases are tagged.

## udev rule

The device enumerates as USB `1209:000a` (CDC-ACM, product `PicoSignet`). Out of
the box its `/dev/ttyACM*` node is root-owned (group `uucp` on Arch, `dialout`
on Debian), so opening it needs root or group membership.
`60-picosignet.rules`:

- tags the port with `uaccess` — the **active local user** gets access via
  systemd-logind, no group changes needed;
- keeps a `uucp` / `0660` fallback for daemon/service users; and
- adds a stable `/dev/picosignet` symlink you can pass as `--port`.

Package installation reloads udev rules, but they only apply to devices plugged
in **afterward**. Re-trigger for an already-connected device:

```sh
sudo udevadm control --reload && sudo udevadm trigger
```
