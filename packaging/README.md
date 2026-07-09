# Arch Linux packaging

An Arch Linux (`makepkg`/pacman) package for the **host `picosignet` CLI** — the
bridge daemon and provisioning/management tool from `host/`. It does **not**
package the RP2350 firmware, which is cross-built and flashed to the device
directly (`make uf2` / `make flash-uf2`; see [`../docs/PROVISIONING.md`](../docs/PROVISIONING.md)).

## Contents

| File                   | Purpose                                                              |
| ---------------------- | ------------------------------------------------------------------- |
| `PKGBUILD`             | VCS (`-git`) build recipe; builds the Go CLI from GitHub `HEAD`.     |
| `60-picosignet.rules`  | udev rule granting the device's serial port to the logged-in user.  |
| `.SRCINFO`             | Generated metadata (required if this is uploaded to the AUR).       |

The produced package (`picosignet-git`) `provides`/`conflicts` `picosignet`, and
installs:

- `/usr/bin/picosignet`
- `/usr/lib/udev/rules.d/60-picosignet.rules`
- `/usr/share/licenses/picosignet-git/{LICENSE-APACHE,LICENSE-MIT}`
- `/usr/share/doc/picosignet/*.md`

## Build & install

```sh
cd packaging
makepkg -si          # build, then install with pacman
```

`makepkg` fetches the Go module dependencies from the public module proxy during
`prepare()`, runs `go vet`/`go test` in `check()`, and builds a hardened (PIE,
`-trimpath`) binary. Requires `go>=1.26` and `git` (both pulled in as
`makedepends`).

To skip the test phase: `makepkg -si --nocheck`.

## udev rule

The device enumerates as USB `1209:000a` (CDC-ACM, product `PicoSignet`). Out of
the box its `/dev/ttyACM*` node is `root:uucp`, so opening it needs root or
`uucp` membership. `60-picosignet.rules`:

- tags the port with `uaccess` — the **active local user** gets access via
  systemd-logind, no group changes needed;
- keeps a `uucp` / `0660` fallback for daemon/service users; and
- adds a stable `/dev/picosignet` symlink you can pass as `--port`.

pacman reloads udev rules on install, but the rule only applies to devices
plugged in **after** that. Re-trigger for an already-connected device:

```sh
sudo udevadm control --reload && sudo udevadm trigger
```

## Versioning

There are no upstream release tags yet, so `pkgver()` derives a VCS version
(`r<commit-count>.<short-sha>`). Once releases are tagged, replace the `git+…`
source with a versioned tarball and remove `pkgver()` to make it a normal
(non-`-git`) package.

## Regenerating `.SRCINFO`

After editing `PKGBUILD`:

```sh
makepkg --printsrcinfo > .SRCINFO
```
