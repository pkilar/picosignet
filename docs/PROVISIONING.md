# Provisioning & deployment

End-to-end setup, from a blank board to `ssh-cert-api` signing through the
device. Target hardware: Waveshare RP2350-One (RP2350A, 4 MiB flash).

## 0. Build & flash the firmware

```sh
make uf2
# BOOTSEL flashing: hold BOOTSEL, plug the board in, then either:
cp target/thumbv8m.main-none-eabihf/release/hsm-fw.uf2 /run/media/$USER/RP2350/
# or over picoboot (no drive mount needed):
make flash-uf2
# or, with a debug probe:
make flash
```

The device enumerates as a USB CDC-ACM serial port (`1209:000A`, product
`PicoSignet`), discoverable at `/dev/serial/by-id/*PicoSignet*`. All `PicoSignet` commands
accept `--port <path>` to override auto-discovery.

**First boot self-provisions the OTP device secret** (see
`FLASH_LAYOUT.md`): the firmware burns a TRNG-generated 32-byte secret into an
on-die OTP page and permanently locks the page against the bootloader and
non-secure access. This is a one-time, per-chip event; `picosignet status` should
show `otp secret: true` from then on. Reflashing the firmware does not touch
it.

## 1a. Dev mode (no PIN; for development hosts)

```sh
picosignet init               # dev mode
picosignet generate-key       # generate the on-device CA key, prints the public key
picosignet pubkey > cerberus-ca.pub
picosignet status
```

The device is operational immediately on every plug-in. The dev wrapping key is
bound to the OTP device secret, so a flash chip-off dump alone cannot recover
the CA key — but anyone holding the *running* device can sign, and until the
secure-boot burn (below) anyone can also reflash it. Use dev mode where that is
acceptable (see `THREAT_MODEL.md`).

## 1b. Production mode (PIN-protected)

```sh
picosignet init --prod --max-retries 10           # prompts for a PIN twice
# init in prod mode generates the CA key as part of init.
picosignet pubkey > cerberus-ca.pub               # works while locked
picosignet unlock                                  # prompts for the PIN
picosignet status                                  # state: prodReady
```

Use a strong passphrase. The KEK is bound to the on-die OTP secret, so offline
brute-force of a flash dump is no longer possible — the passphrase budget now
defends against *online* guessing (rate-limited, ≈1 s Argon2id per attempt,
lockout after `--max-retries`) and against an attacker who has also defeated
the chip's OTP protections. Add `--wipe-on-lockout` if you prefer key
destruction over availability after a brute-force attempt. Re-lock when idle
with `picosignet lock`; rotate the passphrase with `picosignet change-pin`.

To change modes later, `picosignet factory-reset` (destroys the key) then `init`
again — there is no in-place dev↔prod switch.

## 1c. Production lockdown: secure boot (IRREVERSIBLE)

Development devices stay freely reflashable. A *production* device should also
refuse to run anything but our signed firmware — otherwise an attacker with
physical access can flash key-exfiltrating firmware and wait for an unlock.
This is a staged, partially **irreversible** process driven by
`scripts/provision_production.sh`; a mistake at the wrong stage bricks the
board, so the script gates every fuse write behind a typed confirmation.

```sh
make keygen          # one-time secp256k1 boot key -> keys/picosignet-boot.pem
                     #   BACK IT UP OFFLINE, TWICE. After P4, losing it
                     #   permanently bricks firmware updates.
make uf2-signed      # signed+sealed UF2 + keys/picosignet-bootkey-otp.json

picosignet reboot-bootloader                  # device into BOOTSEL for each stage
scripts/provision_production.sh P1       # flash SIGNED image; run full HIL
scripts/provision_production.sh P2       # [BURN] boot-key hash (BOOTKEY0)
scripts/provision_production.sh P3       # power-cycle check (nothing burned)
scripts/provision_production.sh P4       # [BURN] SECURE_BOOT_ENABLE
                                          #   = point of no return
scripts/provision_production.sh P5       # [BURN] optional: glitch-detector
                                          #   force-arm, debug disable,
                                          #   PICOBOOT disable
```

Order of operations is the safety mechanism:

- **P1** proves the *signed* image boots while the bootrom still ignores
  signatures — validating the seal pipeline before anything irreversible.
- **P2** burns only the key hash; the device still boots anything. Verify the
  burned rows against `keys/picosignet-bootkey-otp.json` (`picotool otp get`)
  before going further.
- **P4** flips enforcement. Immediately verify: the signed image boots,
  `picosignet status` shows `secure boot: true`, and an **unsigned** UF2 is
  refused.
- **P5** items are independent and each gated: ROM-level glitch-detector
  force-arm, debug-port disable, and PICOBOOT disable (picotool stops working
  forever; signed-UF2 drag-and-drop via the BOOTSEL drive remains — never also
  disable the MSD interface or the device becomes un-updatable).

Dry-run the whole sequence P1→P4 (including the unsigned-refused negative
test) on a sacrificial board before touching a real production unit.

Firmware updates after lockdown: build, `make uf2-signed`, reboot to BOOTSEL,
copy the **signed** UF2. Anti-rollback versioning (`picotool seal --rollback`)
is available if downgrade attacks enter your threat model; it burns an OTP row
per version step.

## 2. Trust the CA on your SSH servers

```sh
sudo cp cerberus-ca.pub /etc/ssh/cerberus-ca.pub
# /etc/ssh/sshd_config:
#   TrustedUserCAKeys /etc/ssh/cerberus-ca.pub
sudo systemctl reload sshd
```

## 3. Run the bridge for ssh-cert-api

The bridge exposes the device's protocol over VSOCK/TCP/Unix and reproduces the
enclave's framing, limits, and 32-connection cap. It pushes wall-clock time to
the device on connect and every 5 minutes, and **firewalls management commands**
away from network clients by default.

```sh
# TCP (simplest for a non-Nitro host):
picosignet bridge --listen tcp:127.0.0.1:5000

# Unix socket:
picosignet bridge --listen unix:/run/PicoSignet.sock

# VSOCK (Nitro-style drop-in — see the CID-16 note below):
picosignet bridge --listen vsock:5000
```

`ssh-cert-api` dials VSOCK **CID 16, port 5000**. On a plain Linux host you cannot
bind a vsock listener as CID 16 (loopback is CID 1), so a true drop-in points the
API at the bridge instead. In order of preference:

- **Endpoint override (recommended).** ssh-cert-api reads `CERBERUS_SIGNER_ENDPOINT`
  (implemented on the cerberus `usbhsm-signer-endpoint` branch — `enclave/endpoint.go`):

  ```sh
  picosignet bridge --listen tcp:127.0.0.1:5000 &
  CERBERUS_SIGNER_ENDPOINT=tcp://127.0.0.1:5000 ssh-cert-api ...
  # or over a unix socket:
  picosignet bridge --listen unix:/run/PicoSignet.sock &
  CERBERUS_SIGNER_ENDPOINT=unix:///run/PicoSignet.sock ssh-cert-api ...
  ```

  Unset, ssh-cert-api behaves exactly as before (VSOCK CID 16) — the override is
  opt-in and transport-transparent (same framing/deadlines).

  Note: on a non-Nitro host, ssh-cert-api's startup `LoadKeySigner` also fetches
  AWS credentials from IMDS and starts a KMS VSOCK proxy. The PicoSignet device
  ignores the credentials, but those startup steps assume an EC2/Nitro
  environment; running fully off-Nitro may need them stubbed/skipped separately.

- Run the bridge inside a VM whose guest CID is set to 16 (no api change).
- `socat VSOCK-LISTEN:5000,fork TCP:127.0.0.1:5000` alongside `picosignet bridge
  --listen tcp:127.0.0.1:5000` (no api change).

Only enable `--allow-remote-mgmt` if you deliberately want provisioning over the
network; by default, `init`/`unlock`/`generateKey`/etc. are local-CLI only.

## 4. Verify end-to-end

```sh
picosignet self-test
# runs the on-device KATs (incl. the OTP-secret presence check) AND signs a
# throwaway key, verifying the certificate against the device CA with
# x/crypto/ssh.
```

A full client flow then looks like cerberus's: `ssh-cert-api` authenticates and
authorizes the user, calls the bridge with a `signSshKey` request, and returns
the certificate; the user drops it next to their key and SSHes in. The issued
certificate is byte-identical to one the enclave would have produced (proven by
`make test-diff`), so `ssh-keygen -L` and `sshd` accept it unchanged.

## Operational notes

- **Time**: the device has no RTC. If you run management commands without the
  bridge, `picosignet set-time` first, or signing fails closed. The bridge handles
  this automatically.
- **Reboots**: dev devices reload the key automatically; prod devices come up
  `prodLocked` and need `unlock` again.
- **Security posture at a glance**: `picosignet status` reports `otp secret`,
  `glitch det` (detectors armed), `secure boot` (enforcement burned), and warns
  if the last reset was a glitch-detector trigger.
- **Backups**: there is intentionally no key export, and key blobs are bound to
  the chip's OTP secret — a flash image is not a backup. To survive device
  loss, trust **two** CA public keys on your servers (`TrustedUserCAKeys`
  accepts multiple lines), one per device, and keep a spare device provisioned
  and stored securely.

## Status LED

The WS2812 on GPIO16 mirrors the device state machine, so the current state is
visible at a glance:

| LED | State |
|---|---|
| 🔵 blue | Uninitialized — freshly flashed; run `init` |
| ⚪ white | Busy — held while a request is handled (a prod Argon2id `unlock` visibly holds white ≈1.4 s) |
| 🟢 green | DevReady / ProdReady — initialized and unlocked, ready to sign |
| 🟠 amber | ProdLocked — production device; run `unlock` with the PIN |
| 🔴 red | LockedOut — too many failed PIN attempts |

**Off (no color)** means the application is not running — the board is in
BOOTSEL, or, after secure-boot lockdown (1c), the bootrom is refusing an
**unsigned** image. That is expected, not a brick: reflash the *signed* UF2
with `make flash-uf2-signed` (BOOTSEL via the BOOT button always works until
PICOBOOT is disabled in P5).
