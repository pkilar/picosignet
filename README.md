# PicoSignet

An RP2350-based USB security key that acts as an SSH certificate-signing HSM,
**drop-in wire-compatible** with the cerberus `ssh-cert-signer` (an AWS Nitro
Enclave service). The Ed25519 CA private key is generated **on the device** and
never leaves it — only the CA public key is exportable. The device answers the
exact same newline-delimited-JSON protocol cerberus `ssh-cert-api` already
speaks, so it is a hardware replacement for the enclave signer.

The build leans on the RP2350's security hardware: keys are generated from the
hardware TRNG, both wrapping keys are bound to a per-device secret locked in
on-die OTP (a flash chip-off dump alone cannot recover the CA key), voltage
glitch detectors are armed at boot, and production devices can burn signed-boot
enforcement so only project-signed firmware ever runs. Target board: Waveshare
RP2350-One (4 MiB flash, WS2812 status LED on GPIO16).

Two operating modes:

- **dev** — fully operational the moment it is plugged in (the CA key is
  wrapped under an OTP-bound device key; possession equals signing, but the
  key resists at-rest capture).
- **production** — the CA key is wrapped under an Argon2id(PIN) + OTP-bound
  key. The device must be unlocked with the PIN before it will sign. Wrong-PIN
  attempts are rate-limited and the device locks out (optionally wiping the
  key) after a configurable budget.

## Why

cerberus anchors trust in AWS Nitro Enclaves + KMS attestation. `PicoSignet` moves
that anchor onto a physical key you hold: the same short-lived, principal-scoped
SSH user certificates, signed by a CA whose private half is sealed in hardware.

## Architecture

```
   ┌────────────────────────── workstation / server ──────────────────────────┐
   │                                                                           │
   │   ssh-cert-api ──vsock/tcp/unix──▶ picosignet bridge ──USB CDC-ACM──▶ device  │
   │   (unmodified)    newline JSON      (Go, host/)     newline JSON  (RP2350) │
   │                                                                           │
   └───────────────────────────────────────────────────────────────────────────┘
```

- **`hsm-core`** — `no_std`+`alloc` Rust library holding *all* the logic: the
  protocol state machine, request validation (byte-compatible with cerberus),
  the OpenSSH certificate encoder, key wrapping, flash storage, the PIN counter,
  and the DRBG. Hardware lives behind traits (`EntropySource`, `Monotonic`,
  `FlashStore`), so the security-critical code is fully unit-tested on a
  workstation.
- **`hsm-fw`** — thin Embassy firmware for the RP2350 that supplies the real
  peripherals (USB CDC-ACM, QSPI flash, hardware TRNG, OTP device secret,
  glitch detectors, timer) and runs `hsm-core`'s dispatcher.
- **`hsm-sim`** — a host binary that runs `hsm-core` against an in-memory HAL
  over stdin/stdout, used by the differential test suite.
- **`host/`** — the Go `PicoSignet` tool: a bridge daemon (serial ↔ vsock/tcp/unix)
  and a provisioning/management CLI. Reuses cerberus's `messages` module for the
  signer-path wire types.

## Repository layout

| Path | Purpose |
|------|---------|
| `hsm-core/` | core library (protocol, crypto, storage, state machine) |
| `hsm-sim/` | stdin/stdout simulator |
| `hsm-fw/` | RP2350 Embassy firmware |
| `host/` | Go bridge + CLI (`PicoSignet`) |
| `tests/differential/` | Go suite: HSM certs round-tripped through `x/crypto/ssh` |
| `tests/golden/` | deterministic golden-vector certs verified with `ssh-keygen -L` |
| `tests/hil/` | hardware-in-the-loop end-to-end script |
| `docs/` | `PROTOCOL.md`, `FLASH_LAYOUT.md`, `THREAT_MODEL.md`, `PROVISIONING.md` |

## Build & test

```sh
make test         # hsm-core unit + golden tests on the host
make build-fw     # cross-build the RP2350 firmware (release)
make go-test      # Go bridge/CLI vet + tests
make test-diff    # differential: every HSM cert == x/crypto/ssh re-marshal
make uf2          # produce an (unsigned) UF2 for BOOTSEL flashing
make uf2-signed   # signed UF2 + boot-key OTP JSON (production secure boot)
make flash-uf2    # flash over picoboot (device in BOOTSEL)
make flash        # flash an attached probe via probe-rs
make hil          # full dev+prod flow on a real device (see tests/hil)
```

Toolchain: stable Rust with the `thumbv8m.main-none-eabihf` target, Go 1.26+,
`picotool` (UF2 conversion, signing, OTP provisioning), and (for the golden/HIL
checks) `ssh-keygen`.

## Quick start (hardware)

```sh
# 1. Flash the firmware (BOOTSEL: hold BOOTSEL, plug in, copy the UF2).
make uf2 && cp target/thumbv8m.main-none-eabihf/release/hsm-fw.uf2 /run/media/$USER/RP2350/

# 2. Provision a dev key and export the CA public key.
picosignet init
picosignet generate-key
picosignet pubkey > cerberus-ca.pub

# 3. Trust the CA on your SSH servers.
#    /etc/ssh/sshd_config:  TrustedUserCAKeys /etc/ssh/cerberus-ca.pub

# 4. Run the bridge so ssh-cert-api can use the device.
picosignet bridge --listen tcp:127.0.0.1:5000

# 5. Confirm everything end-to-end.
picosignet self-test
```

For production mode (`picosignet init --prod`), the secure-boot lockdown runbook,
and deployment details, see `docs/PROVISIONING.md`. For what the RP2350
security hardware does and does not buy (OTP-bound keys, glitch detectors,
signed boot — and the honest residual risks), see `docs/THREAT_MODEL.md`.

## Compatibility

The signer-path protocol (`signSshKey`, `ping`, `loadKeySigner`,
`getEnclaveMetrics`) is byte-compatible with cerberus `messages`. The device
adds an `hsm` management envelope for provisioning; Go's `encoding/json` ignores
it on the signer side, so the variant is additive and safe. The differential
suite proves every issued certificate is byte-identical to one
`golang.org/x/crypto/ssh` would marshal. See `docs/PROTOCOL.md` for the full
wire spec and the handful of documented divergences.
