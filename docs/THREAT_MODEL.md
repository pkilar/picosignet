# Threat model

`PicoSignet` moves the SSH CA trust anchor from an AWS Nitro Enclave onto a physical
RP2350 key. The RP2350 provides a **hardware TRNG, signed boot, on-die OTP with
per-page access control, and voltage-glitch detectors** — this document states
what the design does with each, and just as plainly what it still does not
protect against.

## Asset

The Ed25519 CA private key (a 32-byte seed). It is generated on-device and only
ever exists off-device as ciphertext. Compromise of this key lets an attacker
mint SSH user certificates trusted by every server that trusts the CA.

## Security architecture in one paragraph

A 32-byte **device secret** is generated on first boot from the health-checked
TRNG and burned into an on-die OTP page that is then permanently locked:
secure firmware may read it, the bootloader/picotool may not, and nobody can
ever write it again. At every boot the firmware copies it to RAM and SW-locks
the page until the next reset. Both wrapping keys are bound to it — dev:
`HKDF(OTP secret)`; prod: `HKDF(salt = OTP secret, ikm = Argon2id(PIN))` — so
the AEAD-sealed seed stored in external QSPI flash is cryptographically tied to
this physical chip. Production devices additionally burn `SECURE_BOOT_ENABLE`
so only firmware signed with the project boot key ever runs (see
`PROVISIONING.md`), and the voltage-glitch detectors are armed at every boot
(optionally force-armed from boot ROM).

## Protected against

- **Remote / software attackers.** The private key never crosses USB. Only
  signed certificates and the CA *public* key are emitted. A compromised host
  can ask the device to sign, but cannot extract the key. Blast radius is
  bounded by short certificate validity (≤24 h) and host-side
  authorization/audit.
- **Flash chip-off / dump — both modes.** The QSPI flash is external and always
  dumpable, but a dump alone is now useless: the KEK is bound to the OTP device
  secret inside the RP2350 die. There is nothing to brute-force offline without
  first extracting the OTP secret from the chip — so offline Argon2id PIN
  grinding against a flash image is impossible, and even dev mode resists
  at-rest capture.
- **Stolen production device.** Signing requires the PIN. PIN correctness is
  the AEAD tag check (no faster oracle); each *online* guess costs a full
  Argon2id pass (m = 256 KiB, t tuned to ≈1 s on-device). `factoryReset` and
  `rebootBootloader` require the same PIN (or an explicit `force`, for a
  forgotten PIN) once a device is `prodLocked`/`prodReady`/`lockedOut` — USB or
  physical possession of a locked device no longer suffices on its own to
  destroy the CA key or force the device into the USB bootloader.
- **Online PIN brute force.** The retry counter is persisted *before* each
  verification (anti power-glitch), failures back off exponentially
  (`min(250 ms·2^n, 30 s)`), and the device locks out after `maxRetries`
  (default 10), optionally wiping the key. Lockout survives reboot; only
  `factoryReset` (key destruction) escapes. The backoff itself is enforced as a
  gate keyed off the *persisted* attempt count and the monotonic timer's
  reading *since boot* — not a blocking sleep — so power-cycling the device
  between guesses restarts the same wait from zero rather than skipping it.
- **Malicious firmware reflash (production, after the P4 burn).** With
  `SECURE_BOOT_ENABLE` burned, the bootrom refuses any image not signed with
  the project boot key. An attacker can no longer flash key-exfiltrating
  firmware and wait for a legitimate unlock. Before the burn, `rebootBootloader`
  requiring the PIN (see above) also narrows who can force a device into the
  bootloader in the first place — not just whoever can reach the BOOTSEL
  button, but whoever can reach it *and* prove PIN knowledge (or use `force`).
- **Power-glitch retry-counter bypass.** A tick that is interrupted mid-program
  still counts, and the tick is confirmed before the KEK is derived. Glitching
  costs an attempt rather than granting a free one.
- **Voltage fault injection (raised bar).** The glitch detectors are armed and
  config-locked at every boot (sensitivity 2/3); a trigger hard-resets the
  switched-core power domain with no software in the loop. `status` reports
  `glitchArmed` and whether the last reset was a glitch trigger. Production
  provisioning can force-arm them from boot ROM (`CRIT1.GLITCH_DETECTOR_*`).
- **Blob/config tampering & swapping.** The AEAD AAD binds the wrapped seed to
  its wrap type and public key. A/B records are CRC-protected with sequence
  numbers. Legacy v1 key blobs (the earlier wrap format without the OTP
  binding) are rejected outright.
- **Entropy failure at key generation.** Raw TRNG output (hardware
  post-processing bypassed on purpose) is health-checked (repetition-count +
  adaptive-proportion) before seeding/keygen; a stuck or biased source yields
  `ERR_ENTROPY` and refuses to generate a key. The OTP device secret itself is
  drawn through the same checked, SHA-512-conditioned path.

## NOT protected against

- **The pre-burn window.** Until `SECURE_BOOT_ENABLE` is burned (production
  stage P4), *any* firmware runs as "secure" and could read the OTP secret
  before our lock-on-boot lands. Development devices therefore get chip-off
  protection but **not** malicious-reflash protection. This is the explicit
  trade for keeping dev boards freely reflashable; the production runbook
  closes it.
- **Determined silicon-level attackers.** The RP2350 security model has been
  publicly dented: the 2024 hacking challenge and follow-up work demonstrated
  OTP secret extraction via voltage/EM fault injection and laser probing
  (e.g. the USB-bootloader glitch and IOActive's laser work). The glitch
  detectors raise the cost of the voltage-glitch class; they do not stop a lab
  with a decapping bench. This is a hobby-grade die, not a certified secure
  element — treat the OTP binding as a strong deterrent, not an absolute.
- **Host compromise while unlocked.** Once a production device is unlocked, a
  compromised host can request signatures until it is re-locked or unplugged.
  Mitigate with short validity, host-side rate limiting and audit, and locking
  the device when idle (`picosignet lock`). `setTime` cannot be abused to
  widen this window: it is bounded (a plausible first value per boot session,
  ±15 minutes of the tracked time thereafter), so a compromised host can't
  march the clock forward to pre-mint certificates dated outside their true
  issuance window — but it can still request certificates at the *actual*
  current time for as long as it holds an unlocked session.
- **RAM scraping by code already running on the device.** The OTP secret and
  (while unlocked) the CA seed live in SRAM. With secure boot burned, "code
  already running" means our signed firmware — but a signing-key compromise or
  a firmware bug is still game over. Keep the boot key offline.
- **Possession of an unlocked/dev device.** Dev mode signs for whoever holds
  it; that is its purpose. Production mode re-locks on USB reset/suspend.
- **PIN-counter rollback by flash chip-off (bounded).** The retry counter
  lives in external flash; an attacker who desolders and rewrites it can reset
  the *online* attempt budget — but each attempt still costs a full Argon2id
  pass against an OTP-bound KEK on the real device, with backoff. The lockout
  is a rate limiter, not the cryptographic boundary.
- **Supply-chain / board-level implants.** Out of scope.

## Deliberately out of scope (and why)

- **TrustZone secure/non-secure partitioning.** The firmware runs as a single
  Secure-world image. The enforced boundary in this design is *secure boot +
  OTP page permissions vs. the (non-secure) bootloader and PICOBOOT* — there is
  no untrusted code on the device to wall off, so an S/NS split would add an
  unmaintained trust boundary with nothing behind it.
- **Encrypted boot.** The firmware is open source; the image holds no secrets
  (the key material is in OTP and wrapped flash records). Nothing to hide.
- **RCP (redundancy coprocessor) hardening.** Used by the pico-sdk's secure
  boot path; no usable Rust toolchain support today. Revisit if it lands.

## Trust assumptions

- The provisioning workstation is trusted at `init`/`generateKey` time (it sees
  the PIN you type and the CA public key, never the private key).
- The boot signing key (`keys/picosignet-boot.pem`) is generated and stored
  offline; after the P4 burn it is the root of the device's code-integrity
  story (and losing it bricks updates).
- The USB host is trusted to the extent that it can request signatures; it is
  not trusted with key material (which it never receives).

## Recommended posture

- Production mode + a strong passphrase for any device that leaves a controlled
  environment; run the full provisioning runbook (P1–P4, and P5 hardening as
  appropriate) on production units.
- `wipeOnLockout` enabled where re-provisioning is acceptable and key
  confidentiality outweighs availability.
- Short certificate validity and host-side authorization/audit (cerberus
  `ssh-cert-api` already provides Kerberos + Casbin).
- Treat the device as single-purpose: do not run other firmware on it.
- Keep two offline copies of the boot signing key; verify them before P4.
