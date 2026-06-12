# Threat model

`usbhsm` moves the SSH CA trust anchor from an AWS Nitro Enclave onto a physical
RP2040 key. This document states honestly what that does and does not protect
against. The RP2040 has **no hardware TRNG, no secure boot, no OTP, and an
externally readable QSPI flash** — so the guarantees are weaker than a certified
HSM, and we say so plainly.

## Asset

The Ed25519 CA private key (a 32-byte seed). It is generated on-device and only
ever exists off-device as ciphertext. Compromise of this key lets an attacker
mint SSH user certificates trusted by every server that trusts the CA.

## Protected against

- **Remote / software attackers.** The private key never crosses USB. Only signed
  certificates and the CA *public* key are emitted. A compromised host can ask
  the device to sign, but cannot extract the key. Blast radius is bounded by
  short certificate validity (≤24 h) and host-side authorization/audit.
- **Stolen device, flash dump — production mode.** The seed is AEAD-sealed under
  `Argon2id(PIN)`. A flash image alone is useless without the PIN. PIN
  correctness is the AEAD tag check (no faster oracle).
- **Online PIN brute force.** The retry counter is persisted *before* each
  verification (anti power-glitch), failures back off exponentially
  (`min(250 ms·2^n, 30 s)`), and the device locks out after `maxRetries`
  (default 10), optionally wiping the key. Lockout survives reboot; only
  `factoryReset` (key destruction) escapes.
- **Power-glitch retry-counter bypass.** A tick that is interrupted mid-program
  still counts (a byte that has left `0xFF` is a used attempt), and the tick is
  confirmed before the KEK is derived. Glitching therefore costs an attempt
  rather than granting a free one.
- **Blob/config tampering & swapping.** The AEAD AAD binds the wrapped seed to its
  wrap type and public key. A/B records are CRC-protected with sequence numbers.
- **Entropy failure at key generation.** Raw ROSC entropy is health-checked
  (repetition-count + adaptive-proportion) before seeding/keygen; a stuck or
  grossly biased source yields `ERR_ENTROPY` and refuses to generate a key.

## NOT protected against (RP2040 limitations)

- **Offline PIN brute force against a flash dump.** With the flash image, an
  attacker can run `Argon2id` guesses offline. The memory parameter is only
  64 KiB (RP2040 RAM), so this is far weaker than a server-grade KDF. **Mitigation:
  use a high-entropy passphrase, not a short numeric PIN.** A 6-word diceware
  passphrase is recommended for any device that could be physically captured.
- **Malicious firmware reflash.** The RP2040 has no secure boot. An attacker with
  physical access can hold BOOTSEL and flash arbitrary firmware — e.g. firmware
  that exfiltrates the key after a legitimate unlock. There is no defense on
  RP2040; the RP2350 build (future) adds signed boot and OTP to close this.
- **Invasive/silicon attacks.** Decapping, fault injection beyond the modeled
  power-glitch, side-channel extraction of the key during signing. Out of scope
  for a hobby-grade MCU.
- **Host compromise while unlocked.** Once a production device is unlocked, a
  compromised host can request signatures until it is re-locked or unplugged.
  Mitigate with short validity, host-side rate limiting and audit, and locking
  the device when idle (`usbhsm lock`).
- **Dev mode at rest.** The dev-mode wrapping key is derived from the chip unique
  id, which is in the same flash dump. Dev mode is **not** confidential; use it
  only where physical capture is not in scope.

## Trust assumptions

- The provisioning workstation is trusted at `init`/`generateKey` time (it sees
  the PIN you type and could observe the CA public key, but never the private
  key).
- The USB host is trusted to the extent that it can request signatures; it is not
  trusted with the key material (which it never receives).

## Recommended posture

- Production mode + a strong passphrase for any device that leaves a controlled
  environment.
- `wipeOnLockout` enabled where re-provisioning is acceptable and key
  confidentiality outweighs availability.
- Short certificate validity and host-side authorization/audit (cerberus
  `ssh-cert-api` already provides Kerberos + Casbin).
- Treat the device as single-purpose: do not run other firmware on it.
- Plan to migrate to RP2350 for secure boot + OTP if the physical-attacker class
  matters.
