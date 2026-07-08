# Flash & OTP layout

Persistent HSM state lives in two places on the Waveshare RP2350-One:

- the last six 4 KiB sectors of the 4 MiB **QSPI flash** (records below) —
  external, dumpable, holds only ciphertext and public data;
- two pages of the RP2350's on-die **OTP** — holds the per-device wrapping
  secret that makes the flash records chip-bound.

`memory.x` carves the HSM sectors out of the firmware's `FLASH` region so code
can never grow into them — the linker errors if the binary exceeds the firmware
region, a hard ceiling protecting the key.

## QSPI flash (4 MiB)

| Region         | Offset     | Size      | Contents                                                         |
| -------------- | ---------- | --------- | ---------------------------------------------------------------- |
| Firmware (XIP) | `0x000000` | ~3.98 MiB | vector table, IMAGE_DEF block, code + rodata; ends at `0x3FA000` |
| CONFIG_A       | `0x3FA000` | 4 KiB     | device config record                                             |
| CONFIG_B       | `0x3FB000` | 4 KiB     | redundant config copy                                            |
| KEY_A          | `0x3FC000` | 4 KiB     | wrapped CA key record                                            |
| KEY_B          | `0x3FD000` | 4 KiB     | redundant key copy                                               |
| PIN_COUNTER    | `0x3FE000` | 4 KiB     | PIN attempt tick log                                             |
| RESERVED       | `0x3FF000` | 4 KiB     | future (audit log)                                               |

There is no BOOT2 second-stage bootloader: the RP2350 bootrom boots directly
from the `IMAGE_DEF` metadata block (`.start_block`, placed right after the
vector table inside the first 4 KiB). Current firmware footprint is ≈190 KiB.

## Record format (CONFIG / KEY)

A/B pairs give power-fail safety. Each record:

```
magic "UHSM" (u32) | version (u16=2) | seq (u32) | payload_len (u16) | payload | crc32 (u32)
```

- **Read**: parse both copies; pick the highest `seq` whose CRC validates. A torn
  write leaves the older valid copy intact.
- **Write**: `seq = max(existing)+1`, written to the *lower-seq* copy, so the most
  recent good record survives until the new write completes.
- CRC-32 (ISO-HDLC) over everything preceding the CRC.
- The schema `version` is **2**. v1 (which stored the Argon2 salt in the config
  record) is rejected by the version check.

### DeviceConfig payload

`mode (u8: 0=dev,1=prod) | argon2 m_cost (u32, KiB) | t_cost (u32) | parallelism
(u8) | max_retries (u8) | wipe_on_lockout (u8) | fw_version[3]`.

### KeyBlob payload

`wrap_type (u8: 3=devKEK, 4=pinKEK) | aead_nonce[12] | pubkey[32] | ciphertext[32]
| tag[16] | salt[16]`.

- `pubkey` is stored **in the clear** so `getPublicKey` works while locked.
- `ciphertext` is the 32-byte Ed25519 seed, AEAD-sealed with ChaCha20-Poly1305.
- `salt` is the Argon2 salt that derives the prod KEK (zero for dev wraps). It
  lives **in the key record, not the config**, so a PIN rotation rewrites a
  single atomic record: the wrapped seed and the salt needed to unwrap it can
  never be torn apart across a power loss (which previously could strand the CA
  key under a salt the active config no longer held).
- AEAD AAD = `wrap_type ‖ pubkey`, so a blob cannot be presented under a
  different wrap type or paired with a different public key. A tampered `salt`
  simply yields the wrong KEK, so the tag check fails.
- Wrap types 1/2 were the earlier v1 wraps without the OTP binding; the
  parser rejects them.

## OTP allocation (on-die, 64 pages × 64 ECC rows × 16 data bits)

| Rows (ECC space)  | Page | Name                                                                                                                                      | Written by                                 |
| ----------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `0x000–0x003`     | 0    | CHIPID (factory) — feeds `unique_id()` / the `serial` field                                                                               | factory                                    |
| `0x040`           | 1    | CRIT1: `SECURE_BOOT_ENABLE` bit0, `DEBUG_DISABLE` bit2, `GLITCH_DETECTOR_ENABLE` bit4, `GLITCH_DETECTOR_SENS` bits5–6 (raw, 8× redundant) | picotool, production runbook               |
| `0x048` / `0x04B` | 1    | BOOT_FLAGS0 (`DISABLE_BOOTSEL_USB_PICOBOOT_IFC`) / BOOT_FLAGS1 (`KEY_VALID`)                                                              | picotool, production runbook               |
| `0x080–0x08F`     | 2    | BOOTKEY0 = SHA-256 of the secp256k1 boot public key                                                                                       | picotool via the seal-generated OTP JSON   |
| `0xF00–0xF11`     | 60   | **device secret, slot B (fallback)**: rows 0–15 secret (32 B), row 16 marker `0xA5C3`, row 17 void `0xDEAD`                               | firmware, first boot                       |
| `0xF40–0xF51`     | 61   | **device secret, slot A (primary)**: same layout                                                                                          | firmware, first boot                       |
| `0xFF9` / `0xFFB` | 63   | PAGE60_LOCK1 / PAGE61_LOCK1 = `0x3D3D3D`                                                                                                  | firmware, right after a verified provision |

### Device-secret lifecycle (`hsm-fw/src/otp_secret.rs`)

- **First boot**: 32 bytes drawn through the health-checked, SHA-512-conditioned
  DRBG (never raw TRNG); each ECC row written and read-back-verified; the
  validity marker written **last** so a torn provisioning never looks valid;
  then the page hard-locked. A failed slot is voided (`0xDEAD`) and the
  fallback page used — worst case wastes 2 of 64 pages, never bricks.
- **Hard lock** (`PAGEn_LOCK1 = 0x3D3D3D`, 3-byte majority): byte `0x3D` =
  Secure **read-only**, Non-secure **inaccessible**, Bootloader
  **inaccessible**. picotool/PICOBOOT can never read or write the page again.
- **Every boot**: the secret is copied to RAM, then the page's `SW_LOCK`
  register is set to inaccessible (writes OR — can only tighten) until the next
  reset, so even secure-world code cannot re-read the page mid-session.
- **Fail closed**: no valid slot ⇒ `device_secret()` errors, every KEK
  operation returns `ERR_INTERNAL`, and `status` reports `otpSecret: false`.

## Key wrapping

- **dev**: `KEK = HKDF-SHA256(OTP secret, info = "usbhsm-dev-kek-v2")`. At rest
  this is as strong as the OTP secret; possession of a running device still
  equals signing (dev mode has no PIN by design).
- **prod**: `KEK = HKDF-SHA256(salt = OTP secret, ikm = Argon2id(PIN, salt16,
  m = 256 KiB, t = tuned, p = 1), info = "usbhsm-prod-kek-v2")`. PIN correctness
  *is* the AEAD tag check — no separate verifier exists that would offer a
  faster brute-force oracle. An offline attacker with a flash dump but no OTP
  secret has nothing to grind against.

## PIN attempt counter

The `PIN_COUNTER` sector is a bit-clear tick log: erased (`0xFF`) means zero
attempts; each attempt programs the next byte toward `0x00`. A correct unlock
erases the sector. A byte counts as a used attempt as soon as it leaves `0xFF`,
so a half-completed (power-glitched) tick still counts — **fail-closed**. The
tick is written and confirmed *before* the KEK is derived, so a glitch during
verification always costs an attempt; it cannot be used to brute-force the PIN
for free. Up to 4096 attempts fit per erase, far above any sane `max_retries`.

The exponential backoff between attempts (`min(250 ms·2^n, 30 s)`) is enforced
as a gate read from this same persisted count, checked against the monotonic
timer's reading *since boot* — not a blocking sleep. A blocking sleep is
trivially defeated by power-cycling the device mid-wait; reading the gate from
flash means a reset just restarts the same wait from zero instead of skipping
it, and keeps every response fast enough that a shared serial transport's read
timeout never trips mid-backoff.

NOR note: every tick for counts < 256 lands in page 0, programmed incrementally
(only ever clearing fresh bits, never re-programming a byte). The W25Q-class
flash permits this.
