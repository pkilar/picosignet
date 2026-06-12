# Flash layout

The last six 4 KiB sectors of the Pico's 2 MiB QSPI flash hold persistent HSM
state. `memory.x` carves them out of the firmware's `FLASH` region so code can
never grow into them — the linker errors if the binary exceeds the firmware
region, a hard ceiling protecting the key.

| Region | Offset | Size | Contents |
|--------|--------|------|----------|
| BOOT2 | `0x000000` | 256 B | second-stage bootloader (provided by embassy-rp) |
| Firmware (XIP) | `0x000100` | ~1.99 MiB | code + rodata, ends at `0x1FA000` |
| CONFIG_A | `0x1FA000` | 4 KiB | device config record |
| CONFIG_B | `0x1FB000` | 4 KiB | redundant config copy |
| KEY_A | `0x1FC000` | 4 KiB | wrapped CA key record |
| KEY_B | `0x1FD000` | 4 KiB | redundant key copy |
| PIN_COUNTER | `0x1FE000` | 4 KiB | PIN attempt tick log |
| RESERVED | `0x1FF000` | 4 KiB | future (RP2350 OTP shadow, audit log) |

Current firmware footprint is ≈188 KiB of the ~2 MiB firmware region.

## Record format (CONFIG / KEY)

A/B pairs give power-fail safety. Each record:

```
magic "UHSM" (u32) | version (u16) | seq (u32) | payload_len (u16) | payload | crc32 (u32)
```

- **Read**: parse both copies; pick the highest `seq` whose CRC validates. A torn
  write leaves the older valid copy intact.
- **Write**: `seq = max(existing)+1`, written to the *lower-seq* copy, so the most
  recent good record survives until the new write completes.
- CRC-32 (ISO-HDLC) over everything preceding the CRC.

### DeviceConfig payload

`mode (u8: 0=dev,1=prod) | argon2 m_cost (u32, KiB) | t_cost (u32) | parallelism
(u8) | salt[16] | max_retries (u8) | wipe_on_lockout (u8) | fw_version[3]`.

### KeyBlob payload

`wrap_type (u8: 1=devKEK, 2=pinKEK) | aead_nonce[12] | pubkey[32] | ciphertext[32]
| tag[16]`.

- `pubkey` is stored **in the clear** so `getPublicKey` works while locked.
- `ciphertext` is the 32-byte Ed25519 seed, AEAD-sealed with ChaCha20-Poly1305.
- AEAD AAD = `wrap_type ‖ pubkey`, so a blob cannot be presented under a
  different wrap type or paired with a different public key.

## Key wrapping

- **dev**: `KEK = HKDF-SHA256(flash unique id, "usbhsm-dev-kek-v1")`. Obfuscation
  only — anyone who can read the flash can also read the unique id. Documented as
  such; dev mode is for convenience, not protection.
- **prod**: `KEK = Argon2id(PIN, salt, m=64 KiB, t=tuned, p=1)`. PIN correctness
  *is* the AEAD tag check — there is no separate verifier that would offer a
  faster brute-force oracle. The 64 KiB memory parameter is an RP2040 RAM
  constraint; pair it with a strong passphrase (see `THREAT_MODEL.md`).

## PIN attempt counter

The `PIN_COUNTER` sector is a bit-clear tick log: erased (`0xFF`) means zero
attempts; each attempt programs the next byte toward `0x00`. A correct unlock
erases the sector. A byte counts as a used attempt as soon as it leaves `0xFF`,
so a half-completed (power-glitched) tick still counts — **fail-closed**. The
tick is written and confirmed *before* the KEK is derived, so a glitch during
verification always costs an attempt; it cannot be used to brute-force the PIN
for free. Up to 4096 attempts fit per erase, far above any sane `max_retries`.

NOR note: every tick for counts < 256 lands in page 0, programmed incrementally
(only ever clearing fresh bits, never re-programming a byte). The Pico's
W25Q-class flash permits this.
