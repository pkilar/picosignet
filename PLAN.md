# usbhsm — USB HSM for SSH Certificate Signing (original implementation plan)

> **Superseded note (2026-06-12, v0.3.0):** the project is now **RP2350-only**.
> RP2040 support was removed entirely in favor of the RP2350's security
> hardware: hardware TRNG, a per-device wrapping secret locked in on-die OTP
> (both KEKs bound to it — flash dumps alone are useless), voltage-glitch
> detectors armed at boot, and a gated production secure-boot pipeline
> (`scripts/provision_production.sh`). Target board: Waveshare RP2350-One.
> See `docs/THREAT_MODEL.md` and `docs/FLASH_LAYOUT.md` for the current
> design. The plan below is the original RP2040 (v0.1–v0.2) record; its
> RP2040-specific sections are historical.

## Context

The cerberus project signs short-lived SSH user certificates inside an AWS Nitro Enclave (`ssh-cert-signer`), with the CA key KMS-sealed and attestation-gated. This project replaces that cloud trust anchor with a physical one: an RP2040-based USB key that generates an Ed25519 CA key **on the device**, never exports the private key (only the public key), and answers the **exact same newline-delimited-JSON protocol** so existing cerberus clients (`ssh-cert-api`) work unmodified. Two modes: **dev** (operational at plug-in) and **production** (CA key wrapped under a PIN-derived KEK; device must be unlocked before it signs).

**Confirmed decisions**: Rust + Embassy firmware; RP2040 first with code structured for a later RP2350 build (feature flag); Ed25519-only CA; PIN/passphrase unlock over serial.

## Wire-compatibility contract (verified against cerberus source)

Ground-truth files (re-read during implementation):
- `/home/pkilar/Devel/cerberus/messages/messages.go` — wire types to mirror field-for-field
- `/home/pkilar/Devel/cerberus/ssh-cert-signer/cmd/ssh-cert-signer/main.go` — framing (1 JSON object + `\n` per message), 256 KiB max request, 32 conns, 5 s deadlines, top-level `{"error":"…"}` routing for ALL failures
- `/home/pkilar/Devel/cerberus/ssh-cert-signer/internal/handlers/sign-public-key.go` — validation order + exact error strings, cert population
- `/home/pkilar/Devel/cerberus/ssh-cert-api/internal/enclave/client.go` — client dials VSOCK CID 16 port 5000 per request, 30 s deadline
- `/home/pkilar/Devel/cerberus/constants/constants.go` — `EnclaveCID=16`, `EnclaveListeningPort=5000`

Must replicate exactly:
- **Envelope**: Request = exactly one of `loadKeySigner` | `signSshKey` | `ping` | `getEnclaveMetrics` (we add a 5th additive `hsm` variant — safe, Go ignores unknown fields). Response = `loadKeySigner` | `error` (top-level string) | `signSshKey` | `pong` | `enclaveMetrics`.
- **signSshKey request**: `ssh_key` (bare authorized_keys, reject options/trailing data), `key_id`, `principals` (1..100, none blank), `validity` (Go duration string, >0, ≤24h), `permissions`/`custom_attributes` (merge → Extensions; key collision rejected), `critical_options`.
- **Validation order & error strings** (parity goal): empty-field checks → `time.ParseDuration` → principals checks → permissions∩custom_attributes → `ParseAuthorizedKey` → options/trailing-data → key algo (RSA 2048–8192, ECDSA P-256/384/521, Ed25519) → duration >0 → ≤24h.
- **Cert population**: Nonce=32 rand bytes; Serial=random u64; CertType=UserCert always; KeyId/principals from request; ValidAfter = now−300; ValidBefore = now+validity; Extensions = permissions ∪ custom_attributes; CriticalOptions from request. Response: `{"signSshKey":{"signed_key":"<TrimSpace'd single-line OpenSSH cert>"}}`.
- **ping** → `{"pong":{"signerLoaded":bool}}` where signerLoaded = (DevReady|ProdReady) ∧ keyPresent ∧ clockSet.
- **loadKeySigner** → `{"loadKeySigner":{"success":true}}` if signer available, else top-level error mirroring cerberus phrasing ("CA signer is not initialized…"). AWS credentials ignored.
- **getEnclaveMetrics** → same JSON shape (`cpu` floats, `memory` uint64s) with device-meaningful values (heap stats, zeros/uptime for CPU).

## Architecture & repo layout

```
usbhsm/
├── Cargo.toml                # workspace: hsm-core, hsm-sim, hsm-fw (fw built via --target thumbv6m-none-eabi)
├── rust-toolchain.toml       # pinned stable + thumbv6m-none-eabi
├── .cargo/config.toml        # runner = probe-rs / elf2uf2-rs
├── Makefile                  # build-fw, flash, test, test-diff, hil
├── .github/workflows/ci.yml  # fmt, clippy, host tests, fw cross-build, Go vet/test
├── hsm-core/                 # no_std+alloc lib — ALL logic, host-testable
│   └── src/: lib.rs, hal.rs (EntropySource/Monotonic/FlashStore traits),
│       proto/{mod,signer,hsm}.rs, dispatch.rs (process_line entry point),
│       state.rs, validate.rs, goduration.rs, cert.rs, sshwire.rs (fallback),
│       keys.rs, wrap.rs, storage.rs, pin.rs, rng.rs, clock.rs, metrics.rs
├── hsm-sim/                  # std bin: hsm-core + mock HAL on stdin/stdout
│                             # flags: --deterministic-rng, --state-file, --fixed-time
├── hsm-fw/                   # thin Embassy RP2040 binary
│   └── src/: main.rs, usb.rs (CDC-ACM), lineio.rs (16 KiB line assembler),
│       flash_hal.rs, entropy_hal.rs, time_hal.rs; memory.x (last 24 KiB carved out)
├── host/                     # Go module github.com/pkilar/usbhsm/host — single `usbhsm` binary
│   ├── cmd/usbhsm/main.go
│   └── internal/: device/ (serial discovery + mutex RoundTrip),
│       hsmproto/ (Go mirror of hsm envelope), bridge/ (vsock/tcp/unix listeners),
│       cli/ (init, generate-key, pubkey, unlock, lock, status, set-time,
│             change-pin, factory-reset, self-test, add-entropy, bridge)
├── tests/golden/             # fixed-seed certs verified via ssh-keygen -L
├── tests/differential/       # Go: hsm-sim vs x/crypto/ssh field-level comparison
├── tests/hil/run.sh          # real-hardware end-to-end
└── docs/: PROTOCOL.md, FLASH_LAYOUT.md, THREAT_MODEL.md, PROVISIONING.md
```

Key reuse: host Go module imports `github.com/pkilar/cerberus/messages` for signer-path types (with optional local `replace => ../../cerberus`); `mdlayher/vsock` for the bridge; `go.bug.st/serial` for the device; `golang.org/x/crypto/ssh` + `x/term` for self-test and PIN prompts.

## HSM management envelope (additive `hsm` request variant)

Management errors return INSIDE the hsm response (`{"hsm":{"error":{"code":"ERR_*","message":"…",…}}}`); signer-path errors stay top-level. Codes: ERR_BAD_REQUEST, ERR_ALREADY_INIT, ERR_NOT_INIT, ERR_NO_KEY, ERR_KEY_EXISTS, ERR_LOCKED, ERR_BAD_PIN, ERR_LOCKED_OUT, ERR_CLOCK_UNSET, ERR_BAD_MODE, ERR_ENTROPY, ERR_FLASH, ERR_OVERSIZE, ERR_BUSY, ERR_INTERNAL.

| Command | Request | Success response |
|---|---|---|
| init | `{"hsm":{"init":{"mode":"dev"}}}` / `{"hsm":{"init":{"mode":"prod","pin":"…","maxRetries":10,"wipeOnLockout":false}}}` (pin 6–64 bytes) | `{"hsm":{"init":{"ok":true,"mode":"prod"}}}` |
| generateKey | `{"hsm":{"generateKey":{"force":false}}}` | `{"hsm":{"generateKey":{"ok":true,"publicKey":"ssh-ed25519 AAAA… usbhsm-ca"}}}` |
| getPublicKey | `{"hsm":{"getPublicKey":{}}}` | `{"hsm":{"getPublicKey":{"publicKey":"…"}}}` (works while ProdLocked — pubkey stored plaintext) |
| unlock | `{"hsm":{"unlock":{"pin":"…"}}}` | `{"hsm":{"unlock":{"ok":true}}}`; fail → error with `remainingAttempts`, `backoffMs` |
| lock | `{"hsm":{"lock":{}}}` | `{"hsm":{"lock":{"ok":true}}}` |
| setTime | `{"hsm":{"setTime":{"unixSeconds":N}}}` | `{"hsm":{"setTime":{"ok":true,"uptimeMs":…,"previousSet":bool}}}` |
| status | `{"hsm":{"status":{}}}` | state, mode, keyPresent, unlocked, clockSet, unixSeconds, uptimeMs, retryRemaining, fwVersion, serial, heapFreeBytes |
| changePin | `{"hsm":{"changePin":{"currentPin":"…","newPin":"…"}}}` | `{"hsm":{"changePin":{"ok":true}}}` (counts as retry attempt) |
| addEntropy | `{"hsm":{"addEntropy":{"hex":"…"}}}` (≤1024 B) | ok (hashed into pool, never sole source) |
| selfTest | `{"hsm":{"selfTest":{}}}` | per-test pass/fail: ed25519Kat, sha2Kat, aeadKat, drbgHealth, flashCrc |
| factoryReset | `{"hsm":{"factoryReset":{"confirm":"ERASE"}}}` | ok — erases key+config+counter → Uninitialized |

`signSshKey` with clock unset fails closed: top-level `{"error":"device clock not set; send hsm.setTime first"}`.

## Device state machine

States: `Uninitialized`, `DevReady`, `ProdLocked`, `ProdReady`, `LockedOut`.

- Uninitialized —init(dev)→ DevReady; —init(prod,pin)→ ProdLocked
- ProdLocked —unlock(ok)→ ProdReady (counter reset, seed decrypted to RAM); —unlock(bad)→ ProdLocked or LockedOut (pre-ticked counter; wipeOnLockout ⇒ key erased)
- ProdReady —lock / USB reset / suspend→ ProdLocked (RAM seed zeroized)
- LockedOut —factoryReset→ Uninitialized (only escape)
- Boot: config=dev→DevReady; prod→ProdLocked (LockedOut if counter exhausted); none→Uninitialized
- Always allowed: ping, getEnclaveMetrics, status, setTime, selfTest, addEntropy. getPublicKey: any state with key. sign/loadKeySigner: DevReady|ProdReady + key + clock. dev↔prod mode change ONLY via factoryReset (one-way, key destroyed).

## Flash layout & key protection (2 MB flash, 4 KiB sectors)

| Region | Offset | Size |
|---|---|---|
| Firmware (XIP) | 0x000000 | 0x1FA000 |
| CONFIG_A / CONFIG_B | 0x1FA000 / 0x1FB000 | 4 KiB each |
| KEY_A / KEY_B | 0x1FC000 / 0x1FD000 | 4 KiB each |
| PIN_COUNTER | 0x1FE000 | 4 KiB |
| RESERVED | 0x1FF000 | 4 KiB |

- Record format: `magic "UHSM" u32 | version u16 | seq u32 | payload_len u16 | payload | crc32`. A/B: write lower-seq copy with seq=max+1; read highest-seq valid-CRC → power-fail safe.
- DeviceConfig: mode, Argon2 params (m_cost u32 KiB, t_cost u32, p u8), salt[16], maxRetries, wipeOnLockout, fw version.
- KeyBlob: wrapType (1=devKEK, 2=pinKEK) | aeadNonce[12] | pubkey[32] plaintext | ciphertext[32] (Ed25519 seed) | tag[16]; AAD = wrapType‖pubkey‖config.seq (anti blob/config swap).
- KEKs: prod = Argon2id(pin, salt, m=64 KiB, t tuned to 0.5–2 s on hardware, p=1); dev = HKDF-SHA256(flash unique_id, "usbhsm-dev-kek-v1") — documented as obfuscation only. PIN correctness == AEAD tag check (no faster oracle).
- PIN counter: erased sector = 0 attempts; each attempt programs next 0xFF byte → 0x00 (bit-clear, no erase); successful unlock erases sector. **Pre-tick before KEK derivation** (power-glitch always costs an attempt). Backoff `min(250ms × 2^fails, 30s)`.

## Entropy (RP2040 has no TRNG)

Raw: ROSC RANDOMBIT with timer-jittered sampling + von Neumann debias; ADC temp-sensor LSBs; flash unique ID (personalization); 4 KiB `.uninit` SRAM hashed at boot. Health tests (repetition-count + adaptive-proportion, SP 800-90B style) on raw stream gate keygen — failure ⇒ ERR_ENTROPY. Conditioning: SHA-512 over ≥1024 debiased bits → ChaCha20Rng DRBG; reseed every 64 outputs and before keygen. `addEntropy` is additive only.

## Firmware crates & constraints

- hsm-core (all default-features=false): serde(derive,alloc), serde_json(alloc), **ssh-key(alloc,ed25519)**, ed25519-dalek(alloc,zeroize), sha2, hkdf, chacha20poly1305(alloc), argon2(alloc), rand_core+rand_chacha, zeroize(derive), crc.
- hsm-fw: embassy-executor(arch-cortex-m,executor-thread), embassy-rp(rp2040,time-driver,critical-section-impl,rom-func-cache), embassy-usb (CDC-ACM), embassy-time, embassy-sync, embedded-alloc (128 KiB heap), cortex-m(-rt), static_cell, portable-atomic(critical-section) (thumbv6m has no CAS), defmt/panic-probe (dev) / fail-closed zeroize+halt panic handler (release).
- **M1 spike (top risk)**: confirm `ssh-key` certificate::Builder works no_std+alloc with explicit nonce and sorted extensions. Fallback fully specified: `sshwire.rs` hand-rolled encoder per OpenSSH PROTOCOL.certkeys (~200 lines, golden-vector covered).
- Flash writes: embassy-rp blocking flash (ROM funcs from RAM, interrupts masked, ~50–400 ms erase) — fine since single in-flight request; never concurrent with USB beyond HW buffering.
- Device line cap 16 KiB (vs 256 KiB cerberus) — documented divergence; largest legit request ≈6 KiB. Oversize ⇒ drain to `\n` + top-level JSON error.
- `goduration.rs`: exact port of `time.ParseDuration` (units ns/us/µs/μs/ms/s/m/h, fractions, sign, overflow) + Go `Duration.String()` for byte-identical error messages; vectors from Go's time_test.go.
- Time: wall offset over `embassy_time::Instant`; None ⇒ sign fails closed.

## Go host tool

- `device`: enumerate `/dev/serial/by-id/*usbhsm*` (fallback VID:PID via go.bug.st/serial), mutex-serialized RoundTrip with 10 s timeout, reconnect-on-error.
- `bridge`: `usbhsm bridge --listen vsock:5000,tcp:…,unix:…`; 32-conn semaphore; per-conn bufio.Scanner 64 KiB/256 KiB, 5 s deadlines (exact signer behavior); forwards lines to device; **management firewall** — reject top-level `hsm` lines from network clients unless `--allow-remote-mgmt`; bridge itself sends `setTime` on (re)connect + every 5 min.
- VSOCK CID-16 caveat: on non-Nitro hosts a listener can't be CID 16; document options (api-side CID override env, VM with CID 16, socat) in PROTOCOL.md.
- CLI: unlock prompts via x/term (no PIN in argv); factory-reset requires typing ERASE; self-test signs and verifies a cert via x/crypto/ssh.

## Testing

1. **Host unit tests** (cargo test, hsm-core): duration vectors; ~40-case validation parity table; wrap/unwrap + tamper; A/B power-fail simulation (corrupt every offset); state-machine table; DRBG health vectors; metrics JSON shape.
2. **Golden vectors**: deterministic RNG + fixed time → expected cert line; CI runs `ssh-keygen -L` to verify (skip if absent).
3. **Differential Go test**: identical request + CA seed + injected nonce/serial/time through `hsm-sim` AND in-process x/crypto/ssh; assert every cert field equal + signature verifies; rejection parity per error class (byte-exact where the duration Stringer port allows).
4. **HIL** (`tests/hil/run.sh`, real hardware): flash → factory-reset → init dev → generate-key → set-time → ping(signerLoaded:true) → sign → ssh-keygen -L → dockerized sshd accept test (TrustedUserCAKeys) → prod flow: unlock, sign, bad-PIN×N → lockout, mid-unlock power-cycle proves pre-tick, factory-reset recovery.
5. **End-to-end drop-in**: unmodified ssh-cert-api `enclave.Call` path signs through bridge (TCP shim or vsock).

## Milestones (each gated on verifiable criteria)

- **M0 Scaffold**: workspace + 3 crates compile, fw links for thumbv6m, Go vets, CI green on skeleton.
- **M1 hsm-core on host**: ssh-key spike resolved (or sshwire fallback); full protocol in hsm-sim; all unit+golden tests pass; `echo '{"ping":{}}' | hsm-sim` round-trips.
- **M2 Firmware bring-up**: CDC-ACM enumerates; `{"ping":{}}` → `{"pong":{"signerLoaded":false}}` on real /dev/ttyACM0.
- **M3 Storage + entropy + dev signing on hardware**: HIL dev-flow passes incl. ssh-keygen -L.
- **M4 Production mode**: Argon2 tuned on-device; unlock/lock/changePin/lockout/wipe/factoryReset; HIL prod-flow incl. power-pull retry test passes.
- **M5 Go bridge + CLI**: unmodified ssh-cert-api signs a cert through the device.
- **M6 Differential + docs**: differential suite green; PROTOCOL/FLASH_LAYOUT/THREAT_MODEL/PROVISIONING written incl. divergence list; v0.1.0 tag.

## Risks / open questions

1. ssh-key Builder no_std status — M1 spike; sshwire.rs fallback specified.
2. ed25519-dalek speed on M0+ (expect 50–300 ms/sign) — benchmark M3; `salty` as alternative behind keys.rs.
3. Argon2 64 KiB timing on M0+ — tune t_cost on hardware; params persisted in config.
4. VSOCK CID-16 drop-in on non-Nitro hosts — deployment decision, documented options.
5. USB VID/PID — pid.codes allocation; interim testing PID + unique product string.
6. Exact error-string parity — port where cheap; differential tests assert error class otherwise.

## Verification (end-to-end)

1. `make test` — hsm-core unit + golden tests on host.
2. `cd tests/differential && go test ./...` — field-level cert equality vs x/crypto/ssh.
3. `make flash && tests/hil/run.sh /dev/serial/by-id/<dev>` — full dev+prod hardware flows.
4. Drop-in proof: `usbhsm bridge --listen tcp:127.0.0.1:5000` + ssh-cert-api pointed at it → sign request returns a cert that `ssh-keygen -L` decodes and a sshd container accepts.
5. Security checks: flash dump of a production-mode device yields no usable key without PIN (manual audit step); bad-PIN lockout and pre-tick behavior demonstrated in HIL.

## Threat model summary (to be expanded in docs/THREAT_MODEL.md)

- **Protected against**: remote/software attackers (key never crosses USB; only signed certs and the public key do), stolen-device flash dump in production mode (seed AEAD-wrapped under Argon2id(PIN)), PIN brute-force over the wire (pre-ticked retry counter, backoff, lockout/wipe), power-glitch retry-counter bypass (tick persisted before verification), blob/config swap attacks (AAD binding).
- **NOT protected against** (documented honestly, RP2040 limits): physical attacker with flash dump + weak PIN (offline Argon2 brute-force — use a strong passphrase), malicious firmware reflash (no secure boot on RP2040; RP2350 build adds this later), invasive silicon attacks, host compromise while the device is unlocked (attacker can request signatures — mitigated by short validity and audit logging host-side).
