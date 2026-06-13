export const meta = {
  name: 'rp2350-port-review',
  description: 'Adversarial review of the RP2350-only security port (commits ba18b01..HEAD)',
  phases: [
    { title: 'Review', detail: '3 lenses: crypto/security, embedded API vs vendored source, consistency/wire-compat' },
    { title: 'Verify', detail: 'adversarial refutation of every finding' },
  ],
}

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          file: { type: 'string' },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          description: { type: 'string', description: 'What is wrong, why it matters, and the concrete evidence (file:line, quoted code)' },
        },
        required: ['title', 'file', 'severity', 'description'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    isReal: { type: 'boolean' },
    explanation: { type: 'string', description: 'Evidence-based justification; if refuted, the exact counter-evidence' },
  },
  required: ['isReal', 'explanation'],
}

const COMMON = `Repo: /home/pkilar/Devel/usbhsm. Review ONLY the changes in 'git diff ba18b01..HEAD' (run that to see them; read full files for context). This is a security-critical USB HSM port: RP2040 was removed; now RP2350-only (Waveshare RP2350-One, embassy-rp 0.3.1 feature rp235xa, rp-pac 7.0.0, thumbv8m.main-none-eabihf). Wire compatibility with the cerberus signer protocol is an inviolable requirement. Report only findings that would change behavior, weaken security, or break the build/hardware bring-up tomorrow — not style. If you find nothing real, return an empty findings array; do NOT invent findings.`

const LENSES = [
  {
    key: 'crypto-security',
    prompt: `${COMMON}
Lens: cryptography and security logic. Scrutinize:
- hsm-core/src/wrap.rs: the KEK v2 constructions (dev: HKDF-SHA256(ikm=OTP secret, info dev-v2); prod: Argon2id(PIN) -> HKDF-SHA256(salt=OTP secret, info prod-v2)). Domain separation, salt-vs-ikm placement, zeroization of intermediates.
- hsm-fw/src/otp_secret.rs: the first-boot OTP provisioning state machine. Torn-write windows (power loss between any two writes), the marker-last invariant, void-slot semantics, the both-pages hard-lock, degenerate-secret rejection, whether any path can return a secret that was not fully verified, whether a failure path can brick or silently weaken.
- hsm-core/src/dispatch.rs: every device_secret() call site fails closed? Any path that still derives a KEK without the secret? The dev-mode boot path with missing secret. The pre-tick-before-KEK PIN ordering preserved?
- hsm-core/src/storage.rs: wrap_type 3/4 rejection of v1 blobs; any parsing that could alias.
- hsm-fw/src/security.rs + usb.rs boot ordering: glitch detectors armed before key material is touched? OTP secret loaded then SW_LOCKed before USB serves requests?
- Anything in the diff that LOOKS like hardening but is a no-op.`,
  },
  {
    key: 'embedded-api',
    prompt: `${COMMON}
Lens: embedded correctness against the ACTUAL vendored crate sources at ~/.cargo/registry/src/*/embassy-rp-0.3.1/ and ~/.cargo/registry/src/*/rp-pac-7.0.0/ (read them; do not trust memory). Verify exactly:
- hsm-fw/src/otp_secret.rs: embassy_rp::otp::{read_ecc_word, write_ecc_word, write_raw_word, read_raw_word} semantics — row addressing (ECC row numbers vs byte addresses), what a BLANK row reads as, error behavior on permission-denied, the 24-bit raw write mask vs our 0x3D3D3D lock value, and whether rp_pac::OTP.sw_lock(n) page indexing matches OTP pages. Verify lock1_row(page)=0xF80+2*page+1 against pico-sdk otp_data.h in ~/.cache/yay/pico-sdk/src/pico-sdk/src/rp2350/hardware_regs/include/hardware/regs/otp_data.h (PAGE60_LOCK1/PAGE61_LOCK1) and that 0x3D encodes S=read-only NS=inaccessible BL=inaccessible per the LOCK1 field layout in that header.
- hsm-fw/src/security.rs: GLITCH_DETECTOR sensitivity register field layout (det0..3 at bits 0..7, inverted copies at bits 8..15, DEFAULT field semantics — vals::Default::NO=0xde required to use register values?), Arm::YES=0 write semantics, LOCK register behavior; POWMAN.chip_reset().had_glitch_detect() exists; embassy_rp::otp::read_raw_word(0x40) for CRIT1 — confirm CRIT1 is a RAW row (not ECC) and bit0 = SECURE_BOOT_ENABLE per pico-sdk otp_data.h.
- hsm-fw/src/usb.rs: rom_data::reboot(0x0102, 100, 0, 0) — check the flag values against pico-sdk's picoboot_constants.h / bootrom_constants.h (REBOOT2_FLAG_REBOOT_TYPE_BOOTSEL, NO_RETURN_ON_SUCCESS) and the embassy fn signature; TRNG bind_interrupts + blocking_fill_bytes usage; PIN_16 exists on rp235xa (30 GPIO).
- hsm-fw/memory.x + main.rs IMAGE_DEF: section placement vs embassy-rp's expectations (search the crate for start_block/end_block/bi_entries handling); FLASH length 0x3FA000 and the flash_hal offsets vs the 4 MiB part; RAM 512K and HEAP_SIZE 384K + static usage — is there a realistic stack overflow risk (Argon2 m_cost=256 KiB allocated where)?
- hsm-fw/Cargo.toml: rp-pac version/feature exactly matching what embassy-rp 0.3.1 resolves (one PAC in the build); removal of portable-atomic safe for all remaining deps on thumbv8m?`,
  },
  {
    key: 'consistency',
    prompt: `${COMMON}
Lens: cross-cutting consistency and wire compatibility. Check:
- proto.rs StatusResp/SelfTestDetails serde renames vs host/internal/hsmproto/hsmproto.go struct tags vs docs/PROTOCOL.md field lists — every new field identical in all three (otpSecret, glitchArmed, secureBoot, glitchReset; selfTest otpSecret).
- Signer-path JSON untouched: diff must not alter anything in the signSshKey/ping/loadKeySigner/getEnclaveMetrics shapes EXCEPT the documented metrics total SRAM value change. Confirm tests/differential and tests/golden do not pin the old 264 KiB value or old status shape anywhere.
- docs vs code: OTP rows/values in docs/FLASH_LAYOUT.md vs otp_secret.rs constants; flash offsets in memory.x header comment vs flash_hal.rs vs FLASH_LAYOUT.md; Argon2 defaults (256/14/1) consistent across dispatch.rs, docs, README; KeyBlob wrap_type values 3/4 in docs vs storage.rs.
- Makefile/scripts: make uf2/uf2-signed/flash-uf2/keygen target correctness (picotool 2.2.0 arg syntax — verify with 'picotool help seal' etc.), scripts/provision_production.sh shell correctness (run bash -n; check the BOOTKEY selector names exist in 'picotool otp list' output if a device-less check is possible, e.g. grep pico-sdk otp_data.h for BOOTKEY0_0), .gitignore keys/ entry.
- tests/hil/run.sh still consistent with the new CLI output (it greps nothing brittle?); ci.yml target swap complete; rust-toolchain/.cargo config coherent (the cfg() rustflags table reaches the firmware build — check a fresh 'cargo build -p hsm-fw --target thumbv8m.main-none-eabihf --release -v 2>&1 | grep -c link-arg' returns nonzero... use a touch of hsm-fw/src/main.rs first to force a rebuild, then 'git checkout' nothing — touching timestamps is fine).
- hsm-sim: does it compile/run with the new MockFlash device_secret default and report the documented sim values (otpSecret true, others false)?`,
  },
]

phase('Review')
const results = await pipeline(
  LENSES,
  l => agent(l.prompt, { label: `review:${l.key}`, phase: 'Review', schema: FINDINGS_SCHEMA }),
  (review, lens) => parallel((review?.findings ?? []).map(f => () =>
    agent(
      `You are an adversarial verifier on a security-critical embedded Rust codebase at /home/pkilar/Devel/usbhsm (RP2350 USB HSM, changes in git diff ba18b01..HEAD). A reviewer (lens: ${lens.key}) claims:\n\nTITLE: ${f.title}\nFILE: ${f.file}\nSEVERITY: ${f.severity}\nCLAIM: ${f.description}\n\nTry to REFUTE this finding with concrete evidence: read the actual files, the vendored embassy-rp-0.3.1/rp-pac-7.0.0 sources in ~/.cargo/registry/src/, and the pico-sdk headers in ~/.cache/yay/pico-sdk/src/pico-sdk/ as needed; run read-only commands (cargo build/test is allowed). If after honest effort the finding stands, mark it real. Default to isReal=false when the evidence is ambiguous or the claim is speculative/stylistic.`,
      { label: `verify:${f.title.slice(0, 40)}`, phase: 'Verify', schema: VERDICT_SCHEMA }
    ).then(v => ({ ...f, lens: lens.key, verdict: v }))
  ))
)

const all = results.filter(Boolean).flat().filter(Boolean)
return {
  confirmed: all.filter(f => f.verdict?.isReal),
  refuted: all.filter(f => !f.verdict?.isReal).map(f => ({ title: f.title, severity: f.severity, why: f.verdict?.explanation?.slice(0, 300) })),
}