#!/usr/bin/env bash
# Production OTP provisioning for a PicoSignet RP2350 device.
#
# !!! THIS SCRIPT BURNS ONE-TIME-PROGRAMMABLE FUSES. STAGES P2/P4/P5 ARE !!!
# !!! PERMANENT AND CANNOT BE UNDONE. A MISTAKE CAN BRICK THE BOARD.     !!!
#
# Implements the staged runbook from docs/PROVISIONING.md:
#   P1  flash the SIGNED image and verify it boots (reversible — the bootrom
#       ignores signatures until P4; this validates the seal/sign step)
#   P2  burn the boot-key hash: BOOTKEY0 + BOOT_FLAGS1.KEY_VALID  [IRREVERSIBLE]
#   P3  power-cycle check: signed image still boots               (reversible)
#   P4  burn CRIT1.SECURE_BOOT_ENABLE                  [IRREVERSIBLE — point of
#       no return: only images signed with keys/picosignet-boot.pem will ever boot]
#   P5  optional hardening, each gated separately                 [IRREVERSIBLE]
#
# Run each stage explicitly:  scripts/provision_production.sh <P1|P2|P3|P4|P5>
# The device must be in BOOTSEL mode for every stage (picosignet reboot-bootloader,
# or hold BOOTSEL while plugging in). Every irreversible gate requires typing
# the literal confirmation phrase.
#
# Each stage reads current OTP state first (read-only) and acts on it:
#   * P2 skips if the key is already burned (BOOTKEY0 is one-time — never re-burn).
#   * P4 REFUSES unless a valid key is present (KEY_VALID set), else exits without
#     burning — enabling secure boot with no key would brick the board.
#   * P4/P5 skip fuses that are already set. Unreadable state fails closed on the
#     irreversible stages.
#
# Prerequisites: make keygen && make uf2-signed; keys/picosignet-boot.pem backed up
# OFFLINE, TWICE — after P4, losing it permanently bricks firmware updates.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$here/.."
signed_uf2="$root/target/thumbv8m.main-none-eabihf/release/hsm-fw-signed.uf2"
bootkey_otp="$root/keys/picosignet-bootkey-otp.json"

stage="${1:-}"

gate() { # gate <stage> <description...>
    local s="$1"; shift
    echo
    echo "=============================================================="
    echo " IRREVERSIBLE: $*"
    echo " This burns OTP fuses on the connected device. There is no undo."
    echo "=============================================================="
    printf 'Type "BURN %s" to continue: ' "$s"
    read -r answer
    [ "$answer" = "BURN $s" ] || { echo "aborted (no fuses touched)"; exit 1; }
}

need_artifacts() {
    [ -f "$signed_uf2" ] || { echo "missing $signed_uf2 — run 'make uf2-signed'"; exit 1; }
    [ -f "$bootkey_otp" ] || { echo "missing $bootkey_otp — run 'make uf2-signed'"; exit 1; }
}

# ---- OTP state inspection (READ-ONLY: 'otp get' never writes a fuse) -------
# require_device: abort if no RP2350 is reachable, so a later "unknown" state
# means a parse failure (fail-closed), not merely a disconnected board.
require_device() {
    if ! picotool otp get -n CRIT1.SECURE_BOOT_ENABLE >/dev/null 2>&1; then
        echo "ERROR: cannot read OTP from a device. Put the board in BOOTSEL mode"
        echo "(hold BOOTSEL while plugging in, or 'picosignet reboot-bootloader')"
        echo "and retry. No fuses were touched."
        exit 1
    fi
}

# otp_state <selector> -> echoes 'set' (nonzero) | 'clear' (zero) | 'unknown'.
# Parses the value after the last '=' in picotool's (-n) readout; any value it
# cannot read or parse is reported 'unknown' so callers can fail closed.
otp_state() {
    local sel="$1" out line val digits
    if ! out="$(picotool otp get -n "$sel" 2>/dev/null)"; then echo unknown; return 0; fi
    line="$(printf '%s\n' "$out" | grep '=' | tail -1 || true)"
    if [ -z "$line" ]; then echo unknown; return 0; fi
    val="$(printf '%s' "$line" | sed -E 's/.*=[[:space:]]*//; s/[^0-9A-Fa-fxX].*$//' || true)"
    if [ -z "$val" ]; then echo unknown; return 0; fi
    digits="${val#0[xX]}"
    digits="$(printf '%s' "$digits" | tr -d '0' || true)"
    if [ -n "$digits" ]; then echo set; else echo clear; fi
    return 0
}

case "$stage" in
P1)
    need_artifacts
    require_device
    echo "Current OTP state before P1:"
    echo "  BOOT_FLAGS1.KEY_VALID    = $(otp_state BOOT_FLAGS1.KEY_VALID)"
    echo "  CRIT1.SECURE_BOOT_ENABLE = $(otp_state CRIT1.SECURE_BOOT_ENABLE)"
    echo "P1: flashing the SIGNED image (secure boot not yet enforced)."
    picotool load -u -v -x "$signed_uf2"
    echo "P1 done. Now run the full HIL suite against this image"
    echo "(tests/hil/run.sh) before proceeding to P2."
    ;;
P2)
    need_artifacts
    command -v jq >/dev/null || { echo "P2 needs 'jq' to strip secure_boot_enable from the seal JSON"; exit 1; }
    require_device
    # Idempotency: KEY_VALID is set by P2's load. If it is already set, the key
    # was burned before — do NOT load again (BOOTKEY0 is a one-time ECC row;
    # re-loading a different value would corrupt it). Skip and let the operator
    # confirm the existing rows match the JSON.
    kv="$(otp_state BOOT_FLAGS1.KEY_VALID)"
    if [ "$kv" = set ]; then
        echo "BOOT_FLAGS1.KEY_VALID is already set — the boot key was burned previously."
        echo "Existing key rows on the device:"
        picotool otp get BOOTKEY0_0 BOOTKEY0_1 BOOTKEY0_2 BOOTKEY0_3
        echo "Skipping P2 (the key is one-time; re-burning is unnecessary and unsafe)."
        echo "Confirm the rows above match $bootkey_otp, then continue to P3."
        exit 0
    fi
    # kv is 'clear' or 'unknown'. Secure boot is still OFF at this stage and
    # 'otp load' verifies its own write, so proceeding is recoverable either way;
    # warn if we could not read the flag.
    [ "$kv" = unknown ] && echo "WARNING: could not read KEY_VALID; relying on otp-load's own verify."
    # picotool seal bundles crit1.secure_boot_enable=1 into the SAME JSON as the
    # key hash, and 'otp load' burns EVERY field in the file. Loading it verbatim
    # would enable secure boot here in P2 — collapsing the reversible P2/P3
    # checkpoint into the irreversible P4 and skipping P4's explicit gate.
    # So burn ONLY the key hash + KEY_VALID now; P4 enables secure boot later.
    # .json suffix is REQUIRED: picotool infers file type from the extension and
    # refuses an extensionless file (it errors during arg parsing, before any
    # burn — but that aborts P2). Keep the same type the original .json had.
    key_only="$(mktemp --suffix=.json)"
    trap 'rm -f "$key_only"' EXIT
    jq 'del(.crit1)' "$bootkey_otp" > "$key_only"
    echo "P2 will burn the boot-key hash from: $bootkey_otp"
    echo "Rows: BOOTKEY0 (0x080-0x08F) + BOOT_FLAGS1.KEY_VALID."
    echo "Secure boot stays DISABLED after P2 — it is enabled later, gated, in P4."
    echo "Fields actually being loaded: $(jq -c 'keys' "$key_only")"
    gate P2 "burn boot-key hash (BOOTKEY0 + KEY_VALID)"
    picotool otp load "$key_only"   # 'load' reads the rows back and verifies them
    echo "Verifying burned key hash:"
    picotool otp get BOOTKEY0_0 BOOTKEY0_1 BOOTKEY0_2 BOOTKEY0_3
    echo "P2 done. Secure boot is still OFF; continue to P3 (power-cycle check)."
    ;;
P3)
    require_device
    echo "P3 state check (nothing is burned in this stage):"
    kv="$(otp_state BOOT_FLAGS1.KEY_VALID)"
    sbe="$(otp_state CRIT1.SECURE_BOOT_ENABLE)"
    echo "  BOOT_FLAGS1.KEY_VALID    = $kv    (expect 'set'   — P2 done)"
    echo "  CRIT1.SECURE_BOOT_ENABLE = $sbe    (expect 'clear' — P4 not yet)"
    [ "$kv" = set ]   || echo "  ! KEY_VALID is not set — run P2 before P4."
    [ "$sbe" = clear ] || echo "  ! SECURE_BOOT_ENABLE is already set — you are past P4."
    echo "Now power-cycle the device (unplug/replug) and confirm the signed image"
    echo "boots and 'picosignet status' shows secure boot: false (not enforced yet)."
    ;;
P4)
    require_device
    # Idempotency: if secure boot is already enabled, there is nothing to do.
    sbe="$(otp_state CRIT1.SECURE_BOOT_ENABLE)"
    if [ "$sbe" = set ]; then
        echo "CRIT1.SECURE_BOOT_ENABLE is already set — secure boot is already enabled."
        echo "Nothing to do in P4."
        exit 0
    fi
    # FAIL-CLOSED PRECONDITION: never enable secure boot unless a valid boot key
    # is present. Enabling it with no valid key bricks the device (the bootrom
    # would reject every image). KEY_VALID is the bootrom's own validity flag.
    kv="$(otp_state BOOT_FLAGS1.KEY_VALID)"
    if [ "$kv" != set ]; then
        echo "REFUSING P4: BOOT_FLAGS1.KEY_VALID = $kv (must be 'set')."
        echo "Enabling secure boot now would BRICK the device — no valid key to"
        echo "verify any image. Run P2 first, then re-run P4."
        echo "Current key state:"
        picotool otp get BOOT_FLAGS1.KEY_VALID BOOTKEY0_0 BOOTKEY0_1 BOOTKEY0_2 BOOTKEY0_3 || true
        exit 1
    fi
    echo "Precondition OK: a valid boot key is present (KEY_VALID = set)."
    echo "P4 is the POINT OF NO RETURN. After this burn:"
    echo "  - only images signed with keys/picosignet-boot.pem will boot"
    echo "  - losing that key means the device can never be updated again"
    echo "Do NOT proceed unless P1-P3 passed and the key is backed up offline."
    gate P4 "enable secure boot (CRIT1.SECURE_BOOT_ENABLE)"
    picotool otp set CRIT1.SECURE_BOOT_ENABLE 1
    echo "P4 done. Verify NOW:"
    echo "  1. power-cycle: the signed image must boot"
    echo "  2. 'picosignet status' must show secure boot: true"
    echo "  3. NEGATIVE TEST: an unsigned UF2 must be refused by the bootrom"
    ;;
P5)
    require_device
    echo "P5: optional hardening. Each item is gated separately."
    [ "$(otp_state CRIT1.SECURE_BOOT_ENABLE)" = set ] || \
        echo "NOTE: secure boot is not enabled yet (P4). P5 hardening normally follows P4."
    echo
    echo "(a) Force-arm glitch detectors from boot ROM (firmware arming becomes"
    echo "    redundant; sensitivity 2 matches the firmware default)."
    if [ "$(otp_state CRIT1.GLITCH_DETECTOR_ENABLE)" = set ]; then
        echo "    already set — skipping."
    else
        printf 'Burn glitch-detector force-arm? [y/N] '
        read -r yn
        if [ "$yn" = "y" ]; then
            gate P5-GLITCH "force-arm glitch detectors (CRIT1.GLITCH_DETECTOR_ENABLE/SENS)"
            picotool otp set CRIT1.GLITCH_DETECTOR_ENABLE 1
            picotool otp set CRIT1.GLITCH_DETECTOR_SENS 2
        fi
    fi
    echo
    echo "(b) Disable debug access (SWD). SECURE_DEBUG_DISABLE keeps non-secure"
    echo "    debug; DEBUG_DISABLE kills all of it."
    if [ "$(otp_state CRIT1.DEBUG_DISABLE)" = set ]; then
        echo "    already set — skipping."
    else
        printf 'Burn DEBUG_DISABLE? [y/N] '
        read -r yn
        if [ "$yn" = "y" ]; then
            gate P5-DEBUG "disable all debug access (CRIT1.DEBUG_DISABLE)"
            picotool otp set CRIT1.DEBUG_DISABLE 1
        fi
    fi
    echo
    echo "(c) Disable the PICOBOOT interface. picotool stops working forever;"
    echo "    signed-UF2 drag-and-drop via the MSD drive remains. NEVER also"
    echo "    disable the MSD interface or the device becomes un-updatable."
    if [ "$(otp_state BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC)" = set ]; then
        echo "    already set — skipping."
    else
        printf 'Burn DISABLE_BOOTSEL_USB_PICOBOOT_IFC? [y/N] '
        read -r yn
        if [ "$yn" = "y" ]; then
            gate P5-PICOBOOT "disable PICOBOOT (BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC)"
            picotool otp set BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC 1
        fi
    fi
    echo "P5 done."
    ;;
*)
    sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
