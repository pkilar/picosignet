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

case "$stage" in
P1)
    need_artifacts
    echo "P1: flashing the SIGNED image (secure boot not yet enforced)."
    picotool load -u -v -x "$signed_uf2"
    echo "P1 done. Now run the full HIL suite against this image"
    echo "(tests/hil/run.sh) before proceeding to P2."
    ;;
P2)
    need_artifacts
    echo "P2 will burn the boot-key hash from: $bootkey_otp"
    echo "Rows: BOOTKEY0 (0x080-0x08F) + BOOT_FLAGS1.KEY_VALID bit0."
    gate P2 "burn boot-key hash (BOOTKEY0 + KEY_VALID)"
    picotool otp load "$bootkey_otp"
    echo "Verifying burned key hash against the OTP JSON:"
    picotool otp get BOOTKEY0_0 BOOTKEY0_1 BOOTKEY0_2 BOOTKEY0_3
    echo "P2 done. Compare the rows above with $bootkey_otp before P4."
    ;;
P3)
    echo "P3: power-cycle the device (unplug/replug), confirm the signed image"
    echo "boots and 'picosignet status' shows secure boot: false (not enforced yet)."
    echo "Nothing is burned in this stage."
    ;;
P4)
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
    echo "P5: optional hardening. Each item is gated separately."
    echo
    echo "(a) Force-arm glitch detectors from boot ROM (firmware arming becomes"
    echo "    redundant; sensitivity 2 matches the firmware default)."
    printf 'Burn glitch-detector force-arm? [y/N] '
    read -r yn
    if [ "$yn" = "y" ]; then
        gate P5-GLITCH "force-arm glitch detectors (CRIT1.GLITCH_DETECTOR_ENABLE/SENS)"
        picotool otp set CRIT1.GLITCH_DETECTOR_ENABLE 1
        picotool otp set CRIT1.GLITCH_DETECTOR_SENS 2
    fi
    echo
    echo "(b) Disable debug access (SWD). SECURE_DEBUG_DISABLE keeps non-secure"
    echo "    debug; DEBUG_DISABLE kills all of it."
    printf 'Burn DEBUG_DISABLE? [y/N] '
    read -r yn
    if [ "$yn" = "y" ]; then
        gate P5-DEBUG "disable all debug access (CRIT1.DEBUG_DISABLE)"
        picotool otp set CRIT1.DEBUG_DISABLE 1
    fi
    echo
    echo "(c) Disable the PICOBOOT interface. picotool stops working forever;"
    echo "    signed-UF2 drag-and-drop via the MSD drive remains. NEVER also"
    echo "    disable the MSD interface or the device becomes un-updatable."
    printf 'Burn DISABLE_BOOTSEL_USB_PICOBOOT_IFC? [y/N] '
    read -r yn
    if [ "$yn" = "y" ]; then
        gate P5-PICOBOOT "disable PICOBOOT (BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC)"
        picotool otp set BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC 1
    fi
    echo "P5 done."
    ;;
*)
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
