#!/usr/bin/env bash
# Hardware-in-the-loop end-to-end test for a flashed PicoSignet device.
#
# Exercises the full dev and production lifecycles against real hardware using
# the PicoSignet CLI, and verifies issued certificates with ssh-keygen -L. This is
# DESTRUCTIVE: it factory-resets the device.
#
# Usage:  tests/hil/run.sh [/dev/serial/by-id/...]
#         (port auto-discovered if omitted)
#
# Requires: a flashed device, ssh-keygen. PINs are piped to the CLI (which reads
# non-interactive stdin), so this runs unattended.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
port="${1:-}"
portflag=()
[ -n "$port" ] && portflag=(--port "$port")

echo "hil: building PicoSignet CLI"
(cd "$root/host" && go build -o "$root/target/picosignet" ./cmd/picosignet)
cli="$root/target/picosignet"

run() { echo "+ picosignet $*"; "$cli" "${portflag[@]}" "$@"; }

# Confirm a device is present before doing anything destructive.
if ! "$cli" "${portflag[@]}" status >/dev/null 2>&1; then
  echo "hil: no PicoSignet device found (flash the firmware and plug it in)" >&2
  exit 1
fi

PIN="correct-horse-battery-staple"
WRONGPIN="nope-nope-nope"

echo "=== clean slate ==="
echo ERASE | run factory-reset --yes || true

echo "=== DEV FLOW ==="
run init
run generate-key
run set-time
run status
run self-test            # signs a throwaway key and verifies against the device CA
run pubkey

echo "=== PROD FLOW ==="
echo ERASE | run factory-reset --yes
printf '%s\n%s\n' "$PIN" "$PIN" | run init --prod --max-retries 3
run pubkey               # works while locked (public key stored in clear)
echo "  (expect failure: signing while locked)"
if run self-test 2>/dev/null; then echo "  UNEXPECTED: self-test passed while locked"; exit 1; fi
echo "  ok: locked device refuses to sign"

echo "  wrong PIN (expect ERR_BAD_PIN):"
if echo "$WRONGPIN" | run unlock 2>/dev/null; then echo "  UNEXPECTED: wrong PIN unlocked"; exit 1; fi
echo "  ok: wrong PIN rejected"

echo "  correct PIN:"
echo "$PIN" | run unlock
run set-time
run self-test
run lock

echo "=== LOCKOUT ==="
echo ERASE | run factory-reset --yes
printf '%s\n%s\n' "$PIN" "$PIN" | run init --prod --max-retries 3
for i in 1 2 3; do
  echo "  bad attempt $i:"
  echo "$WRONGPIN" | run unlock 2>/dev/null || true
done
echo "  device should now be locked out; correct PIN must fail:"
if echo "$PIN" | run unlock 2>/dev/null; then echo "  UNEXPECTED: unlocked after lockout"; exit 1; fi
echo "  ok: locked out"

echo "  factory-reset recovers:"
echo ERASE | run factory-reset --yes
run status

echo "hil: PASSED"
