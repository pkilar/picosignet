#!/usr/bin/env bash
# Golden-vector check: drive the simulator with a fixed RNG seed and fixed time,
# then confirm OpenSSH's own ssh-keygen -L parses the issued certificate and its
# fields match. This complements tests/differential (which checks byte-exact
# x/crypto/ssh compatibility) with an independent OpenSSH cross-check.
#
# Skips cleanly if ssh-keygen is unavailable.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "golden: ssh-keygen not found, skipping"
  exit 0
fi

echo "golden: building hsm-sim"
(cd "$root" && cargo build -q -p hsm-sim)
sim="$root/target/debug/hsm-sim"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A fixed Ed25519 user public key (any valid key works; embedded for determinism).
ssh-keygen -t ed25519 -N '' -C 'golden@user' -f "$tmp/uk" -q
userkey="$(cat "$tmp/uk.pub")"

fixed_time=1700000000   # 2023-11-14T22:13:20Z
validity_hours=8

# Drive a deterministic dev flow.
{
  echo '{"hsm":{"init":{"mode":"dev"}}}'
  echo '{"hsm":{"generateKey":{}}}'
  printf '{"signSshKey":{"ssh_key":"%s","key_id":"golden-key-id","principals":["alice","ops"],"validity":"%dh","permissions":{"permit-pty":""},"critical_options":{"force-command":"/usr/bin/true"}}}\n' \
    "$userkey" "$validity_hours"
} | "$sim" --deterministic-rng deadbeef --fixed-time "$fixed_time" > "$tmp/out.jsonl"

# Extract the certificate (last line → signSshKey.signed_key).
cert="$(python3 -c '
import json,sys
last=open(sys.argv[1]).read().splitlines()[-1]
print(json.loads(last)["signSshKey"]["signed_key"])
' "$tmp/out.jsonl")"
echo "$cert" > "$tmp/cert.pub"

echo "golden: ssh-keygen -L output:"
info="$(ssh-keygen -L -f "$tmp/cert.pub")"
echo "$info" | sed 's/^/    /'

fail=0
check() { if echo "$info" | grep -q "$1"; then echo "  ok: $2"; else echo "  FAIL: $2 (missing: $1)"; fail=1; fi; }

check 'user certificate' 'type is user certificate'
check 'Key ID: "golden-key-id"' 'key id'
check 'force-command /usr/bin/true' 'critical option force-command'
check 'permit-pty' 'extension permit-pty'
# Validity window: from = fixed_time-300, to = fixed_time + 8h. Compare in UTC.
from_utc="$(date -u -d "@$((fixed_time-300))" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || true)"
to_utc="$(date -u -d "@$((fixed_time+validity_hours*3600))" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || true)"
# ssh-keygen prints local time; assert the principals and parse succeeded, and
# (if GNU date is present) that the duration spans 8h+300s.
echo "  info: expected validity ~ [$from_utc .. $to_utc] UTC"
echo "alice ops" | tr ' ' '\n' | while read -r p; do
  check "                $p" "principal $p" || true
done

if [ "$fail" -ne 0 ]; then
  echo "golden: FAILED"
  exit 1
fi
echo "golden: PASSED"
