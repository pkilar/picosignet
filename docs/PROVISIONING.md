# Provisioning & deployment

End-to-end setup, from a blank Pico to `ssh-cert-api` signing through the device.

## 0. Build & flash the firmware

```sh
make uf2
# BOOTSEL flashing: hold BOOTSEL, plug the Pico in, then:
cp target/thumbv6m-none-eabi/release/hsm-fw.uf2 /media/$USER/RPI-RP2/
# or, with a debug probe:
make flash
```

The device enumerates as a USB CDC-ACM serial port (`1209:000A`, product
`usbhsm`), discoverable at `/dev/serial/by-id/*usbhsm*`. All `usbhsm` commands
accept `--port <path>` to override auto-discovery.

## 1a. Dev mode (convenience; not physically secure)

```sh
usbhsm init               # dev mode
usbhsm generate-key       # generate the on-device CA key, prints the public key
usbhsm pubkey > cerberus-ca.pub
usbhsm status
```

The device is operational immediately on every plug-in. Use this where physical
capture of the device is not in your threat model (see `THREAT_MODEL.md`).

## 1b. Production mode (PIN-protected)

```sh
usbhsm init --prod --max-retries 10           # prompts for a PIN twice
# init in prod mode generates the CA key as part of init.
usbhsm pubkey > cerberus-ca.pub               # works while locked
usbhsm unlock                                  # prompts for the PIN
usbhsm status                                  # state: prodReady
```

Use a **strong passphrase** (e.g. 6-word diceware), not a short numeric PIN — the
RP2040's flash is externally readable and the KDF is RAM-limited. Add
`--wipe-on-lockout` if you prefer key destruction over availability after a
brute-force attempt. Re-lock when idle with `usbhsm lock`; rotate the passphrase
with `usbhsm change-pin`.

To change modes later, `usbhsm factory-reset` (destroys the key) then `init`
again — there is no in-place dev↔prod switch.

## 2. Trust the CA on your SSH servers

```sh
sudo cp cerberus-ca.pub /etc/ssh/cerberus-ca.pub
# /etc/ssh/sshd_config:
#   TrustedUserCAKeys /etc/ssh/cerberus-ca.pub
sudo systemctl reload sshd
```

## 3. Run the bridge for ssh-cert-api

The bridge exposes the device's protocol over VSOCK/TCP/Unix and reproduces the
enclave's framing, limits, and 32-connection cap. It pushes wall-clock time to
the device on connect and every 5 minutes, and **firewalls management commands**
away from network clients by default.

```sh
# TCP (simplest for a non-Nitro host):
usbhsm bridge --listen tcp:127.0.0.1:5000

# Unix socket:
usbhsm bridge --listen unix:/run/usbhsm.sock

# VSOCK (Nitro-style drop-in — see the CID-16 note below):
usbhsm bridge --listen vsock:5000
```

`ssh-cert-api` dials VSOCK **CID 16, port 5000**. On a plain Linux host you cannot
bind a vsock listener as CID 16 (loopback is CID 1), so a true drop-in points the
API at the bridge instead. In order of preference:

- **Endpoint override (recommended).** ssh-cert-api reads `CERBERUS_SIGNER_ENDPOINT`
  (implemented on the cerberus `usbhsm-signer-endpoint` branch — `enclave/endpoint.go`):

  ```sh
  usbhsm bridge --listen tcp:127.0.0.1:5000 &
  CERBERUS_SIGNER_ENDPOINT=tcp://127.0.0.1:5000 ssh-cert-api ...
  # or over a unix socket:
  usbhsm bridge --listen unix:/run/usbhsm.sock &
  CERBERUS_SIGNER_ENDPOINT=unix:///run/usbhsm.sock ssh-cert-api ...
  ```

  Unset, ssh-cert-api behaves exactly as before (VSOCK CID 16) — the override is
  opt-in and transport-transparent (same framing/deadlines).

  Note: on a non-Nitro host, ssh-cert-api's startup `LoadKeySigner` also fetches
  AWS credentials from IMDS and starts a KMS VSOCK proxy. The usbhsm device
  ignores the credentials, but those startup steps assume an EC2/Nitro
  environment; running fully off-Nitro may need them stubbed/skipped separately.

- Run the bridge inside a VM whose guest CID is set to 16 (no api change).
- `socat VSOCK-LISTEN:5000,fork TCP:127.0.0.1:5000` alongside `usbhsm bridge
  --listen tcp:127.0.0.1:5000` (no api change).

Only enable `--allow-remote-mgmt` if you deliberately want provisioning over the
network; by default, `init`/`unlock`/`generateKey`/etc. are local-CLI only.

## 4. Verify end-to-end

```sh
usbhsm self-test
# runs the on-device KATs AND signs a throwaway key, verifying the certificate
# against the device CA with x/crypto/ssh.
```

A full client flow then looks like cerberus's: `ssh-cert-api` authenticates and
authorizes the user, calls the bridge with a `signSshKey` request, and returns
the certificate; the user drops it next to their key and SSHes in. The issued
certificate is byte-identical to one the enclave would have produced (proven by
`make test-diff`), so `ssh-keygen -L` and `sshd` accept it unchanged.

## Operational notes

- **Time**: the device has no RTC. If you run management commands without the
  bridge, `usbhsm set-time` first, or signing fails closed. The bridge handles
  this automatically.
- **Reboots**: dev devices reload the key automatically; prod devices come up
  `prodLocked` and need `unlock` again.
- **Backups**: there is intentionally no key export. To survive device loss, run
  two devices provisioned as the same CA — generate the CA seed out-of-band and
  ... not possible (keys are device-generated). Instead, trust **two** CA public
  keys on your servers (`TrustedUserCAKeys` accepts multiple lines), one per
  device, and keep a spare device provisioned and stored securely.
