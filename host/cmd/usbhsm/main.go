// Command usbhsm is the host-side companion to the RP2040 usbhsm device: a
// bridge daemon that exposes the device over VSOCK/TCP/Unix for cerberus
// ssh-cert-api, plus a provisioning/management CLI. See `usbhsm help`.
package main

import (
	"os"

	"github.com/pkilar/usbhsm/host/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
