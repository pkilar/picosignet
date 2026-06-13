// Command PicoSignet is the host-side companion to the RP2350 PicoSignet device: a
// bridge daemon that exposes the device over VSOCK/TCP/Unix for cerberus
// ssh-cert-api, plus a provisioning/management CLI. See `PicoSignet help`.
package main

import (
	"os"

	"github.com/pkilar/picosignet/host/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
