// Package cli implements the PicoSignet provisioning/management commands and the
// bridge launcher.
package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkilar/cerberus/messages"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/pkilar/picosignet/host/internal/bridge"
	"github.com/pkilar/picosignet/host/internal/device"
	"github.com/pkilar/picosignet/host/internal/hsmproto"
)

// Run dispatches a subcommand. Returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "bridge":
		err = cmdBridge(rest)
	case "init":
		err = cmdInit(rest)
	case "generate-key":
		err = cmdGenerateKey(rest)
	case "pubkey":
		err = cmdPubkey(rest)
	case "unlock":
		err = cmdUnlock(rest)
	case "lock":
		err = cmdSimple(rest, "lock", &hsmproto.Request{Lock: &hsmproto.Empty{}})
	case "status":
		err = cmdStatus(rest)
	case "set-time":
		err = cmdSetTime(rest)
	case "change-pin":
		err = cmdChangePin(rest)
	case "factory-reset":
		err = cmdFactoryReset(rest)
	case "self-test":
		err = cmdSelfTest(rest)
	case "add-entropy":
		err = cmdAddEntropy(rest)
	case "reboot-bootloader":
		err = cmdRebootBootloader(rest)
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "picosignet: unknown command %q\n", cmd)
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "picosignet %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `PicoSignet — RP2350 SSH-certificate HSM companion

usage: picosignet <command> [flags]

  bridge         expose the device over vsock/tcp/unix for ssh-cert-api
  init           initialize the device (dev or prod mode)
  generate-key   generate the on-device Ed25519 CA key
  pubkey         print the CA public key (authorized_keys line)
  unlock         unlock a production-mode device with its PIN
  lock           re-lock a production-mode device
  status         print device status
  set-time       push wall-clock time to the device
  change-pin     change the production-mode PIN
factory-reset  erase all keys and config (destructive; prompts for the PIN
               in prod mode; forgotten-PIN recovery requires GPIO15 low at reset)
  self-test      run on-device self-tests and an end-to-end signing check
  add-entropy    mix host-supplied entropy into the device pool
reboot-bootloader  reset the device into the USB bootloader (for reflashing;
               prompts for the PIN in prod mode; recovery requires GPIO15 low at reset)

Common flags: --port <path> (default: auto-discover), --timeout <dur>
`)
}

// ---- device helpers -------------------------------------------------------

type commonFlags struct {
	port    string
	timeout time.Duration
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.StringVar(&c.port, "port", "", "serial device path (default: auto-discover)")
	fs.DurationVar(&c.timeout, "timeout", device.DefaultTimeout, "per-request timeout")
	return c
}

func openDevice(c *commonFlags) (*device.Serial, error) {
	return device.Open(c.port, c.timeout)
}

// sendHsm round-trips one management request and returns the response body,
// surfacing a structured device error as a Go error.
func sendHsm(conn device.Conn, req *hsmproto.Request, timeout time.Duration) (*hsmproto.ResponseBody, error) {
	line, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	raw, err := conn.RoundTrip(ctx, line)
	if err != nil {
		return nil, err
	}
	var resp hsmproto.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w (%q)", err, raw)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("device: %s", *resp.Error)
	}
	if resp.Hsm == nil {
		return nil, fmt.Errorf("empty response: %q", raw)
	}
	if e := resp.Hsm.Error; e != nil {
		if e.RemainingAttempts != nil {
			return nil, fmt.Errorf("%s: %s (%d attempts remaining)", e.Code, e.Message, *e.RemainingAttempts)
		}
		return nil, fmt.Errorf("%s: %s", e.Code, e.Message)
	}
	return resp.Hsm, nil
}

// devicePromptsForPin reports whether factory-reset/reboot-bootloader should
// prompt for a PIN: only in prod mode, where the device actually gates on
// one. Dev mode and an uninitialized device ignore the field, so skip
// pestering the operator for it there. Any status error falls back to
// prompting — better an unnecessary prompt than silently skipping a PIN the
// device actually requires.
func devicePromptsForPin(conn device.Conn, timeout time.Duration) bool {
	body, err := sendHsm(conn, &hsmproto.Request{Status: &hsmproto.Empty{}}, timeout)
	if err != nil || body.Status == nil {
		return true
	}
	return body.Status.Mode == "prod"
}

// pipedStdin is a persistent reader for non-interactive PIN entry, so a
// multi-prompt flow (change-pin) reads successive lines correctly.
var pipedStdin *bufio.Reader

func readSecret(prompt string) (string, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// Non-interactive: read one line from stdin (automation / HIL).
	if pipedStdin == nil {
		pipedStdin = bufio.NewReader(os.Stdin)
	}
	line, err := pipedStdin.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" && err != nil {
		return "", errors.New("no PIN available on stdin")
	}
	return line, nil
}

// ---- commands -------------------------------------------------------------

func cmdBridge(args []string) error {
	fs := flag.NewFlagSet("bridge", flag.ContinueOnError)
	c := bindCommon(fs)
	listen := fs.String("listen", "vsock:5000", "comma-separated listeners: vsock:PORT,tcp:HOST:PORT,unix:PATH; "+
		"suffix an individual entry with +mgmt (e.g. unix:/run/picosignet.sock+mgmt) to allow hsm management "+
		"commands on just that listener")
	allowRemoteMgmt := fs.Bool("allow-remote-mgmt", false, "permit hsm management commands from network clients "+
		"on every listener (prefer tagging one listener with +mgmt instead — see --listen)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return bridge.Run(ctx, conn, bridge.Options{
		Listen:          splitNonEmpty(*listen),
		AllowRemoteMgmt: *allowRemoteMgmt,
	})
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	c := bindCommon(fs)
	prod := fs.Bool("prod", false, "initialize in production mode (requires a PIN)")
	maxRetries := fs.Uint("max-retries", 10, "production PIN retry budget")
	wipe := fs.Bool("wipe-on-lockout", false, "erase the key when the retry budget is exhausted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prod && (*maxRetries == 0 || *maxRetries > 255) {
		return errors.New("--max-retries must be between 1 and 255")
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := &hsmproto.InitReq{Mode: "dev"}
	if *prod {
		pin, err := readSecret("New PIN: ")
		if err != nil {
			return err
		}
		confirm, err := readSecret("Confirm PIN: ")
		if err != nil {
			return err
		}
		if pin != confirm {
			return errors.New("PINs do not match")
		}
		mr := uint8(*maxRetries)
		req = &hsmproto.InitReq{Mode: "prod", Pin: pin, MaxRetries: &mr, WipeOnLockout: wipe}
	}
	body, err := sendHsm(conn, &hsmproto.Request{Init: req}, c.timeout)
	if err != nil {
		return err
	}
	fmt.Printf("initialized in %s mode\n", body.Init.Mode)
	return nil
}

func cmdGenerateKey(args []string) error {
	fs := flag.NewFlagSet("generate-key", flag.ContinueOnError)
	c := bindCommon(fs)
	force := fs.Bool("force", false, "overwrite an existing key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	body, err := sendHsm(conn, &hsmproto.Request{GenerateKey: &hsmproto.GenerateKey{Force: *force}}, c.timeout)
	if err != nil {
		return err
	}
	fmt.Println(body.GenerateKey.PublicKey)
	return nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	body, err := sendHsm(conn, &hsmproto.Request{GetPublicKey: &hsmproto.Empty{}}, c.timeout)
	if err != nil {
		return err
	}
	fmt.Println(body.GetPublicKey.PublicKey)
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	pin, err := readSecret("PIN: ")
	if err != nil {
		return err
	}
	if _, err := sendHsm(conn, &hsmproto.Request{Unlock: &hsmproto.PinReq{Pin: pin}}, c.timeout); err != nil {
		return err
	}
	fmt.Println("unlocked")
	return nil
}

func cmdSimple(args []string, name string, req *hsmproto.Request) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := sendHsm(conn, req, c.timeout); err != nil {
		return err
	}
	fmt.Printf("%s: ok\n", name)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	body, err := sendHsm(conn, &hsmproto.Request{Status: &hsmproto.Empty{}}, c.timeout)
	if err != nil {
		return err
	}
	s := body.Status
	fmt.Printf("state:        %s\n", s.State)
	fmt.Printf("mode:         %s\n", s.Mode)
	fmt.Printf("key present:  %t\n", s.KeyPresent)
	fmt.Printf("unlocked:     %t\n", s.Unlocked)
	fmt.Printf("clock set:    %t\n", s.ClockSet)
	if s.RetryRemaining != nil {
		fmt.Printf("retries left: %d\n", *s.RetryRemaining)
	}
	fmt.Printf("firmware:     %s\n", s.FwVersion)
	fmt.Printf("serial:       %s\n", s.Serial)
	fmt.Printf("otp secret:   %t\n", s.OtpSecret)
	fmt.Printf("glitch det:   %t\n", s.GlitchArmed)
	fmt.Printf("secure boot:  %t\n", s.SecureBoot)
	if s.GlitchReset {
		fmt.Printf("WARNING: last reset was a glitch-detector trigger\n")
	}
	return nil
}

func cmdSetTime(args []string) error {
	fs := flag.NewFlagSet("set-time", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	unix := time.Now().Unix()
	if fs.NArg() > 0 {
		v, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid unix time: %w", err)
		}
		unix = v
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := sendHsm(conn, &hsmproto.Request{SetTime: &hsmproto.SetTimeReq{UnixSeconds: unix}}, c.timeout); err != nil {
		return err
	}
	fmt.Printf("clock set to %s\n", time.Unix(unix, 0).UTC().Format(time.RFC3339))
	return nil
}

func cmdChangePin(args []string) error {
	fs := flag.NewFlagSet("change-pin", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	cur, err := readSecret("Current PIN: ")
	if err != nil {
		return err
	}
	next, err := readSecret("New PIN: ")
	if err != nil {
		return err
	}
	confirm, err := readSecret("Confirm new PIN: ")
	if err != nil {
		return err
	}
	if next != confirm {
		return errors.New("new PINs do not match")
	}
	if _, err := sendHsm(conn, &hsmproto.Request{ChangePin: &hsmproto.ChangePinReq{CurrentPin: cur, NewPin: next}}, c.timeout); err != nil {
		return err
	}
	fmt.Println("PIN changed")
	return nil
}

func cmdFactoryReset(args []string) error {
	fs := flag.NewFlagSet("factory-reset", flag.ContinueOnError)
	c := bindCommon(fs)
	yes := fs.Bool("yes", false, "skip the interactive confirmation")
	physicalRecovery := fs.Bool("physical-recovery", false, "GPIO15 was held low during device reset; suppress PIN prompt only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes {
		fmt.Fprint(os.Stderr, "This ERASES the CA key and all config. Type ERASE to confirm: ")
		var typed string
		_, _ = fmt.Scanln(&typed)
		if typed != "ERASE" {
			return errors.New("aborted")
		}
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := &hsmproto.FactoryResetReq{Confirm: "ERASE"}
	if !*physicalRecovery && devicePromptsForPin(conn, c.timeout) {
		pin, err := readSecret("PIN: ")
		if err != nil {
			return err
		}
		req.Pin = pin
	}
	if _, err := sendHsm(conn, &hsmproto.Request{FactoryReset: req}, c.timeout); err != nil {
		return err
	}
	fmt.Println("device erased")
	return nil
}

func cmdRebootBootloader(args []string) error {
	fs := flag.NewFlagSet("reboot-bootloader", flag.ContinueOnError)
	c := bindCommon(fs)
	physicalRecovery := fs.Bool("physical-recovery", false, "GPIO15 was held low during device reset; suppress PIN prompt only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := &hsmproto.RebootBootloader{}
	if !*physicalRecovery && devicePromptsForPin(conn, c.timeout) {
		pin, err := readSecret("PIN: ")
		if err != nil {
			return err
		}
		req.Pin = pin
	}
	// The device acks, then resets into BOOTSEL ~80ms later and disconnects.
	if _, err := sendHsm(conn, &hsmproto.Request{RebootBootloader: req}, c.timeout); err != nil {
		return err
	}
	fmt.Println("rebooting into BOOTSEL; the device will appear as the RPI-RP2 drive")
	return nil
}

func cmdAddEntropy(args []string) error {
	fs := flag.NewFlagSet("add-entropy", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: picosignet add-entropy <hex>")
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := sendHsm(conn, &hsmproto.Request{AddEntropy: &hsmproto.AddEntropy{Hex: fs.Arg(0)}}, c.timeout); err != nil {
		return err
	}
	fmt.Println("entropy mixed")
	return nil
}

// cmdSelfTest runs the device's KAT self-test and an end-to-end signing check:
// it signs a freshly generated key and verifies the certificate with
// x/crypto/ssh against the device's CA public key.
func cmdSelfTest(args []string) error {
	fs := flag.NewFlagSet("self-test", flag.ContinueOnError)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := openDevice(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	// On-device KATs.
	body, err := sendHsm(conn, &hsmproto.Request{SelfTest: &hsmproto.Empty{}}, c.timeout)
	if err != nil {
		return err
	}
	st := body.SelfTest
	fmt.Printf("device self-test: ok=%t ed25519=%s sha2=%s aead=%s drbg=%s flash=%s otp=%s\n",
		st.Ok, st.Tests.Ed25519Kat, st.Tests.Sha2Kat, st.Tests.AeadKat, st.Tests.DrbgHealth, st.Tests.FlashCrc, st.Tests.OtpSecret)
	if !st.Ok {
		return errors.New("on-device self-test failed")
	}

	// End-to-end signing check.
	pkBody, err := sendHsm(conn, &hsmproto.Request{GetPublicKey: &hsmproto.Empty{}}, c.timeout)
	if err != nil {
		return fmt.Errorf("getting CA public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pkBody.GetPublicKey.PublicKey))
	if err != nil {
		return fmt.Errorf("parsing CA public key: %w", err)
	}

	// Ensure the device has a clock (sign fails closed otherwise).
	if _, err := sendHsm(conn, &hsmproto.Request{SetTime: &hsmproto.SetTimeReq{UnixSeconds: time.Now().Unix()}}, c.timeout); err != nil {
		return err
	}

	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sshUser, err := ssh.NewPublicKey(userPub)
	if err != nil {
		return err
	}
	userLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshUser)))

	signReq := messages.Request{SignSshKey: &messages.EnclaveSigningRequest{
		SSHKey:     userLine,
		KeyID:      "picosignet-self-test",
		Principals: []string{"selftest"},
		Validity:   "5m",
	}}
	reqLine, err := json.Marshal(signReq)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	raw, err := conn.RoundTrip(ctx, reqLine)
	if err != nil {
		return err
	}
	var signResp messages.Response
	if err := json.Unmarshal(raw, &signResp); err != nil {
		return fmt.Errorf("decoding sign response: %w", err)
	}
	if signResp.Error != nil {
		return fmt.Errorf("signing: %s", *signResp.Error)
	}
	if signResp.SignSshKey == nil || signResp.SignSshKey.SignedKey == "" {
		return errors.New("no certificate in response")
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signResp.SignSshKey.SignedKey))
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return errors.New("signed key is not a certificate")
	}
	if err := caPub.Verify(bytesForSigning(cert), cert.Signature); err != nil {
		return fmt.Errorf("certificate signature does not verify: %w", err)
	}
	fmt.Println("end-to-end signing check: ok (certificate verifies against the device CA)")
	return nil
}

func bytesForSigning(cert *ssh.Certificate) []byte {
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	return out[:len(out)-4]
}

func splitNonEmpty(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
