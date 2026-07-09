// Package device talks to the PicoSignet hardware over its USB CDC-ACM serial port,
// speaking the same newline-delimited JSON the cerberus enclave does. A single
// device processes one request at a time, so RoundTrip is mutex-serialized.
package device

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

// USB identifiers the firmware advertises. 0x1209 is the pid.codes community
// VID; the PID is a PicoSignet allocation (interim — see docs/PROTOCOL.md). The
// product string "PicoSignet" also appears under /dev/serial/by-id for matching.
const (
	usbVID = "1209"
	usbPID = "000A"
)

// DefaultTimeout bounds a single request/response exchange. It must exceed the
// device's slowest operation (Argon2id unlock).
const DefaultTimeout = 10 * time.Second

// maxLine caps an inbound response line.
const maxLine = 64 * 1024

// Conn is the device transport the bridge and CLI depend on.
type Conn interface {
	RoundTrip(ctx context.Context, req []byte) ([]byte, error)
	Close() error
}

// Serial is a Conn backed by a CDC-ACM serial port.
type Serial struct {
	mu      sync.Mutex
	port    serial.Port
	r       *bufio.Reader
	timeout time.Duration
	path    string
	// poisoned is set after any failed exchange: the device may still emit a
	// late response, so the link must be reopened before the next request to
	// avoid delivering a stale response to the wrong caller.
	poisoned bool
}

// Discover finds the device's serial path: first via the stable
// /dev/serial/by-id symlink, then by USB VID:PID enumeration.
func Discover() (string, error) {
	if matches, _ := filepath.Glob("/dev/serial/by-id/*PicoSignet*"); len(matches) > 0 {
		return matches[0], nil
	}
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return "", fmt.Errorf("enumerating serial ports: %w", err)
	}
	for _, p := range ports {
		if !p.IsUSB {
			continue
		}
		if strings.EqualFold(p.VID, usbVID) && strings.EqualFold(p.PID, usbPID) {
			return p.Name, nil
		}
	}
	// No serial port matched. If the device is nonetheless sitting on the USB
	// bus, the problem isn't a missing device but a missing tty: the CDC-ACM
	// driver never bound, so distinguish that case with an actionable message.
	if usbDeviceAttached() {
		return "", fmt.Errorf("PicoSignet is attached to USB (%s:%s) but exposes no serial port — "+
			"the CDC-ACM kernel driver (cdc_acm) is not bound. This usually means the kernel was "+
			"upgraded without rebooting, or cdc_acm is not loaded. Reboot (or run 'sudo modprobe "+
			"cdc_acm'), then retry; or pass --port explicitly", usbVID, usbPID)
	}
	return "", errors.New("no PicoSignet device found (set the path explicitly with --port)")
}

// sysfsUSBRoot is the Linux sysfs directory with one entry per USB device.
// A package variable so tests can point the scan at a synthetic tree.
var sysfsUSBRoot = "/sys/bus/usb/devices"

// usbDeviceAttached reports whether a USB device advertising the PicoSignet
// VID:PID is currently attached. It is a best-effort, Linux-only diagnostic
// that lets Discover tell "device unplugged" apart from "device present but no
// serial port"; on other platforms or any error it reports false so Discover
// falls back to its generic message.
func usbDeviceAttached() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return sysfsHasDevice(sysfsUSBRoot, usbVID, usbPID)
}

// sysfsHasDevice scans a sysfs USB-devices tree for a device whose
// idVendor/idProduct match vid/pid. sysfs writes these as lowercase 4-digit
// hex with a trailing newline, so matching is trimmed and case-insensitive.
// Only device directories carry idVendor, so the glob skips interface nodes.
func sysfsHasDevice(root, vid, pid string) bool {
	vidPaths, err := filepath.Glob(filepath.Join(root, "*", "idVendor"))
	if err != nil {
		return false
	}
	for _, vidPath := range vidPaths {
		gotVID, err := os.ReadFile(vidPath)
		if err != nil || !strings.EqualFold(strings.TrimSpace(string(gotVID)), vid) {
			continue
		}
		gotPID, err := os.ReadFile(filepath.Join(filepath.Dir(vidPath), "idProduct"))
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(gotPID)), pid) {
			return true
		}
	}
	return false
}

// Open opens the device at path. An empty path triggers Discover.
func Open(path string, timeout time.Duration) (*Serial, error) {
	if path == "" {
		discovered, err := Discover()
		if err != nil {
			return nil, err
		}
		path = discovered
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// Baud rate is irrelevant for USB CDC-ACM but the API requires one.
	port, err := serial.Open(path, &serial.Mode{BaudRate: 115200})
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	if err := port.SetReadTimeout(timeout); err != nil {
		_ = port.Close()
		return nil, fmt.Errorf("setting read timeout: %w", err)
	}
	return &Serial{
		port:    port,
		r:       bufio.NewReaderSize(timeoutReader{port}, 4096),
		timeout: timeout,
		path:    path,
	}, nil
}

// RoundTrip writes one request line and reads one response line.
func (s *Serial) RoundTrip(ctx context.Context, req []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A previous exchange failed mid-flight (e.g. a read timeout). The device
	// may still emit that response later, so reopen the port — discarding any
	// buffered or in-flight bytes — before issuing a new request. Otherwise a
	// stale response could be returned to the wrong caller.
	if s.poisoned {
		if err := s.reconnect(); err != nil {
			return nil, fmt.Errorf("recovering serial link: %w", err)
		}
	}

	if d, ok := ctx.Deadline(); ok {
		// Honor a tighter caller deadline by adjusting the port read timeout.
		if remaining := time.Until(d); remaining > 0 && remaining < s.timeout {
			_ = s.port.SetReadTimeout(remaining)
			defer func() { _ = s.port.SetReadTimeout(s.timeout) }()
		}
	}

	line := append(append([]byte(nil), req...), '\n')
	if _, err := s.port.Write(line); err != nil {
		s.poisoned = true
		return nil, fmt.Errorf("writing request: %w", err)
	}
	resp, err := s.r.ReadBytes('\n')
	if err != nil {
		// Any read failure (timeout included) leaves framing desynchronized.
		s.poisoned = true
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(resp) > maxLine {
		// Oversize/garbled framing — treat the link as untrustworthy.
		s.poisoned = true
		return nil, errors.New("response exceeds maximum line length")
	}
	return resp[:len(resp)-1], nil // strip trailing newline
}

// drainTimeout bounds how long reconnect waits for stale bytes to stop
// arriving before trusting the link again.
const drainTimeout = 100 * time.Millisecond

// reconnect closes and reopens the serial port, then actively drains any
// bytes the device emits in the following window before clearing the
// poisoned flag. The caller must hold s.mu.
//
// Reopening the OS handle does not by itself guarantee a clean slate: the
// underlying serial library issues no explicit flush, and a still-in-flight
// device write (e.g. a response to the request the previous, poisoned
// exchange gave up on) can land on the newly reopened port moments later,
// where it would otherwise be misdelivered as the answer to an unrelated
// subsequent request. Draining here is defense-in-depth alongside the
// device-side fix (the firmware no longer blocks a response on PIN backoff,
// which was the main way a reply could arrive this late).
func (s *Serial) reconnect() error {
	if s.port != nil {
		_ = s.port.Close()
	}
	port, err := serial.Open(s.path, &serial.Mode{BaudRate: 115200})
	if err != nil {
		return fmt.Errorf("reopening %s: %w", s.path, err)
	}
	drainStale(port)
	if err := port.SetReadTimeout(s.timeout); err != nil {
		_ = port.Close()
		return fmt.Errorf("setting read timeout: %w", err)
	}
	s.port = port
	s.r = bufio.NewReaderSize(timeoutReader{port}, 4096)
	s.poisoned = false
	return nil
}

// drainStale reads and discards bytes until drainTimeout passes with none
// arriving, or a real read error occurs. Best-effort — it cannot prove the
// link is clean, only reduce the odds of a stale response surviving.
func drainStale(port serial.Port) {
	_ = port.SetReadTimeout(drainTimeout)
	buf := make([]byte, 256)
	for {
		n, err := port.Read(buf)
		if err != nil || n == 0 {
			return
		}
	}
}

// Close closes the underlying port.
func (s *Serial) Close() error {
	return s.port.Close()
}

// timeoutReader converts go.bug.st/serial's (0, nil) timeout signal into an
// error, so bufio's ReadBytes terminates instead of spinning.
type timeoutReader struct {
	p serial.Port
}

func (t timeoutReader) Read(b []byte) (int, error) {
	n, err := t.p.Read(b)
	if err == nil && n == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	return n, err
}
