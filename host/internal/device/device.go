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
	return "", errors.New("no PicoSignet device found (set the path explicitly with --port)")
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

// reconnect closes and reopens the serial port, dropping any buffered or
// in-flight bytes and clearing the poisoned flag. The caller must hold s.mu.
func (s *Serial) reconnect() error {
	if s.port != nil {
		_ = s.port.Close()
	}
	port, err := serial.Open(s.path, &serial.Mode{BaudRate: 115200})
	if err != nil {
		return fmt.Errorf("reopening %s: %w", s.path, err)
	}
	if err := port.SetReadTimeout(s.timeout); err != nil {
		_ = port.Close()
		return fmt.Errorf("setting read timeout: %w", err)
	}
	s.port = port
	s.r = bufio.NewReaderSize(timeoutReader{port}, 4096)
	s.poisoned = false
	return nil
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
