// Package bridge exposes a usbhsm device's newline-JSON protocol over VSOCK,
// TCP, and Unix sockets, so cerberus ssh-cert-api (or any client of the enclave
// protocol) can talk to the hardware key unmodified. It reproduces the
// enclave's framing and limits (one JSON object per line, 256 KiB max, 32
// concurrent connections, 5 s per-message deadlines) and firewalls device
// management commands away from network clients.
package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/pkilar/usbhsm/host/internal/device"
	"github.com/pkilar/usbhsm/host/internal/hsmproto"
)

const (
	maxConns      = 32
	maxRequest    = 256 * 1024
	connDeadline  = 5 * time.Second
	timeSyncEvery = 5 * time.Minute
)

// Options configures the bridge.
type Options struct {
	// Listen specs: "vsock:PORT", "tcp:HOST:PORT", "unix:PATH" (comma-joined on
	// the CLI, pre-split here).
	Listen []string
	// AllowRemoteMgmt permits `hsm` management commands from network clients.
	// Off by default: provisioning should happen over the local CLI.
	AllowRemoteMgmt bool
}

// Run starts the listeners and the time-sync loop, forwarding traffic to conn
// until ctx is cancelled.
func Run(ctx context.Context, conn device.Conn, opts Options) error {
	b := &bridge{conn: conn, allowRemoteMgmt: opts.AllowRemoteMgmt}

	var listeners []net.Listener
	for _, spec := range opts.Listen {
		l, err := listen(spec)
		if err != nil {
			for _, prev := range listeners {
				_ = prev.Close()
			}
			return fmt.Errorf("listen %q: %w", spec, err)
		}
		listeners = append(listeners, l)
		log.Printf("bridge: listening on %s", spec)
	}
	if len(listeners) == 0 {
		return errors.New("no listeners configured")
	}

	// Close listeners on shutdown to unblock Accept.
	context.AfterFunc(ctx, func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	})

	var wg sync.WaitGroup
	b.syncTime(ctx) // best-effort initial sync
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.timeSyncLoop(ctx)
	}()

	for _, l := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			b.acceptLoop(ctx, l)
		}(l)
	}
	wg.Wait()
	return nil
}

type bridge struct {
	conn            device.Conn
	allowRemoteMgmt bool
}

func listen(spec string) (net.Listener, error) {
	scheme, addr, ok := strings.Cut(spec, ":")
	if !ok {
		return nil, fmt.Errorf("malformed listen spec %q (want scheme:addr)", spec)
	}
	switch scheme {
	case "vsock":
		var port uint32
		if _, err := fmt.Sscanf(addr, "%d", &port); err != nil {
			return nil, fmt.Errorf("invalid vsock port %q: %w", addr, err)
		}
		return vsock.Listen(port, nil)
	case "tcp":
		return net.Listen("tcp", addr)
	case "unix":
		return net.Listen("unix", addr)
	default:
		return nil, fmt.Errorf("unknown listen scheme %q", scheme)
	}
}

func (b *bridge) acceptLoop(ctx context.Context, l net.Listener) {
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("bridge: accept error: %v", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			b.handleConn(ctx, conn)
		}()
	}
	wg.Wait()
}

func (b *bridge) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	context.AfterFunc(ctx, func() { _ = conn.Close() })

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxRequest)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(connDeadline))
		if !scanner.Scan() {
			return
		}
		resp := b.forward(ctx, scanner.Bytes())
		_ = conn.SetWriteDeadline(time.Now().Add(connDeadline))
		if _, err := conn.Write(append(resp, '\n')); err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// forward applies the management firewall, then relays the line to the device.
func (b *bridge) forward(ctx context.Context, line []byte) []byte {
	if !b.allowRemoteMgmt && hsmproto.IsManagementLine(line) {
		return errorLine("management commands are not permitted over the network")
	}
	// Copy: scanner.Bytes() is only valid until the next Scan.
	req := append([]byte(nil), line...)
	resp, err := b.conn.RoundTrip(ctx, req)
	if err != nil {
		return errorLine(fmt.Sprintf("device error: %v", err))
	}
	return resp
}

func (b *bridge) timeSyncLoop(ctx context.Context) {
	t := time.NewTicker(timeSyncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.syncTime(ctx)
		}
	}
}

// syncTime pushes the host's wall clock to the device. Sent by the bridge
// itself, so it bypasses the management firewall.
func (b *bridge) syncTime(ctx context.Context) {
	req := hsmproto.Request{SetTime: &hsmproto.SetTimeReq{UnixSeconds: time.Now().Unix()}}
	line, err := req.Marshal()
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, connDeadline)
	defer cancel()
	if _, err := b.conn.RoundTrip(cctx, line); err != nil {
		log.Printf("bridge: time sync failed: %v", err)
	}
}

func errorLine(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}
