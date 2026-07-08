// Package bridge exposes a PicoSignet device's newline-JSON protocol over VSOCK,
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

	"github.com/pkilar/picosignet/host/internal/device"
	"github.com/pkilar/picosignet/host/internal/hsmproto"
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
	// the CLI, pre-split here). Any entry may carry a "+mgmt" suffix (e.g.
	// "unix:/run/picosignet.sock+mgmt") to allow `hsm` management commands on
	// that listener specifically, independent of AllowRemoteMgmt — see the
	// AllowRemoteMgmt doc for why this matters when a single bridge process
	// serves both a trusted local socket and a network-facing one.
	Listen []string
	// AllowRemoteMgmt permits `hsm` management commands from network clients
	// on *every* configured listener. Off by default: provisioning should
	// happen over the local CLI. Because it applies process-wide, enabling it
	// to reach one trusted listener (e.g. a local unix socket) also opens
	// every other listener in the same invocation (e.g. a vsock/tcp listener
	// meant only for ssh-cert-api's signing traffic) — prefer tagging just
	// the listener that needs it with "+mgmt" in Listen instead.
	AllowRemoteMgmt bool
}

type boundListener struct {
	net.Listener
	allowMgmt bool
}

// Run starts the listeners and the time-sync loop, forwarding traffic to conn
// until ctx is cancelled.
func Run(ctx context.Context, conn device.Conn, opts Options) error {
	b := &bridge{conn: conn, allowRemoteMgmt: opts.AllowRemoteMgmt}

	var listeners []boundListener
	for _, spec := range opts.Listen {
		raw, mgmt := splitMgmtSuffix(spec)
		l, err := listen(raw)
		if err != nil {
			for _, prev := range listeners {
				_ = prev.Close()
			}
			return fmt.Errorf("listen %q: %w", spec, err)
		}
		listeners = append(listeners, boundListener{Listener: l, allowMgmt: mgmt})
		if mgmt {
			log.Printf("bridge: listening on %s (management commands allowed)", raw)
		} else {
			log.Printf("bridge: listening on %s", raw)
		}
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
		go func(l boundListener) {
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

// splitMgmtSuffix strips a trailing "+mgmt" from a listen spec, reporting
// whether it was present.
func splitMgmtSuffix(spec string) (string, bool) {
	if raw, ok := strings.CutSuffix(spec, "+mgmt"); ok {
		return raw, true
	}
	return spec, false
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

func (b *bridge) acceptLoop(ctx context.Context, l boundListener) {
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
			b.handleConn(ctx, conn, l.allowMgmt)
		}()
	}
	wg.Wait()
}

func (b *bridge) handleConn(ctx context.Context, conn net.Conn, listenerAllowsMgmt bool) {
	defer func() { _ = conn.Close() }()
	context.AfterFunc(ctx, func() { _ = conn.Close() })

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxRequest)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(connDeadline))
		if !scanner.Scan() {
			return
		}
		resp := b.forward(ctx, scanner.Bytes(), listenerAllowsMgmt)
		_ = conn.SetWriteDeadline(time.Now().Add(connDeadline))
		if _, err := conn.Write(append(resp, '\n')); err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// forward applies the management firewall, then relays the line to the
// device. A line is allowed through if either the process-wide
// AllowRemoteMgmt flag is set, or the listener this connection arrived on was
// specifically tagged "+mgmt" — so opting one trusted listener in doesn't
// silently open every other listener in the same bridge invocation.
func (b *bridge) forward(ctx context.Context, line []byte, listenerAllowsMgmt bool) []byte {
	if !(b.allowRemoteMgmt || listenerAllowsMgmt) && hsmproto.IsManagementLine(line) {
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
