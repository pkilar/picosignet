package bridge

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkilar/cerberus/messages"
	"golang.org/x/crypto/ssh"
)

// simConn drives the hsm-sim binary as a device.Conn, so the bridge can be
// exercised end-to-end without hardware.
type simConn struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func newSimConn(t *testing.T) *simConn {
	t.Helper()
	// Build once; cheap if already current.
	build := exec.Command("cargo", "build", "-p", "hsm-sim")
	build.Dir = "../../.."
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("building hsm-sim: %v", err)
	}
	bin, err := filepath.Abs("../../../target/debug/hsm-sim")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &simConn{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return s
}

func (s *simConn) RoundTrip(_ context.Context, req []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.stdin.Write(append(req, '\n')); err != nil {
		return nil, err
	}
	line, err := s.stdout.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return line[:len(line)-1], nil
}

func (s *simConn) Close() error { return nil }

func (s *simConn) provisionDev(t *testing.T) {
	t.Helper()
	for _, r := range []string{
		`{"hsm":{"init":{"mode":"dev"}}}`,
		`{"hsm":{"generateKey":{}}}`,
	} {
		if _, err := s.RoundTrip(context.Background(), []byte(r)); err != nil {
			t.Fatalf("provisioning: %v", err)
		}
	}
}

// startBridge runs a bridge over a unix socket and returns its path.
func startBridge(t *testing.T, conn *simConn, allowRemoteMgmt bool) string {
	t.Helper()
	socks := startBridgeListeners(t, conn, allowRemoteMgmt, []string{"unix:" + newSockPath(t)})
	return socks[0]
}

// startBridgeListeners runs a bridge over one or more unix-socket listeners,
// each described by a "unix:<path>" spec (optionally with a "+mgmt" suffix,
// which startBridgeMgmt below appends), and returns the socket paths in the
// same order.
func startBridgeListeners(t *testing.T, conn *simConn, allowRemoteMgmt bool, specs []string) []string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = Run(ctx, conn, Options{Listen: specs, AllowRemoteMgmt: allowRemoteMgmt})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	var socks []string
	for _, spec := range specs {
		raw, _ := strings.CutSuffix(spec, "+mgmt")
		_, path, _ := strings.Cut(raw, ":")
		socks = append(socks, path)
	}
	for _, sock := range socks {
		waitForSocket(t, sock)
	}
	return socks
}

func newSockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "PicoSignet.sock")
}

func waitForSocket(t *testing.T, sock string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bridge socket %q never appeared", sock)
}

func dialAndExchange(t *testing.T, sock string, req []byte) []byte {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(append(req, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	return line[:len(line)-1]
}

func TestBridgeForwardsSignAndVerifies(t *testing.T) {
	sim := newSimConn(t)
	sim.provisionDev(t)
	// Fetch the CA public key directly from the device.
	caResp, _ := sim.RoundTrip(context.Background(), []byte(`{"hsm":{"getPublicKey":{}}}`))
	var caEnv struct {
		Hsm struct {
			GetPublicKey struct {
				PublicKey string `json:"publicKey"`
			} `json:"getPublicKey"`
		} `json:"hsm"`
	}
	if err := json.Unmarshal(caResp, &caEnv); err != nil {
		t.Fatal(err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caEnv.Hsm.GetPublicKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	sock := startBridge(t, sim, false)

	// The bridge's time sync runs at startup; give it a moment, then ping.
	time.Sleep(50 * time.Millisecond)
	pong := dialAndExchange(t, sock, []byte(`{"ping":{}}`))
	var pongResp messages.Response
	if err := json.Unmarshal(pong, &pongResp); err != nil {
		t.Fatal(err)
	}
	if pongResp.Pong == nil || !pongResp.Pong.SignerLoaded {
		t.Fatalf("expected signerLoaded=true after time sync, got %s", pong)
	}

	// Sign through the bridge using the cerberus message types.
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshUser, _ := ssh.NewPublicKey(userPub)
	userLine := string(ssh.MarshalAuthorizedKey(sshUser))
	signReq, _ := json.Marshal(messages.Request{SignSshKey: &messages.EnclaveSigningRequest{
		SSHKey:     userLine,
		KeyID:      "bridge-test",
		Principals: []string{"alice"},
		Validity:   "1h",
	}})
	raw := dialAndExchange(t, sock, signReq)
	var signResp messages.Response
	if err := json.Unmarshal(raw, &signResp); err != nil {
		t.Fatal(err)
	}
	if signResp.Error != nil {
		t.Fatalf("sign error: %s", *signResp.Error)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signResp.SignSshKey.SignedKey))
	if err != nil {
		t.Fatal(err)
	}
	cert := parsed.(*ssh.Certificate)
	c2 := *cert
	c2.Signature = nil
	signed := c2.Marshal()
	if err := caPub.Verify(signed[:len(signed)-4], cert.Signature); err != nil {
		t.Fatalf("certificate from bridge does not verify: %v", err)
	}
}

func TestBridgeFirewallsManagement(t *testing.T) {
	sim := newSimConn(t)
	sim.provisionDev(t)
	sock := startBridge(t, sim, false)

	raw := dialAndExchange(t, sock, []byte(`{"hsm":{"status":{}}}`))
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "management commands are not permitted over the network" {
		t.Fatalf("expected firewall rejection, got %q", raw)
	}
}

func TestBridgeAllowsManagementWhenEnabled(t *testing.T) {
	sim := newSimConn(t)
	sim.provisionDev(t)
	sock := startBridge(t, sim, true)

	raw := dialAndExchange(t, sock, []byte(`{"hsm":{"status":{}}}`))
	if !contains(raw, []byte(`"state"`)) {
		t.Fatalf("expected a status response, got %q", raw)
	}
}

func TestBridgeListenerMgmtSuffixAllowsManagement(t *testing.T) {
	sim := newSimConn(t)
	sim.provisionDev(t)
	// AllowRemoteMgmt is off; only the listener's own "+mgmt" tag should open it.
	socks := startBridgeListeners(t, sim, false, []string{"unix:" + newSockPath(t) + "+mgmt"})

	raw := dialAndExchange(t, socks[0], []byte(`{"hsm":{"status":{}}}`))
	if !contains(raw, []byte(`"state"`)) {
		t.Fatalf("expected a status response from the +mgmt listener, got %q", raw)
	}
}

func TestBridgeListenerMgmtSuffixDoesNotLeakToOtherListeners(t *testing.T) {
	sim := newSimConn(t)
	sim.provisionDev(t)
	// Regression test: tagging one listener "+mgmt" must not open management
	// on a second, untagged listener in the same bridge process.
	mgmtSock := "unix:" + newSockPath(t) + "+mgmt"
	plainSock := "unix:" + newSockPath(t)
	socks := startBridgeListeners(t, sim, false, []string{mgmtSock, plainSock})

	raw := dialAndExchange(t, socks[0], []byte(`{"hsm":{"status":{}}}`))
	if !contains(raw, []byte(`"state"`)) {
		t.Fatalf("expected a status response from the +mgmt listener, got %q", raw)
	}

	var resp struct {
		Error string `json:"error"`
	}
	raw = dialAndExchange(t, socks[1], []byte(`{"hsm":{"status":{}}}`))
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "management commands are not permitted over the network" {
		t.Fatalf("expected the untagged listener to still firewall management, got %q", raw)
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
