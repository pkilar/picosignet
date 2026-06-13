// Differential tests: drive the PicoSignet simulator and verify every issued
// certificate against golang.org/x/crypto/ssh — the exact library cerberus
// ssh-cert-signer uses. The decisive check is a round-trip: x/crypto parses the
// HSM's certificate and re-marshals it; if the bytes are identical, the HSM's
// hand-rolled encoder is byte-for-byte compatible with Go's. We also verify the
// CA signature and assert rejection parity for invalid requests.
package differential

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var simBinary string

func TestMain(m *testing.M) {
	// Build the simulator so the tests run against current sources.
	build := exec.Command("cargo", "build", "-p", "hsm-sim")
	build.Dir = "../.."
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		println("failed to build hsm-sim:", err.Error())
		os.Exit(1)
	}
	abs, err := filepath.Abs("../../target/debug/hsm-sim")
	if err != nil {
		panic(err)
	}
	simBinary = abs
	os.Exit(m.Run())
}

// session drives one hsm-sim process over stdin/stdout.
type session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	t      *testing.T
}

func newSession(t *testing.T) *session {
	t.Helper()
	cmd := exec.Command(simBinary)
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
	s := &session{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), t: t}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return s
}

// call sends one request line and decodes the one-line response.
func (s *session) call(req string) map[string]any {
	s.t.Helper()
	if _, err := io.WriteString(s.stdin, req+"\n"); err != nil {
		s.t.Fatal(err)
	}
	line, err := s.stdout.ReadBytes('\n')
	if err != nil {
		s.t.Fatalf("reading response: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(line, &out); err != nil {
		s.t.Fatalf("response not JSON: %v (%q)", err, line)
	}
	return out
}

// provisionDev returns a ready-to-sign dev session and the CA public key.
func provisionDev(t *testing.T, unixTime int64) (*session, ssh.PublicKey) {
	s := newSession(t)
	s.call(`{"hsm":{"init":{"mode":"dev"}}}`)
	gen := s.call(`{"hsm":{"generateKey":{}}}`)
	caLine := gen["hsm"].(map[string]any)["generateKey"].(map[string]any)["publicKey"].(string)
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caLine))
	if err != nil {
		t.Fatalf("parsing CA key: %v", err)
	}
	s.call(`{"hsm":{"setTime":{"unixSeconds":` + itoa(unixTime) + `}}}`)
	return s, caPub
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// signReq builds a signSshKey request.
func signReq(sshKey, keyID string, principals []string, validity string, perms, custom, crit map[string]string) string {
	req := map[string]any{
		"ssh_key":    sshKey,
		"key_id":     keyID,
		"principals": principals,
		"validity":   validity,
	}
	if perms != nil {
		req["permissions"] = perms
	}
	if custom != nil {
		req["custom_attributes"] = custom
	}
	if crit != nil {
		req["critical_options"] = crit
	}
	b, _ := json.Marshal(map[string]any{"signSshKey": req})
	return string(b)
}

func mustUserKey(t *testing.T, pub any) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func ed25519Key(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return mustUserKey(t, pub)
}

func rsaKey(t *testing.T, bits int) string {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return mustUserKey(t, &k.PublicKey)
}

func ecdsaKey(t *testing.T, curve elliptic.Curve) string {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mustUserKey(t, &k.PublicKey)
}

// extractCert pulls the *ssh.Certificate out of a sign response.
func extractCert(t *testing.T, resp map[string]any) *ssh.Certificate {
	t.Helper()
	sign, ok := resp["signSshKey"].(map[string]any)
	if !ok {
		t.Fatalf("no signSshKey in response: %v", resp)
	}
	line := sign["signed_key"].(string)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("x/crypto/ssh could not parse the HSM certificate: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is not a certificate: %T", pub)
	}
	// The decisive byte-for-byte differential check: re-marshal via x/crypto and
	// compare to the HSM's wire bytes.
	rawB64 := strings.Fields(line)[1]
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Marshal(), raw) {
		t.Fatalf("certificate is not byte-identical to x/crypto/ssh re-marshal\n got %d bytes\n want %d bytes", len(raw), len(cert.Marshal()))
	}
	return cert
}

// verifyCASignature checks the CA signature exactly as x/crypto/ssh does
// internally (bytes-for-signing = Marshal with nil signature, minus the
// trailing length).
func verifyCASignature(t *testing.T, cert *ssh.Certificate, caPub ssh.PublicKey) {
	t.Helper()
	if err := caPub.Verify(bytesForSigning(cert), cert.Signature); err != nil {
		t.Fatalf("CA signature does not verify: %v", err)
	}
}

func bytesForSigning(cert *ssh.Certificate) []byte {
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	return out[:len(out)-4]
}

func TestCertificateRoundTripsAndVerifies(t *testing.T) {
	const now = int64(1700000000)
	s, caPub := provisionDev(t, now)

	cases := []struct {
		name     string
		userKey  string
		validity string
		wantSecs int64
		perms    map[string]string
		custom   map[string]string
		crit     map[string]string
	}{
		{name: "ed25519/1h", userKey: ed25519Key(t), validity: "1h", wantSecs: 3600},
		{name: "rsa2048/8h", userKey: rsaKey(t, 2048), validity: "8h", wantSecs: 8 * 3600},
		{name: "rsa4096/30m", userKey: rsaKey(t, 4096), validity: "30m", wantSecs: 1800},
		{name: "ecdsa256/24h", userKey: ecdsaKey(t, elliptic.P256()), validity: "24h", wantSecs: 24 * 3600},
		{name: "ecdsa384/12h", userKey: ecdsaKey(t, elliptic.P384()), validity: "12h", wantSecs: 12 * 3600},
		{name: "ecdsa521/1h", userKey: ecdsaKey(t, elliptic.P521()), validity: "1h", wantSecs: 3600},
		{
			name: "ext+crit", userKey: ed25519Key(t), validity: "2h30m", wantSecs: 2*3600 + 30*60,
			perms:  map[string]string{"permit-pty": "", "permit-X11-forwarding": ""},
			custom: map[string]string{"login@example.com": "alice"},
			crit:   map[string]string{"force-command": "/usr/bin/backup", "source-address": "10.0.0.0/8"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.call(signReq(tc.userKey, "kid-"+tc.name, []string{"alice", "bob"}, tc.validity, tc.perms, tc.custom, tc.crit))
			cert := extractCert(t, resp)
			verifyCASignature(t, cert, caPub)

			if cert.CertType != ssh.UserCert {
				t.Errorf("cert type = %d, want user (%d)", cert.CertType, ssh.UserCert)
			}
			if cert.ValidAfter != uint64(now-300) {
				t.Errorf("ValidAfter = %d, want %d", cert.ValidAfter, now-300)
			}
			if cert.ValidBefore != uint64(now+tc.wantSecs) {
				t.Errorf("ValidBefore = %d, want %d", cert.ValidBefore, now+tc.wantSecs)
			}
			if got := cert.ValidPrincipals; len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
				t.Errorf("principals = %v", got)
			}
			// Extensions = permissions ∪ custom_attributes.
			for k, v := range tc.perms {
				if cert.Extensions[k] != v {
					t.Errorf("extension %q = %q, want %q", k, cert.Extensions[k], v)
				}
			}
			for k, v := range tc.custom {
				if cert.Extensions[k] != v {
					t.Errorf("custom-as-extension %q = %q, want %q", k, cert.Extensions[k], v)
				}
			}
			for k, v := range tc.crit {
				if cert.CriticalOptions[k] != v {
					t.Errorf("critical option %q = %q, want %q", k, cert.CriticalOptions[k], v)
				}
			}
		})
	}
}

func TestRejectionParity(t *testing.T) {
	s, _ := provisionDev(t, 1700000000)
	edKey := ed25519Key(t)

	cases := []struct {
		name string
		req  string
		want string // exact top-level error
	}{
		{
			name: "empty-key-id",
			req:  signReq(edKey, "", []string{"a"}, "1h", nil, nil, nil),
			want: "invalid request: KeyID cannot be empty",
		},
		{
			name: "empty-validity",
			req:  signReq(edKey, "k", []string{"a"}, "", nil, nil, nil),
			want: "invalid request: validity duration cannot be empty",
		},
		{
			name: "bad-validity-unit",
			req:  signReq(edKey, "k", []string{"a"}, "5x", nil, nil, nil),
			want: `invalid request: invalid validity duration format: time: unknown unit "x" in duration "5x"`,
		},
		{
			name: "no-principals",
			req:  signReq(edKey, "k", []string{}, "1h", nil, nil, nil),
			want: "invalid request: principals cannot be empty",
		},
		{
			name: "over-max-validity",
			req:  signReq(edKey, "k", []string{"a"}, "25h", nil, nil, nil),
			want: "validity duration 25h0m0s exceeds maximum allowed 24h0m0s",
		},
		{
			name: "rsa-too-small",
			req:  signReq(rsaKey(t, 1024), "k", []string{"a"}, "1h", nil, nil, nil),
			want: "rejected public key: RSA key too small: 1024 bits (minimum 2048)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.call(tc.req)
			got, ok := resp["error"].(string)
			if !ok {
				t.Fatalf("expected top-level error, got %v", resp)
			}
			if got != tc.want {
				t.Errorf("error = %q\n  want %q", got, tc.want)
			}
		})
	}
}

func TestTooManyPrincipals(t *testing.T) {
	s, _ := provisionDev(t, 1700000000)
	principals := make([]string, 101)
	for i := range principals {
		principals[i] = "p" + itoa(int64(i))
	}
	resp := s.call(signReq(ed25519Key(t), "k", principals, "1h", nil, nil, nil))
	want := "invalid request: too many principals: 101 (maximum: 100)"
	if got, _ := resp["error"].(string); got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}
