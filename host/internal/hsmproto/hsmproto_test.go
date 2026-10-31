package hsmproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pkilar/cerberus/messages"
)

// SignerLine drops every key that is not a signer variant, so a variant added
// to cerberus would vanish at the bridge without this check.
func TestSignerVariantsMatchCerberus(t *testing.T) {
	rt := reflect.TypeFor[messages.Request]()
	var tags []string
	for i := range rt.NumField() {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		tags = append(tags, name)
	}
	if !slices.Equal(tags, signerVariants[:]) {
		t.Fatalf("messages.Request has JSON keys %q; signerVariants is %q", tags, signerVariants)
	}
}

func TestIsManagementLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`{"hsm":{"status":{}}}`, true},
		{`{"hsm":{"unlock":{"pin":"x"}}}`, true},
		{`{"ping":{}}`, false},
		{`{"signSshKey":{"ssh_key":"x"}}`, false},
		{`{"getEnclaveMetrics":{}}`, false},
		{`{}`, false},
		// Fails closed: a line the firewall cannot read is refused.
		{`not json`, true},
		{``, true},
		{`{"hsm":null}`, true},
		// serde fills the request struct from an array by position; the fifth
		// element is `hsm`.
		{`[null,null,null,null,{"factoryReset":{"confirm":"ERASE"}}]`, true},
		// encoding/json matches keys in any case (last one wins), serde only
		// exactly. ſ (U+017F) folds to s.
		{`{"hsm":{"factoryReset":{"confirm":"ERASE"}},"HSM":null}`, true},
		{`{"hsm":{"factoryReset":{"confirm":"ERASE"}},"hſm":null}`, true},
		{`{"hsm":{"factoryReset":{"confirm":"ERASE"}},"hsm":null}`, true},
		// A JSON escape spells the same key.
		{`{"\u0068sm":{"status":{}}}`, true},
	}
	for _, tc := range cases {
		if got := IsManagementLine([]byte(tc.line)); got != tc.want {
			t.Errorf("IsManagementLine(%q) = %t, want %t", tc.line, got, tc.want)
		}
	}
}

func TestSignerLine(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{`{"ping":{}}`, `{"ping":{}}`},
		{` { "signSshKey" : { "ssh_key" : "x", "principals" : [ "a" ] } } `, `{"signSshKey":{"ssh_key":"x","principals":["a"]}}`},
		// Values reach the device unchanged: no HTML escaping.
		{`{"signSshKey":{"key_id":"<a&b>"}}`, `{"signSshKey":{"key_id":"<a&b>"}}`},
		// Only top-level keys select a command; the device ignores a nested hsm.
		{`{"ping":{"hsm":{"status":{}}}}`, `{"ping":{"hsm":{"status":{}}}}`},
		// Keys the device would ignore are dropped, including near-miss cases.
		{`{"ping":{},"extra":{"hsm":{}}}`, `{"ping":{}}`},
		{`{"ping":{},"x":1,"x":2}`, `{"ping":{}}`},
		{`{"Ping":{}}`, `{}`},
		{`{}`, `{}`},
		// A fixed order; the device itself rejects more than one variant.
		{`{"getEnclaveMetrics":{},"loadKeySigner":{"credentials":{}}}`, `{"loadKeySigner":{"credentials":{}},"getEnclaveMetrics":{}}`},
	}
	for _, tc := range cases {
		got, err := SignerLine([]byte(tc.line))
		if err != nil || string(got) != tc.want {
			t.Errorf("SignerLine(%q) = %q, %v; want %q", tc.line, got, err, tc.want)
		}
	}
}

func TestSignerLineRejects(t *testing.T) {
	management := []string{
		`{"hsm":{"status":{}}}`,
		`{"hsm":null}`,
		`{"ping":{},"hsm":{"status":{}}}`,
		`{"HSM":{"status":{}}}`,
		`{"hsm":{"factoryReset":{"confirm":"ERASE"}},"HSM":null}`,
		`{"hsm":{"factoryReset":{"confirm":"ERASE"}},"Hsm":null}`,
		`{"hsm":{"factoryReset":{"confirm":"ERASE"}},"hſm":null}`,
		`{"\u0068sm":{"status":{}}}`,
	}
	for _, line := range management {
		if _, err := SignerLine([]byte(line)); !errors.Is(err, ErrManagementLine) {
			t.Errorf("SignerLine(%q) error = %v, want ErrManagementLine", line, err)
		}
	}

	malformed := []string{
		``,
		`not json`,
		`null`,
		`"ping"`,
		`[null,null,null,null,{"factoryReset":{"confirm":"ERASE"}}]`,
		`{"ping":{}`,
		`{"ping":{},}`,
		`{"ping" {}}`,
		`{"ping":{}} {"hsm":{"status":{}}}`,
		`{"ping":{}}x`,
		`{"ping":{},"ping":{}}`,
	}
	for _, line := range malformed {
		got, err := SignerLine([]byte(line))
		if err == nil || errors.Is(err, ErrManagementLine) {
			t.Errorf("SignerLine(%q) = %q, %v; want a parse error", line, got, err)
		}
	}
}

// FuzzSignerLine checks that whatever SignerLine accepts becomes one JSON
// object on one line, holding only signer-path variants, and that the result
// is a fixed point.
func FuzzSignerLine(f *testing.F) {
	for _, s := range []string{
		`{"ping":{}}`,
		`{"signSshKey":{"ssh_key":"x","principals":["a"]}}`,
		`{"Ping":{},"ping":{},"x":[1,{"y":null}]}`,
		`[null,null,null,null,{"status":{}}]`,
		`{"hsm":{"status":{}},"HSM":null}`,
		`{}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		out, err := SignerLine(line)
		if err != nil {
			return
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("SignerLine(%q) = %q, which is not a JSON object: %v", line, out, err)
		}
		for k := range m {
			if !slices.Contains(signerVariants[:], k) {
				t.Fatalf("SignerLine(%q) = %q, which keeps key %q", line, out, k)
			}
		}
		if bytes.ContainsAny(out, "\r\n") {
			t.Fatalf("SignerLine(%q) = %q, which spans lines", line, out)
		}
		if again, err := SignerLine(out); err != nil || !bytes.Equal(again, out) {
			t.Fatalf("SignerLine(%q) = %q, %v; want the same line back", out, again, err)
		}
	})
}

func TestRecoveryRequestsDoNotMarshalForce(t *testing.T) {
	for _, r := range []*Request{
		{FactoryReset: &FactoryResetReq{Confirm: "ERASE"}},
		{RebootBootloader: &RebootBootloader{}},
	} {
		b, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "force") {
			t.Fatalf("recovery request unexpectedly contains force: %s", b)
		}
	}
}

func TestRequestMarshal(t *testing.T) {
	r := &Request{SetTime: &SetTimeReq{UnixSeconds: 1700000000}}
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"hsm":{"setTime":{"unixSeconds":1700000000}}}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", b, want)
	}
}
