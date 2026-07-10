package hsmproto

import (
	"strings"
	"testing"
)

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
		{`not json`, false},
		{`{"hsm":null}`, false},
		{`{}`, false},
	}
	for _, tc := range cases {
		if got := IsManagementLine([]byte(tc.line)); got != tc.want {
			t.Errorf("IsManagementLine(%q) = %t, want %t", tc.line, got, tc.want)
		}
	}
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
