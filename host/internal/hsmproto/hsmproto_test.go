package hsmproto

import "testing"

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
