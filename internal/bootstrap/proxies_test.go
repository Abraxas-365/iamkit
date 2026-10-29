package bootstrap

import "testing"

func TestTrustedProxies(t *testing.T) {
	got, err := trustedProxies(" 10.0.0.0/8, 172.18.0.1 ,fd00::/8,")
	if err != nil || len(got) != 3 || got[0] != "10.0.0.0/8" || got[1] != "172.18.0.1" || got[2] != "fd00::/8" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := trustedProxies(""); err != nil || got != nil {
		t.Fatalf("empty = %v, %v", got, err)
	}
	for _, bad := range []string{"proxy.local", "10.0.0.0/33", "*"} {
		if _, err := trustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckReplicas(t *testing.T) {
	for _, tc := range []struct {
		value   string
		redis   bool
		wantErr bool
		warns   bool
	}{
		{"", false, false, true},
		{"", true, false, false},
		{"1", false, false, false},
		{" 1 ", false, false, false},
		{"3", true, false, false},
		{"2", false, true, false},
		{"10", false, true, false},
		{"0", true, true, false},
		{"-1", true, true, false},
		{"many", true, true, false},
	} {
		warning, err := checkReplicas(tc.value, tc.redis)
		if (err != nil) != tc.wantErr || (warning != "") != tc.warns {
			t.Errorf("checkReplicas(%q, %v) = %q, %v", tc.value, tc.redis, warning, err)
		}
	}
}
