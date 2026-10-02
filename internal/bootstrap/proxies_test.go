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
