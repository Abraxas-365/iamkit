package netx

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestPublicAddresses(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "fd00::1": false, "224.0.0.1": false, "::ffff:127.0.0.1": false,
	} {
		if got := Public(net.ParseIP(addr)); got != want {
			t.Errorf("Public(%s) = %v", addr, got)
		}
	}
}

// A guarded dial to loopback fails before connecting, with ErrNotPublic.
func TestGuardedDialerRefusesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = GuardedDialer().DialContext(context.Background(), "tcp", ln.Addr().String())
	if !errors.Is(err, ErrNotPublic) {
		t.Fatalf("dial loopback: got %v, want ErrNotPublic", err)
	}
}
