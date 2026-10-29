package oauth

import (
	"slices"
	"strconv"
	"sync"
	"testing"
)

func TestRedirectRegistered(t *testing.T) {
	c := Client{Redirects: []string{"https://app.example.com/cb", "http://127.0.0.1:5000/cb", "http://[::1]/cb", "http://localhost:3000/cb"}}
	for _, ok := range []string{"https://app.example.com/cb", "http://127.0.0.1:5000/cb", "http://127.0.0.1:61234/cb", "http://127.0.0.1/cb", "http://[::1]:4000/cb", "http://localhost:3000/cb"} {
		if !c.RedirectRegistered(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"https://app.example.com/cb/", "https://app.example.com:8443/cb", "http://127.0.0.1:5000/other", "http://127.0.0.1:5000/cb?x=1", "https://127.0.0.1:5000/cb", "http://localhost:3001/cb", "http://[::1]:4000/cb2", ""} {
		if c.RedirectRegistered(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

// D14: external clients and LoopbackAnyPort clients match http://localhost
// on any port; hosts never cross (localhost ≠ 127.0.0.1).
func TestRedirectRegisteredLoopbackAnyPort(t *testing.T) {
	redirects := []string{"http://localhost/callback", "http://127.0.0.1/callback", "https://claude.ai/cb"}
	for name, c := range map[string]Client{
		"external": {Source: SourceCIMD, Redirects: redirects},
		"opt-in":   {LoopbackAnyPort: true, Redirects: redirects},
	} {
		for _, ok := range []string{"http://localhost/callback", "http://localhost:49152/callback", "http://127.0.0.1:61000/callback", "https://claude.ai/cb"} {
			if !c.RedirectRegistered(ok) {
				t.Errorf("%s refused %q", name, ok)
			}
		}
		for _, bad := range []string{"http://localhost:49152/other", "http://localhost:1/callback?x=1", "http://[::1]:5000/callback", "https://localhost:443/callback", "http://user@localhost:5/callback", "http://localhost:5/callback#f", "https://claude.ai:8443/cb"} {
			if c.RedirectRegistered(bad) {
				t.Errorf("%s accepted %q", name, bad)
			}
		}
	}
	// Only localhost registered: 127.0.0.1 never matches it.
	c := Client{Source: SourceCIMD, Redirects: []string{"http://localhost/callback"}}
	if c.RedirectRegistered("http://127.0.0.1:5000/callback") {
		t.Error("127.0.0.1 matched a localhost redirect")
	}
	c = Client{Source: SourceCIMD, Redirects: []string{"http://127.0.0.1/callback"}}
	if c.RedirectRegistered("http://localhost:5000/callback") {
		t.Error("localhost matched a 127.0.0.1 redirect")
	}
	// Registered clients without the opt-in keep exact localhost.
	if (Client{Redirects: redirects}).RedirectRegistered("http://localhost:5000/callback") {
		t.Error("registered client matched localhost on another port")
	}
}

func TestWarnings(t *testing.T) {
	got := Warnings([]string{"https://app.example.com/cb", "http://localhost:3000/cb"}, []string{"http://127.0.0.1/bye"})
	want := []ClientWarning{{Code: WarningLoopbackRedirect, Field: "post_logout_redirect_uris", Value: "http://127.0.0.1/bye"}, {Code: WarningLoopbackRedirect, Field: "redirect_uris", Value: "http://localhost:3000/cb"}}
	if !slices.Equal(got, want) {
		t.Fatalf("Warnings = %v, want %v", got, want)
	}
	if w := Warnings([]string{"https://a.example/cb"}, nil); w == nil || len(w) != 0 {
		t.Fatalf("no warnings = %#v", w)
	}
}

// L5: AdmitRedirect never writes through to the slice the client was built
// from, so clients that share one (a cache, a template) never see each
// other's loopback ports, however many requests run at once.
func TestAdmitRedirectDoesNotLeakAcrossClients(t *testing.T) {
	shared := make([]string, 1, 8) // spare capacity: an append would write into it
	shared[0] = "http://localhost/callback"
	const n = 64
	clients := make([]*Client, n)
	ports := make([]string, n)
	var wg sync.WaitGroup
	for i := range clients {
		clients[i] = &Client{Source: SourceCIMD, Redirects: shared}
		ports[i] = "http://localhost:" + strconv.Itoa(40000+i) + "/callback"
		wg.Add(1)
		go func() {
			defer wg.Done()
			clients[i].AdmitRedirect(ports[i])
		}()
	}
	wg.Wait()
	for i, c := range clients {
		if !slices.Contains(c.Redirects, ports[i]) {
			t.Errorf("client %d lost its own port", i)
		}
		for j, other := range ports {
			if j != i && slices.Contains(c.Redirects, other) {
				t.Fatalf("client %d holds the port of client %d", i, j)
			}
		}
	}
	if len(shared) != 1 || shared[0] != "http://localhost/callback" || slices.Contains(shared[:cap(shared)], ports[0]) {
		t.Fatalf("the shared slice was written: %v", shared[:cap(shared)])
	}
	// A URI nothing registered is never admitted.
	c := &Client{Source: SourceCIMD, Redirects: []string{"http://localhost/callback"}}
	c.AdmitRedirect("http://localhost:5000/other")
	c.AdmitRedirect("https://evil.example/callback")
	if len(c.Redirects) != 1 {
		t.Fatalf("admitted %v", c.Redirects)
	}
}
