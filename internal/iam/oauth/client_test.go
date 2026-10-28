package oauth

import (
	"slices"
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
