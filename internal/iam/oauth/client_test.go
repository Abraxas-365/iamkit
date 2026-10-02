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
