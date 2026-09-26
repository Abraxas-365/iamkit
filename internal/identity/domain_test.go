package identity

import "testing"

func TestDomain(t *testing.T) {
	for raw, want := range map[string]string{
		"Example.COM":       "example.com",
		" eu.example.com. ": "eu.example.com",
		"bücher.example":    "xn--bcher-kva.example",
		"acme.co.uk":        "acme.co.uk",
		"my-app.github.io":  "my-app.github.io",
	} {
		got, err := Domain(raw)
		if err != nil || got != want {
			t.Errorf("Domain(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "localhost", "com", "co.uk", "github.io", "*.example.com", "exa mple.com",
		"example..com", "-example.com", "_dmarc.example.com", "user@example.com", "https://example.com",
		string(make([]byte, 254))} {
		if got, err := Domain(raw); err == nil {
			t.Errorf("Domain(%q) accepted as %q", raw, got)
		}
	}
}

func TestEmailDomain(t *testing.T) {
	for email, want := range map[string]string{
		"jane@example.com":        "example.com",
		"jane@Eu.Example.com":     "eu.example.com",
		"jane@bücher.example":     "xn--bcher-kva.example",
		"no-at-sign.example.com":  "",
		"quoted\"@\"@example.com": "example.com",
	} {
		if got := EmailDomain(email); got != want {
			t.Errorf("EmailDomain(%q) = %q; want %q", email, got, want)
		}
	}
}
