package oauth

import (
	"net/url"
	"testing"
)

func TestWithIssuer(t *testing.T) {
	const issuer = "https://iam.example"
	for _, tc := range []struct{ name, location, want string }{
		{"code", "https://app.example/cb?code=abc&state=xyz", "https://app.example/cb?code=abc&iss=https%3A%2F%2Fiam.example&state=xyz"},
		{"error", "https://app.example/cb?error=access_denied&state=s", "https://app.example/cb?error=access_denied&iss=https%3A%2F%2Fiam.example&state=s"},
		{"no query", "http://127.0.0.1:4711/callback", "http://127.0.0.1:4711/callback?iss=https%3A%2F%2Fiam.example"},
		{"replaces a forged iss", "https://app.example/cb?iss=https%3A%2F%2Fevil.example&code=c", "https://app.example/cb?code=c&iss=https%3A%2F%2Fiam.example"},
		{"keeps the redirect's own query", "https://app.example/cb?tenant=a&code=c", "https://app.example/cb?code=c&iss=https%3A%2F%2Fiam.example&tenant=a"},
		{"unparsable", "://bad", "://bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WithIssuer(tc.location, issuer); got != tc.want {
				t.Fatalf("WithIssuer(%q) = %q, want %q", tc.location, got, tc.want)
			}
		})
	}
	// The issuer round-trips exactly (clients compare it byte for byte).
	u, _ := url.Parse(WithIssuer("https://app.example/cb?code=c", issuer))
	if u.Query().Get("iss") != issuer {
		t.Fatalf("iss = %q", u.Query().Get("iss"))
	}
}

func TestDiscoveryAdvertisesIssuerParameter(t *testing.T) {
	if !NewDiscovery("https://iam.example").AuthorizationResponseIssParameterSupported {
		t.Fatal("authorization_response_iss_parameter_supported must be true")
	}
}

// Discovery advertises client_id metadata documents only when the
// deployment offers them.
func TestDiscoveryClientMetadataDocuments(t *testing.T) {
	d := NewDiscovery("https://iam.example")
	if d.ClientIDMetadataDocumentSupported {
		t.Fatal("advertised by default")
	}
	if !d.With(Offers{ClientMetadataDocuments: true}).ClientIDMetadataDocumentSupported {
		t.Fatal("offered but not advertised")
	}
	if d.With(Offers{}).ClientIDMetadataDocumentSupported {
		t.Fatal("not offered but advertised")
	}
}
