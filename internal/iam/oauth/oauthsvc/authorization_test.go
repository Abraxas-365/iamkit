package oauthsvc

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
)

func TestValidateAuthorizationIssuer(t *testing.T) {
	client := &oauth.Client{Redirects: []string{"http://localhost:3000/callback"}}
	query := map[string][]string{
		"redirect_uri": {client.Redirects[0]}, "response_type": {"code"},
		"code_challenge_method": {"S256"}, "code_challenge": {"challenge"},
		"state": {"state"}, "nonce": {"nonce"},
	}
	for _, tc := range []struct {
		issuer string
		valid  bool
	}{
		{"https://iam.example", true},
		{"http://localhost:18998", true},
		{"http://127.0.0.1:18998", true},
		{"http://[::1]:18998", true},
		{"http://iam.example", false},
		{"http://192.168.1.10:18998", false},
		{"http://localhost.example:18998", false},
		{"http://localhost@evil.example", false},
		{"https://", false},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			err := ValidateAuthorization(tc.issuer, client, query)
			if (err == nil) != tc.valid {
				t.Fatalf("ValidateAuthorization = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}
