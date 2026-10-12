package oauth

import (
	"testing"
)

func TestValidateAuthorizationIssuer(t *testing.T) {
	client := &Client{Redirects: []string{"http://localhost:3000/callback"}}
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

func TestValidateAuthorizationInteraction(t *testing.T) {
	client := &Client{Redirects: []string{"https://app.example/callback"}}
	for _, tc := range []struct {
		name  string
		extra map[string]string
		valid bool
	}{
		{"plain", nil, true},
		{"prompt login", map[string]string{"prompt": "login"}, true},
		{"prompt none", map[string]string{"prompt": "none"}, true},
		{"prompt several", map[string]string{"prompt": "login consent select_account"}, true},
		{"prompt none and login", map[string]string{"prompt": "none login"}, false},
		{"prompt unknown", map[string]string{"prompt": "register"}, false},
		{"max_age", map[string]string{"max_age": "0"}, true},
		{"max_age text", map[string]string{"max_age": "abc"}, false},
		{"max_age negative", map[string]string{"max_age": "-5"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := map[string][]string{
				"redirect_uri": {client.Redirects[0]}, "response_type": {"code"},
				"code_challenge_method": {"S256"}, "code_challenge": {"challenge"},
				"state": {"state"}, "nonce": {"nonce"},
			}
			for k, v := range tc.extra {
				query[k] = []string{v}
			}
			if err := ValidateAuthorization("https://iam.example", client, query); (err == nil) != tc.valid {
				t.Fatalf("ValidateAuthorization = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}
