package authsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type oauthTokens struct {
	active    bool
	err       error
	signature string
	client    identity.ClientID
}

func (o *oauthTokens) Active(_ context.Context, _ identity.EnvironmentID, client identity.ClientID, signature string) (bool, error) {
	o.client, o.signature = client, signature
	return o.active, o.err
}

// OAuth-issued tokens must be checked against their live grant (by signature),
// not just the client; otherwise revoking a grant family leaves access tokens usable.
func TestCheckOAuth(t *testing.T) {
	client := identity.NewClientID()
	oauthToken := authentication.Token{OAuthClientID: client}
	cases := []struct {
		name   string
		token  authentication.Token
		raw    string
		oauth  *oauthTokens
		ok     bool
		lookup bool
	}{
		{"non-OAuth token skips lookup", authentication.Token{}, "a.b.c", &oauthTokens{}, true, false},
		{"active grant", oauthToken, "a.b.sig", &oauthTokens{active: true}, true, true},
		{"revoked grant", oauthToken, "a.b.sig", &oauthTokens{}, false, true},
		{"lookup error", oauthToken, "a.b.sig", &oauthTokens{active: true, err: errors.New("db down")}, false, true},
		{"malformed token", oauthToken, "a.b", &oauthTokens{active: true}, false, false},
		{"empty signature", oauthToken, "a.b.", &oauthTokens{active: true}, false, false},
		{"no checker configured", oauthToken, "a.b.sig", nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var checker authentication.OAuthTokens
			if c.oauth != nil {
				checker = c.oauth
			}
			err := NewTokens(nil, nil, nil, checker).checkOAuth(context.Background(), c.raw, c.token)
			if (err == nil) != c.ok {
				t.Fatalf("err=%v want ok=%v", err, c.ok)
			}
			if c.oauth != nil && (c.oauth.signature != "") != c.lookup {
				t.Fatalf("lookup=%v want %v", c.oauth.signature != "", c.lookup)
			}
			if c.lookup && (c.oauth.signature != "sig" || c.oauth.client != client) {
				t.Fatalf("looked up client=%v signature=%q", c.oauth.client, c.oauth.signature)
			}
		})
	}
}
