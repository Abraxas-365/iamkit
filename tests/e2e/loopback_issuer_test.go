package e2e_test

import (
	"net/url"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
)

// TestLoopbackIssuerHostedLogin exercises authorization, hosted password login
// and code exchange using the same HTTP issuers supported at startup. The page
// harness forwards cookies; real browser Secure-cookie behavior is separate.
func TestLoopbackIssuerHostedLogin(t *testing.T) {
	for _, issuer := range []string{"http://localhost:18998", "http://127.0.0.1:18998", "http://[::1]:18998"} {
		t.Run(issuer, func(t *testing.T) {
			e := newEnv(t)
			client := e.hostedClient()
			s := bootstrap.New(e.DB, e.Key, issuer, e.Mail)
			app := s.App()
			t.Cleanup(func() { app.Shutdown() })
			e.App = contracted(t, app, s.WaitDeliveries)

			discovery := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200)
			if discovery.JSON["issuer"] != issuer {
				t.Fatalf("discovery issuer = %v", discovery.JSON["issuer"])
			}
			b := e.browser()
			login := b.authorize(client)
			cookie := b.cookies["__Host-iamkit-authorization"]
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
				t.Fatalf("binding cookie security changed: %+v", cookie)
			}
			tokens := b.exchange(client, b.post("/hosted/login/password", url.Values{
				"ticket": {login.field("ticket")}, "email": {e.AliceEmail}, "password": {e.Pass},
			}))
			for _, name := range []string{"access_token", "id_token"} {
				if got := claims(t, tokens[name].(string))["iss"]; got != issuer {
					t.Fatalf("%s issuer = %v, want %s", name, got, issuer)
				}
			}
		})
	}
}
