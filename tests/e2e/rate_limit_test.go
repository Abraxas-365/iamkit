package e2e_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// SCIM is rate limited per client address like the token endpoint, before
// the credential is checked, and answers the limit as a SCIM error (J9 rate
// limits).
func TestSCIMRateLimit(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 2 // SCIM budget: 5 × 2 a minute
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	status := func() (int, string) {
		req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer ik_scim_wrong")
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header.Get("Content-Type") + " " + string(raw)
	}
	for i := range 10 {
		if code, body := status(); code != 401 {
			t.Fatalf("request %d = %d %s, want 401", i+1, code, body)
		}
	}
	code, body := status()
	if code != 429 || !strings.Contains(body, "application/scim+json") || !strings.Contains(body, `"status":"429"`) {
		t.Fatalf("11th request = %d %s, want a SCIM 429", code, body)
	}
}
