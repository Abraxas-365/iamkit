package e2e_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TestExternalClientRowUUIDIsNotAClientID is H-1 of the second review: the
// row uuid of a client named by a metadata document is not its client_id.
// Sent to authorize, token, revocation, introspection and the device
// endpoint it finds no client, so the guards a URL client_id meets (grant
// allowlist, admission, allow_client_metadata, the feature) cannot be
// skipped, and a document client can never introspect other clients'
// tokens, pending or not.
func TestExternalClientRowUUIDIsNotAClientID(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	host.Put(chatGPTID, map[string]any{"client_id": chatGPTID, "client_name": "ChatGPT", "redirect_uris": []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "RS256", "jwks_uri": chatGPTJWKS})
	host.Put(chatGPTJWKS, map[string]any{"keys": []any{rsaJWK(key, "k1")}})
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	e.DB.MustExec(`INSERT INTO oauth_client_allowlist(id,environment_id,origin,path_prefix) VALUES(gen_random_uuid(),$1,'https://chatgpt.com','/oauth/client.json')`, e.EnvID)

	// Claude Code, approved by hand, holds live tokens.
	e.loginAndAsk(claudeCodeID)
	var claudeRow, gptRow string
	e.DB.Get(&claudeRow, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	e.DB.MustExec(`UPDATE oauth_clients SET admission='approved' WHERE id=$1`, claudeRow)
	status, tokens := e.authorizeExternal(claudeCodeID)
	if status != 200 {
		t.Fatalf("claude tokens: %d %v", status, tokens)
	}
	// ChatGPT is approved by policy and persisted by its first sign-in.
	b := e.browser()
	b.signInTo(b.get(resourceAuthorize(chatGPTID, url.Values{"redirect_uri": {"https://chatgpt.com/connector_platform_oauth_redirect"}})), "https://chatgpt.com/connector_platform_oauth_redirect")
	e.DB.Get(&gptRow, `SELECT id FROM oauth_clients WHERE external_id=$1`, chatGPTID)
	if gptRow == "" {
		t.Fatal("chatgpt row not persisted")
	}
	signed := func(row string) string {
		return assertion(t, jwt.SigningMethodRS256, key, "k1", row, testIssuer+"/oauth/token", uuid.NewString())
	}
	post := func(path string, form url.Values, user string) (int, string) {
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, "x")
		}
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var sb strings.Builder
		buf := make([]byte, 4096)
		for n, _ := res.Body.Read(buf); n > 0; n, _ = res.Body.Read(buf) {
			sb.Write(buf[:n])
		}
		return res.StatusCode, sb.String()
	}

	for _, row := range []string{claudeRow, gptRow} {
		// Authorize: no client; a plain 400 (never a page that names it).
		if p := e.browser().get(resourceAuthorize(row, url.Values{"redirect_uri": {loopback}})); p.Status != 400 || p.Location != "" {
			t.Errorf("authorize by uuid %s: %d %q", row, p.Status, p.Location)
		}
		// Token endpoint: refresh and code grants, public or with an assertion.
		for _, grant := range []url.Values{refreshForm(row, tokens["refresh_token"].(string)), codeForm(row, "ik_code_x"), {"grant_type": {"client_credentials"}, "client_id": {row}}} {
			grant.Set("client_assertion_type", assertionType)
			grant.Set("client_assertion", signed(row))
			if status, body := post("/oauth/token", grant, ""); status != 401 || !strings.Contains(body, "invalid_client") {
				t.Errorf("token by uuid %s %s: %d %s", row, grant.Get("grant_type"), status, body)
			}
		}
		// Introspection, however the caller authenticates.
		for _, form := range []url.Values{
			{"token": {tokens["access_token"].(string)}},
			{"token": {tokens["access_token"].(string)}, "client_assertion_type": {assertionType}, "client_assertion": {signed(row)}},
		} {
			if status, body := post("/oauth/introspect", form, row); status != 401 || strings.Contains(body, `"active":true`) {
				t.Errorf("introspect by uuid %s: %d %s", row, status, body)
			}
		}
		// Revocation and the device endpoint.
		if status, _ := post("/oauth/revoke", url.Values{"client_id": {row}, "token": {tokens["refresh_token"].(string)}}, ""); status != 401 {
			t.Errorf("revoke by uuid %s: %d", row, status)
		}
		if status, _ := post("/oauth/device_authorization", url.Values{"client_id": {row}}, ""); status != 401 {
			t.Errorf("device by uuid %s: %d", row, status)
		}
	}
	// Nothing above revoked or consumed the token: it works by its URL.
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), ""); status != 200 {
		t.Fatalf("refresh by URL after uuid attempts: %d %v", status, out)
	}
	// Turning documents off for the server stops authorize by URL, and the
	// uuid never was a way around it.
	e.DB.MustExec(`UPDATE protected_resources SET allow_client_metadata=false WHERE id=$1`, protected)
	if p := e.browser().get(resourceAuthorize(claudeRow, url.Values{"redirect_uri": {loopback}})); p.Status != 400 || p.Location != "" {
		t.Fatalf("authorize by uuid with documents off: %d %q", p.Status, p.Location)
	}
}
