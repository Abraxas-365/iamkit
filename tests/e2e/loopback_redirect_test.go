package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestLoopbackRedirects: native apps and local development register http
// loopback redirect URIs (RFC 8252 §7.3). They are accepted with a warning,
// a registered 127.0.0.1 URI matches any port, and URLs that must stay
// HTTPS (back-channel logout) still refuse http.
func TestLoopbackRedirects(t *testing.T) {
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	e := newEnv(t)
	created := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "public": true,
		"redirect_uris": []string{"http://127.0.0.1/callback", "http://localhost:3000/callback", "https://app.example/callback"}, "post_logout_redirect_uris": []string{"http://localhost:3000/bye"}}, 201).JSON
	id := created["client_id"].(string)
	warned := func(raw any) []string {
		t.Helper()
		out := []string{}
		for _, w := range raw.([]any) {
			m := w.(map[string]any)
			if m["code"] != "loopback_redirect" {
				t.Fatalf("warning = %v", m)
			}
			out = append(out, m["field"].(string)+" "+m["value"].(string))
		}
		return out
	}
	want := "post_logout_redirect_uris http://localhost:3000/bye,redirect_uris http://127.0.0.1/callback,redirect_uris http://localhost:3000/callback"
	if got := strings.Join(warned(created["warnings"]), ","); got != want {
		t.Fatalf("create warnings = %s", got)
	}
	if got := strings.Join(warned(e.Must("GET", e.Base+"/oauth-clients/"+id, e.Owner, nil, 200).JSON["warnings"]), ","); got != want {
		t.Fatalf("find warnings = %s", got)
	}
	e.Must("PATCH", e.Base+"/oauth-clients/"+id, e.Owner, fiber.Map{"redirect_uris": []string{"http://10.0.0.5/callback"}}, 400)
	e.Must("PATCH", e.Base+"/oauth-clients/"+id, e.Owner, fiber.Map{"backchannel_logout_uri": "http://localhost:3000/logout"}, 400)
	e.Must("POST", e.Base+"/applications", e.Owner, fiber.Map{"name": "cli", "redirect_uris": []string{"http://127.0.0.1:8400/cb"}}, 201)
	https := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "public": true, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	if w := https["warnings"].([]any); len(w) != 0 {
		t.Fatalf("https client warnings = %v", w)
	}

	// The app listens on an ephemeral port; the code comes back to it.
	redirect := "http://127.0.0.1:53127/callback"
	verifier := strings.Repeat("n", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {id}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}, "state": {"native-state-123456"}, "nonce": {"native-nonce-123456"},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	send := func(req *http.Request, want int) (*http.Response, map[string]any) {
		t.Helper()
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", req.Method, req.URL, res.StatusCode, want, raw)
		}
		var data map[string]any
		_ = json.Unmarshal(raw, &data)
		return res, data
	}
	res, begin := send(httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil), 200)
	body, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	complete := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
	complete.Header.Set("Content-Type", "application/json")
	complete.Header.Set("Authorization", "Bearer "+e.Login(e.AliceEmail))
	complete.AddCookie(res.Cookies()[0])
	res, _ = send(complete, 303)
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil || location.Host != "127.0.0.1:53127" || location.Query().Get("code") == "" {
		t.Fatalf("redirect = %s %v", res.Header.Get("Location"), err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "redirect_uri": {redirect}, "code": {location.Query().Get("code")}, "code_verifier": {verifier}}
	token := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	token.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, pair := send(token, 200); pair["id_token"] == nil {
		t.Fatalf("token = %v", pair)
	}

	// Other hosts, paths and http://localhost on another port stay refused.
	for _, bad := range []string{"http://127.0.0.1:53127/other", "http://localhost:3001/callback", "http://192.168.1.2:53127/callback"} {
		q.Set("redirect_uri", bad)
		send(httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil), 400)
	}
}
