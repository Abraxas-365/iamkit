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

func oidcJourney(t *testing.T, app *fiber.App, call func(string, string, string, any, int) map[string]any, owner, base, env, org, client, resource string) {
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	registered := call("POST", base+"/oauth-clients", owner, fiber.Map{"application_id": client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}, "public": true}, 201)
	clientID := registered["client_id"].(string)
	login := fiber.Map{"environment_id": env, "organization_id": org, "application_id": client, "resource_id": resource, "email": "alice@example.com", "password": "correct horse battery"}
	token := call("POST", "/identity/v1/login", "", login, 200)["access_token"].(string)
	request := func(method, path, contentType, body, bearer string, cookie *http.Cookie, want int) (map[string]any, *http.Response) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := app.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, res.StatusCode, want, raw)
		}
		var data map[string]any
		if len(raw) > 0 && res.Header.Get("Content-Type") == "application/json" {
			if err = json.Unmarshal(raw, &data); err != nil {
				t.Fatal(err)
			}
		} else if len(raw) > 0 {
			_ = json.Unmarshal(raw, &data)
		}
		return data, res
	}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid offline_access"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}}
	begin, res := request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", nil, 200)
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing browser binding")
	}
	body, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	request("POST", "/oauth/authorize/complete", "application/json", string(body), token, nil, 401)
	_, res = request("POST", "/oauth/authorize/complete", "application/json", string(body), token, cookies[0], 303)
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code: %s", location)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}}
	form.Set("code_verifier", strings.Repeat("x", 43))
	request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 400)
	form.Set("code_verifier", verifier)
	pair, _ := request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 200)
	access, ok := pair["access_token"].(string)
	if !ok {
		t.Fatalf("missing access token: %v", pair)
	}
	if _, ok = pair["id_token"].(string); !ok {
		t.Fatal("missing ID token")
	}
	check := fiber.Map{"environment_id": env, "audience": "https://billing.example"}
	if call("POST", "/identity/v1/introspect", access, check, 200)["active"] != true {
		t.Fatal("OIDC access rejected")
	}
	call("GET", "/management/v1/me", access, nil, 401)
	refresh, ok := pair["refresh_token"].(string)
	if !ok {
		t.Fatal("missing OAuth refresh")
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}}
	rotated, _ := request("POST", "/oauth/token", "application/x-www-form-urlencoded", refreshForm.Encode(), "", nil, 200)
	if rotated["refresh_token"] == refresh {
		t.Fatal("OAuth refresh did not rotate")
	}
	request("POST", "/oauth/token", "application/x-www-form-urlencoded", refreshForm.Encode(), "", nil, 400)
	if call("POST", "/identity/v1/introspect", rotated["access_token"].(string), check, 200)["active"] != false {
		t.Fatal("OAuth replay did not revoke access")
	}
	// Code replay must revoke refresh credentials, not only access tokens.
	begin, res = request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", nil, 200)
	body, _ = json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	_, res = request("POST", "/oauth/authorize/complete", "application/json", string(body), token, res.Cookies()[0], 303)
	location, _ = url.Parse(res.Header.Get("Location"))
	form.Set("code", location.Query().Get("code"))
	second, _ := request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 200)
	request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 400)
	refreshForm.Set("refresh_token", second["refresh_token"].(string))
	request("POST", "/oauth/token", "application/x-www-form-urlencoded", refreshForm.Encode(), "", nil, 400)
	q.Set("prompt", "login")
	request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", nil, 400)
	q.Del("prompt")
	// Concurrent reuse must revoke the winning rotation too.
	begin, res = request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", nil, 200)
	body, _ = json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	_, res = request("POST", "/oauth/authorize/complete", "application/json", string(body), token, res.Cookies()[0], 303)
	location, _ = url.Parse(res.Header.Get("Location"))
	form.Set("code", location.Query().Get("code"))
	third, _ := request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 200)
	refreshForm.Set("refresh_token", third["refresh_token"].(string))
	encoded := refreshForm.Encode()
	type result struct {
		status int
		body   map[string]any
		err    error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(encoded))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := app.Test(r, 10000)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer response.Body.Close()
			var body map[string]any
			err = json.NewDecoder(response.Body).Decode(&body)
			results <- result{response.StatusCode, body, err}
		}()
	}
	close(start)
	success, failed := 0, 0
	winning := ""
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch r.status {
		case 200:
			success++
			winning = r.body["access_token"].(string)
		case 400:
			failed++
		default:
			t.Fatalf("unexpected refresh status %d", r.status)
		}
	}
	if success != 1 || failed != 1 {
		t.Fatalf("concurrent rotation success=%d failed=%d", success, failed)
	}
	if call("POST", "/identity/v1/introspect", winning, check, 200)["active"] != false {
		t.Fatal("concurrent refresh replay left winner active")
	}
	// Code exchange must use current grants, not the approval-time snapshot.
	claims := call("POST", "/identity/v1/introspect", token, check, 200)["claims"].(map[string]any)
	call("PUT", base+"/resources/"+resource, owner, fiber.Map{"name": "Billing API", "permissions": []string{"invoices:read", "invoices:write"}}, 204)
	grant := fiber.Map{"organization_id": org, "user_id": claims["sub"], "resource_id": resource, "permissions": []string{"invoices:read", "invoices:write"}}
	call("PUT", base+"/grants", owner, grant, 200)
	approvalToken := call("POST", "/identity/v1/login", "", login, 200)["access_token"].(string)
	begin, res = request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", nil, 200)
	body, _ = json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	_, res = request("POST", "/oauth/authorize/complete", "application/json", string(body), approvalToken, res.Cookies()[0], 303)
	location, _ = url.Parse(res.Header.Get("Location"))
	form.Set("code", location.Query().Get("code"))
	grant["permissions"] = []string{"invoices:read"}
	call("PUT", base+"/grants", owner, grant, 200)
	// Grant updates revoke the session at the database boundary, so an
	// outstanding authorization code must not produce any new token.
	request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 403)
	grant["permissions"] = claims["permissions"]
	call("PUT", base+"/grants", owner, grant, 200)
	token = call("POST", "/identity/v1/login", "", login, 200)["access_token"].(string)
	// Refresh issuance requires an explicitly approved offline_access scope.
	q.Set("scope", "openid")
	begin, res = request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", nil, 200)
	body, _ = json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	_, res = request("POST", "/oauth/authorize/complete", "application/json", string(body), token, res.Cookies()[0], 303)
	location, _ = url.Parse(res.Header.Get("Location"))
	form.Set("code", location.Query().Get("code"))
	online, _ := request("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", nil, 200)
	if refresh, ok := online["refresh_token"]; ok && refresh != "" {
		t.Fatal("refresh issued without offline_access")
	}
	for _, test := range []struct {
		path, body, code string
		status           int
	}{
		{"/oauth/token", "grant_type=password", "unsupported_grant_type", 400},
		{"/oauth/token", "grant_type=authorization_code&client_id=invalid", "invalid_client", 401},
		{"/oauth/token", "grant_type=authorization_code&client_id=a&client_id=b", "invalid_request", 400},
		{"/oauth/revoke", "client_id=invalid&token=unknown", "invalid_client", 401},
	} {
		failure, res := request("POST", test.path, "application/x-www-form-urlencoded", test.body, "", nil, test.status)
		if failure["error"] != test.code || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("incorrect OAuth error: %v", failure)
		}
	}
	// Do not accidentally accept the OIDC identity token as an API token.
	if call("POST", "/identity/v1/introspect", pair["id_token"].(string), check, 200)["active"] != false {
		t.Fatal("ID token accepted by API")
	}
}
