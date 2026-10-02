package e2e_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
)

// TestUserPhone covers phone numbers (U5): self-service verification
// through /identity/v1/me/phone (fresh sign-in, SMS code, attempts,
// cooldown), operator phone_verified (audited), the phone scope and its
// claims, and SCIM phoneNumbers mapped only for connections that opt in.
func TestUserPhone(t *testing.T) {
	inbox := &smsInbox{}
	srv := httptest.NewServer(inbox)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithMail(authmodule.Mail{SMSClient: http.DefaultTransport}))
	self := func(method, path, token string, body fiber.Map, want int) Response {
		t.Helper()
		if body == nil {
			return e.Must(method, path+"?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), token, nil, want)
		}
		body["environment_id"], body["audience"] = e.EnvID, e.Audience
		return e.Must(method, path, token, body, want)
	}
	phoneOf := func(id string) (string, bool) {
		t.Helper()
		var phone string
		var verified bool
		if err := e.DB.QueryRow(`SELECT phone, phone_verified FROM users WHERE id=$1`, id).Scan(&phone, &verified); err != nil {
			t.Fatal(err)
		}
		return phone, verified
	}
	cooled := func() {
		t.Helper()
		if _, err := e.DB.Exec(`UPDATE phone_verifications SET sent_at = now() - interval '1 minute'`); err != nil {
			t.Fatal(err)
		}
	}
	user := e.Base + "/users/" + e.Alice
	access := e.Login(e.AliceEmail)

	// No SMS provider yet: nothing can be texted.
	self("POST", "/identity/v1/me/phone", access, fiber.Map{"phone": "+15557654321"}, 502)
	e.Must("PUT", e.Base+"/sms", e.Owner, fiber.Map{"provider": "webhook", "webhook_url": srv.URL, "webhook_token": "sms-secret"}, 200)
	self("POST", "/identity/v1/me/phone", "", fiber.Map{"phone": "+15557654321"}, 401)
	self("POST", "/identity/v1/me/phone", access, fiber.Map{"phone": "5551234"}, 400)

	// Start: a code goes to the new number; the user's phone is unchanged
	// until it is entered.
	cooled()
	sent := self("POST", "/identity/v1/me/phone", access, fiber.Map{"phone": "+1 555 765 4321"}, 202)
	text := inbox.last(t)
	if text["phone"] != "+15557654321" || text["purpose"] != "phone_verification" || len(text["code"]) != 6 || strings.Contains(sent.JSON["destination"].(string), "7654321") || sent.JSON["expires_at"] == nil {
		t.Fatalf("start = %s / %v", sent.Body, text)
	}
	if phone, _ := phoneOf(e.Alice); phone != "" {
		t.Fatalf("phone set before verification: %q", phone)
	}
	if r := self("POST", "/identity/v1/me/phone", access, fiber.Map{"phone": "+15557654321"}, 429); !strings.Contains(r.Body, "CODE_COOLDOWN") {
		t.Fatalf("cooldown = %s", r.Body)
	}
	if r := self("POST", "/identity/v1/me/phone/verify", access, fiber.Map{"code": "000000"}, 422); !strings.Contains(r.Body, "INVALID_CODE") {
		t.Fatalf("wrong code = %s", r.Body)
	}
	self("POST", "/identity/v1/me/phone/verify", access, fiber.Map{"code": text["code"]}, 204)
	if phone, verified := phoneOf(e.Alice); phone != "+15557654321" || !verified || e.audited("user.phone_verified", e.Alice) != 1 {
		t.Fatalf("verified phone = %q %v", phone, verified)
	}
	self("POST", "/identity/v1/me/phone/verify", access, fiber.Map{"code": text["code"]}, 422) // single use
	if me := self("GET", "/identity/v1/me", access, nil, 200).JSON; me["phone"] != "+15557654321" || me["phone_verified"] != true {
		t.Fatalf("me = %v", me)
	}

	// Five wrong codes discard the pending one.
	cooled()
	self("POST", "/identity/v1/me/phone", access, fiber.Map{"phone": "+15550001111"}, 202)
	code := inbox.last(t)["code"]
	for range 5 {
		self("POST", "/identity/v1/me/phone/verify", access, fiber.Map{"code": "999999"}, 422)
	}
	self("POST", "/identity/v1/me/phone/verify", access, fiber.Map{"code": code}, 422)
	if phone, _ := phoneOf(e.Alice); phone != "+15557654321" {
		t.Fatalf("phone after failed verification = %q", phone)
	}

	// Changing the number needs a recent sign-in, even with a freshly
	// refreshed access token.
	pair := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200).JSON
	if _, err := e.DB.Exec(`UPDATE sessions SET authenticated_at=now()-interval '1 hour' WHERE user_id=$1`, e.Alice); err != nil {
		t.Fatal(err)
	}
	refresh := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": pair["refresh_token"]}
	stale := e.Must("POST", "/identity/v1/refresh", "", refresh, 200).JSON["access_token"].(string)
	cooled()
	if r := self("POST", "/identity/v1/me/phone", stale, fiber.Map{"phone": "+15550001111"}, 403); !strings.Contains(r.Body, "REAUTHENTICATION_REQUIRED") {
		t.Fatalf("stale = %s", r.Body)
	}
	self("DELETE", "/identity/v1/me/phone", stale, nil, 403)
	access = e.Login(e.AliceEmail)

	// Operators: a new number is unverified; phone_verified is explicit
	// and audited, and needs a number.
	e.Must("PATCH", user, e.Owner, fiber.Map{"phone": "+15552223333"}, 204)
	if u := e.Must("GET", user, e.Owner, nil, 200).JSON; u["phone"] != "+15552223333" || u["phone_verified"] != false {
		t.Fatalf("operator phone = %v", u)
	}
	e.Must("PATCH", user, e.Owner, fiber.Map{"phone_verified": true}, 204)
	if u := e.Must("GET", user, e.Owner, nil, 200).JSON; u["phone_verified"] != true || e.audited("user.phone_verified_set", e.Alice+"?phone_verified=true") != 1 {
		t.Fatalf("operator verified = %v", u)
	}
	bob := e.User("Bob", "bob-phone@example.com")
	e.Must("PATCH", e.Base+"/users/"+bob, e.Owner, fiber.Map{"phone_verified": true}, 400)

	// The phone scope releases phone_number(_verified); profile alone does not.
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	client, secret := registered["client_id"].(string), registered["client_secret"].(string)
	signIn := func(scope string) (map[string]any, string) {
		t.Helper()
		code, verifier := e.authorizationCodeScope(client, scope)
		tokens := e.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}}, client, secret)
		if tokens.Status != 200 {
			t.Fatalf("token = %d %s", tokens.Status, tokens.Body)
		}
		return claims(t, tokens.JSON["id_token"].(string)), tokens.JSON["access_token"].(string)
	}
	id, token := signIn("openid phone")
	if id["phone_number"] != "+15552223333" || id["phone_number_verified"] != true {
		t.Fatalf("phone scope id token = %v", id)
	}
	if info := e.Must("GET", "/oauth/userinfo", token, nil, 200).JSON; info["phone_number"] != "+15552223333" || info["phone_number_verified"] != true {
		t.Fatalf("userinfo = %v", info)
	}
	if id, _ = signIn("openid profile"); id["phone_number"] != nil {
		t.Fatalf("phone released without the phone scope: %v", id)
	}
	if d := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200).JSON; !contains(strs(d["scopes_supported"]), "phone") || !contains(strs(d["claims_supported"]), "phone_number_verified") {
		t.Fatalf("discovery = %v", d)
	}

	// Removing the number clears it.
	self("DELETE", "/identity/v1/me/phone", access, nil, 204)
	if phone, verified := phoneOf(e.Alice); phone != "" || verified || e.audited("user.phone_removed", e.Alice) != 1 {
		t.Fatalf("removed phone = %q %v", phone, verified)
	}

	// SCIM: phoneNumbers are ignored unless the connection maps them.
	s, _ := newSCIM(t, e)
	created := s.must("POST", "/Users", `{"userName":"pat@contoso.com","phoneNumbers":[{"value":"+15554445555","type":"mobile"}]}`, 201).JSON
	pat := created["id"].(string)
	if phone, _ := phoneOf(pat); phone != "" || created["phoneNumbers"] != nil {
		t.Fatalf("unmapped phone stored: %q %v", phone, created)
	}
	e.Must("PATCH", e.Base+"/users/"+pat, e.Owner, fiber.Map{"phone": "+15556667777", "phone_verified": true}, 204)
	s.must("PUT", "/Users/"+pat, `{"userName":"pat@contoso.com"}`, 200)
	if phone, verified := phoneOf(pat); phone != "+15556667777" || !verified {
		t.Fatalf("unmapped replace cleared the phone: %q %v", phone, verified)
	}
	cred := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Mapped", "organization_id": e.Org, "connection_id": s.connection, "map_phone": true}, 201).JSON
	mapped := s.with(map[string]string{"Authorization": "Bearer " + cred["secret"].(string)})
	got := mapped.must("GET", "/Users/"+pat, "", 200).JSON
	if list, _ := got["phoneNumbers"].([]any); len(list) != 1 || list[0].(map[string]any)["value"] != "+15556667777" {
		t.Fatalf("mapped read = %v", got)
	}
	mapped.must("PATCH", "/Users/"+pat, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"phoneNumbers[type eq \"mobile\"].value","value":"+1 555 888 9999"}]}`, 200)
	if phone, verified := phoneOf(pat); phone != "+15558889999" || verified {
		t.Fatalf("mapped patch = %q %v", phone, verified)
	}
	mapped.must("PATCH", "/Users/"+pat, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"phoneNumbers[type eq \"mobile\"].value","value":"not a number"}]}`, 200)
	if phone, _ := phoneOf(pat); phone != "+15558889999" {
		t.Fatalf("invalid directory number replaced the phone: %q", phone)
	}
	mapped.must("PUT", "/Users/"+pat, `{"userName":"pat@contoso.com"}`, 200)
	if phone, _ := phoneOf(pat); phone != "" {
		t.Fatalf("mapped replace kept the phone: %q", phone)
	}
	if views := e.Must("GET", e.Base+"/provisioning-credentials", e.Owner, nil, 200); !strings.Contains(views.Body, `"map_phone":true`) {
		t.Fatalf("credentials = %s", views.Body)
	}
}
