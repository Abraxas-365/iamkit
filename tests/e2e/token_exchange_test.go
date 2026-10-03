package e2e_test

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
)

const (
	exchangeGrant   = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
	userIDTokenType = "urn:iamkit:params:oauth:token-type:user_id"
)

// TestTokenExchangeResource covers RFC 8693 resource exchange: a
// confidential client allowed the grant turns a user's token into one for
// another resource of the application, in a child session that is reused
// and ends with the original one.
func TestTokenExchangeResource(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", "ssssssssssssssssssssssssssssssss")
	reports := e.ID("POST", e.Base+"/resources", fiber.Map{"name": "Reports", "prefix": "reports", "audience": "https://reports.example", "permissions": []string{"reports:read", "reports:write"}})
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": reports}, 201)
	e.Grant(e.Org, e.Alice, reports, "reports:read")
	// Unlinked resource the user can reach elsewhere is not a target.
	e.ID("POST", e.Base+"/resources", fiber.Map{"name": "Other", "prefix": "other", "audience": "https://other.example", "permissions": []string{"other:read"}})

	// Public clients may not exchange.
	e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "public": true, "grant_types": []string{exchangeGrant}}, 400)
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "grant_types": []string{exchangeGrant}}, 201).JSON
	client, secret := registered["client_id"].(string), registered["client_secret"].(string)
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"public": true}, 400)
	if meta := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200).JSON; !contains(anyStrings(meta["grant_types_supported"]), exchangeGrant) {
		t.Fatalf("discovery = %v", meta["grant_types_supported"])
	}

	access := e.Login(e.AliceEmail)
	original := claimsOf(t, access)
	exchange := func(extra url.Values) Response {
		form := url.Values{"grant_type": {exchangeGrant}, "subject_token": {access}, "subject_token_type": {accessTokenType}, "audience": {"https://reports.example"}}
		for k, v := range extra {
			form[k] = v
		}
		return e.tokenRequest(form, client, secret)
	}
	res := exchange(nil)
	if res.Status != 200 || res.JSON["issued_token_type"] != accessTokenType || res.JSON["token_type"] != "Bearer" || res.JSON["refresh_token"] != nil {
		t.Fatalf("exchange = %d %s", res.Status, res.Body)
	}
	exchanged := res.JSON["access_token"].(string)
	got := claimsOf(t, exchanged)
	if !jsonEqual(got["aud"], []any{"https://reports.example"}) || !jsonEqual(got["permissions"], []any{"reports:read"}) || got["sub"] != original["sub"] || got["organization_id"] != original["organization_id"] || got["resource_id"] != reports || got["sid"] == original["sid"] || got["act"] != nil {
		t.Fatalf("exchanged claims = %v (original %v)", got, original)
	}
	// Unset optional IDs are absent, not the nil UUID (SDKs read a present
	// actor_id as impersonation).
	for _, name := range []string{"actor_id", "oauth_client_id"} {
		if v, ok := got[name]; ok {
			t.Fatalf("exchanged %s = %v, want absent", name, v)
		}
		if v, ok := original[name]; ok {
			t.Fatalf("login %s = %v, want absent", name, v)
		}
	}
	if !jsonEqual(got["amr"], original["amr"]) || !jsonEqual(got["auth_time"], original["auth_time"]) {
		t.Fatalf("sign-in facts not kept: %v vs %v", got, original)
	}
	child := got["sid"].(string)
	reportsMe := "/identity/v1/me?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape("https://reports.example")
	e.Must("GET", reportsMe, exchanged, nil, 200)
	if e.audited("oauth.token_exchanged", child) != 1 {
		t.Fatal("exchange not audited")
	}

	// The child session is reused, also when exchanging the exchanged
	// token; exchanging back to the original resource uses the root.
	if again := claimsOf(t, exchange(nil).JSON["access_token"].(string)); again["sid"] != child {
		t.Fatalf("second exchange sid = %v", again["sid"])
	}
	back := e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {exchanged}, "subject_token_type": {accessTokenType}, "audience": {e.Audience}}, client, secret)
	if back.Status != 200 || claimsOf(t, back.JSON["access_token"].(string))["sid"] != original["sid"] {
		t.Fatalf("exchange back = %d %s", back.Status, back.Body)
	}
	if e.audited("oauth.token_exchanged", child) != 1 {
		t.Fatal("reused child audited again")
	}

	// Narrowing by scope; asking beyond the user's grant.
	if r := exchange(url.Values{"scope": {"reports:read"}}); r.Status != 200 {
		t.Fatalf("narrow = %d %s", r.Status, r.Body)
	}
	for name, c := range map[string]struct {
		form  url.Values
		error string
	}{
		"scope beyond grant":   {url.Values{"scope": {"reports:write"}}, "invalid_scope"},
		"unlinked audience":    {url.Values{"audience": {"https://other.example"}}, "invalid_target"},
		"missing audience":     {url.Values{"audience": {""}}, "invalid_target"},
		"refresh token wanted": {url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}}, "invalid_request"},
		"bad subject":          {url.Values{"subject_token": {"not-a-token"}}, "invalid_request"},
		"unknown type":         {url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}}, "invalid_request"},
		"actor token":          {url.Values{"actor_token": {access}, "actor_token_type": {accessTokenType}}, "invalid_request"},
	} {
		if r := exchange(c.form); r.Status != 400 || r.JSON["error"] != c.error {
			t.Fatalf("%s = %d %s", name, r.Status, r.Body)
		}
	}
	if r := e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {access}, "subject_token_type": {accessTokenType}, "audience": {"https://reports.example"}}, client, "wrong"); r.Status != 401 || r.JSON["error"] != "invalid_client" {
		t.Fatalf("wrong secret = %d %s", r.Status, r.Body)
	}
	// A client without the grant.
	plain := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	if r := e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {access}, "subject_token_type": {accessTokenType}, "audience": {"https://reports.example"}}, plain["client_id"].(string), plain["client_secret"].(string)); r.Status != 400 || r.JSON["error"] != "unauthorized_client" {
		t.Fatalf("client without grant = %d %s", r.Status, r.Body)
	}

	// Ending the original session ends the exchanged one.
	if _, err := e.DB.Exec(`UPDATE sessions SET revoked_at=now() WHERE id=$1`, original["sid"]); err != nil {
		t.Fatal(err)
	}
	e.Must("GET", reportsMe, exchanged, nil, 401)
	if r := exchange(nil); r.Status != 400 || r.JSON["error"] != "invalid_request" {
		t.Fatalf("ended subject = %d %s", r.Status, r.Body)
	}
}

// TestTokenExchangeImpersonation: a service account an owner allowed may
// exchange a user id for that user's token (act = the account), with a
// reason, audited; forbidding it ends those sessions.
func TestTokenExchangeImpersonation(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", "ssssssssssssssssssssssssssssssss")
	sa := e.Must("POST", e.Base+"/service-accounts", e.Owner, fiber.Map{"name": "support-bot", "application_id": e.Client, "resource_id": e.Res, "permissions": []string{"invoices:read"}}, 201).JSON
	id, secret := sa["id"].(string), sa["secret"].(string)
	if view := e.Must("GET", e.Base+"/service-accounts/"+id, e.Owner, nil, 200).JSON; view["can_impersonate"] != false {
		t.Fatalf("account = %v", view)
	}
	impersonate := func(user, reason string) Response {
		return e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {user}, "subject_token_type": {userIDTokenType}, "organization_id": {e.Org}, "reason": {reason}}, id, secret)
	}
	if r := impersonate(e.Alice, "support ticket 1234"); r.Status != 400 || r.JSON["error"] != "unauthorized_client" {
		t.Fatalf("not allowed = %d %s", r.Status, r.Body)
	}

	// Only owners may allow it.
	admin := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "admin@example.com", "role": "admin"}, 201).JSON["secret"].(string)
	e.Must("PUT", e.Base+"/service-accounts/"+id+"/impersonation", admin, fiber.Map{"allowed": true}, 403)
	e.Must("PUT", e.Base+"/service-accounts/"+id+"/impersonation", e.Owner, fiber.Map{}, 400)
	if view := e.Must("PUT", e.Base+"/service-accounts/"+id+"/impersonation", e.Owner, fiber.Map{"allowed": true}, 200).JSON; view["can_impersonate"] != true {
		t.Fatalf("allowed = %v", view)
	}
	if e.audited("service_account.impersonation", id) != 1 {
		t.Fatal("impersonation change not audited")
	}

	res := impersonate(e.Alice, "support ticket 1234")
	if res.Status != 200 || res.JSON["issued_token_type"] != accessTokenType {
		t.Fatalf("impersonate = %d %s", res.Status, res.Body)
	}
	token := res.JSON["access_token"].(string)
	claims := claimsOf(t, token)
	if claims["sub"] != e.Alice || !jsonEqual(claims["act"], map[string]any{"sub": id}) || !jsonEqual(claims["permissions"], []any{"invoices:read"}) || claims["actor_id"] != nil {
		t.Fatalf("impersonation claims = %v", claims)
	}
	me := "/identity/v1/me?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape(e.Audience)
	if r := e.Must("GET", me, token, nil, 200).JSON; r["id"] != e.Alice {
		t.Fatalf("me = %v", r)
	}
	// Impersonated tokens cannot manage factors or be exchanged again.
	e.Must("GET", "/identity/v1/me/factors?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), token, nil, 403)

	var reason string
	if err := e.DB.Get(&reason, `SELECT impersonation_reason FROM sessions WHERE id=$1 AND actor_account_id=$2`, claims["sid"], id); err != nil || reason != "support ticket 1234" {
		t.Fatalf("session reason = %q %v", reason, err)
	}
	if e.audited("oauth.impersonated", claims["sid"].(string)) != 1 {
		t.Fatal("impersonation not audited")
	}

	stranger := e.User("Bob", "bob@example.com")
	for name, r := range map[string]Response{
		"short reason": impersonate(e.Alice, "because"),
		"non member":   impersonate(stranger, "support ticket 1234"),
		"bad user":     impersonate("nope", "support ticket 1234"),
	} {
		if r.Status != 400 || r.JSON["error"] != "invalid_request" {
			t.Fatalf("%s = %d %s", name, r.Status, r.Body)
		}
	}
	if r := e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {e.Alice}, "subject_token_type": {userIDTokenType}, "organization_id": {e.Org}, "reason": {"support ticket 1234"}, "audience": {"https://other.example"}}, id, secret); r.Status != 400 || r.JSON["error"] != "invalid_target" {
		t.Fatalf("other audience = %d %s", r.Status, r.Body)
	}
	if r := e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {e.Alice}, "subject_token_type": {userIDTokenType}, "organization_id": {e.Org}, "reason": {"support ticket 1234"}}, id, "ik_svc_wrong"); r.Status != 401 || r.JSON["error"] != "invalid_client" {
		t.Fatalf("wrong secret = %d %s", r.Status, r.Body)
	}

	// Forbidding impersonation ends the account's sessions.
	e.Must("PUT", e.Base+"/service-accounts/"+id+"/impersonation", e.Owner, fiber.Map{"allowed": false}, 200)
	e.Must("GET", me, token, nil, 401)
	if r := impersonate(e.Alice, "support ticket 1234"); r.Status != 400 || r.JSON["error"] != "unauthorized_client" {
		t.Fatalf("after forbidding = %d %s", r.Status, r.Body)
	}
}
