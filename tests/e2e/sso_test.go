package e2e_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP is a TLS OIDC provider whose ID token claims are set per login.
type fakeIdP struct {
	*httptest.Server
	mu     sync.Mutex
	nonce  string
	claims map[string]any
}

func newFakeIdP(t *testing.T, key *rsa.PrivateKey, client string) *fakeIdP {
	t.Helper()
	p := &fakeIdP{}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := p.URL
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "provider", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/me":
			// OAuth 2.0 userinfo for oauth2 connections: the login's claims
			// under "user".
			if r.Header.Get("Authorization") != "Bearer upstream" {
				http.Error(w, "unauthorized", 401)
				return
			}
			p.mu.Lock()
			json.NewEncoder(w).Encode(map[string]any{"user": p.claims})
			p.mu.Unlock()
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code") != "provider-code" {
				http.Error(w, "invalid code", 400)
				return
			}
			if _, secret, _ := r.BasicAuth(); secret != "sealed-secret" && r.Form.Get("client_secret") != "sealed-secret" {
				http.Error(w, "invalid client", 401)
				return
			}
			p.mu.Lock()
			claims := jwt.MapClaims{"iss": issuer, "aud": client, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": p.nonce}
			for k, v := range p.claims {
				claims[k] = v
			}
			p.mu.Unlock()
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "provider"
			signed, _ := token.SignedString(key)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

// sso runs a full federation login through the connection as the provider
// user with claims, and returns the callback response.
func (e *Env) sso(p *fakeIdP, connection, org string, claims map[string]any) Response {
	e.t.Helper()
	body, _ := json.Marshal(fiber.Map{"connection_id": connection, "environment_id": e.EnvID, "organization_id": org, "application_id": e.Client, "resource_id": e.Res})
	req := httptest.NewRequest("POST", "/identity/v1/federation/start", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	var start map[string]any
	json.NewDecoder(res.Body).Decode(&start)
	res.Body.Close()
	if res.StatusCode != 200 {
		return Response{Status: res.StatusCode, JSON: start}
	}
	authorization, _ := url.Parse(start["authorization_url"].(string))
	p.mu.Lock()
	p.nonce, p.claims = authorization.Query().Get("nonce"), claims
	p.mu.Unlock()
	req = httptest.NewRequest("GET", "/identity/v1/federation/callback?code=provider-code&state="+url.QueryEscape(authorization.Query().Get("state")), nil)
	req.AddCookie(res.Cookies()[0])
	result, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer result.Body.Close()
	out := Response{Status: result.StatusCode}
	json.NewDecoder(result.Body).Decode(&out.JSON)
	return out
}

// TestOrgSSOJourney covers organization connections end to end: sealed
// secrets, discovery, just-in-time provisioning with a default group,
// enforcement with break-glass bypass, and the domain-deletion guard.
func TestOrgSSOJourney(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(idp.Client().Transport)
	connections := e.Base + "/federation-connections"
	domains := e.Base + "/organizations/" + e.Org + "/domains"

	// Creation: exactly one secret source; organization-only features.
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client"}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"name": "Env", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "x", "jit_provisioning": true}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "x", "enforcement": "enforced"}, 422)
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200)
	if detail.JSON["secret_source"] != "sealed" || detail.JSON["jit_provisioning"] != true || detail.JSON["organization_id"] != e.Org || strings.Contains(detail.Body, "sealed-secret") {
		t.Fatalf("detail = %s", detail.Body)
	}
	var stored string
	if err := e.DB.Get(&stored, `SELECT secret_sealed FROM federation_connections WHERE id=$1`, conn); err != nil || !strings.HasPrefix(stored, "v1:") || strings.Contains(stored, "sealed-secret") {
		t.Fatalf("stored secret = %q %v", stored, err)
	}
	if l := items(e.Must("GET", connections+"?organization_id="+e.Org, e.Owner, nil, 200)); len(l) != 1 {
		t.Fatalf("filtered list = %v", l)
	}
	if l := items(e.Must("GET", connections+"?scope=organization", e.Owner, nil, 200)); len(l) != 1 {
		t.Fatalf("organization scope = %v", l)
	}
	if l := items(e.Must("GET", connections+"?scope=environment", e.Owner, nil, 200)); len(l) != 0 {
		t.Fatalf("environment scope = %v", l)
	}
	e.Must("GET", connections+"?scope=everyone", e.Owner, nil, 400)

	// Discovery before and after verifying the domain.
	discover := func(email string) map[string]any {
		return e.Must("POST", "/identity/v1/discover", "", fiber.Map{"environment_id": e.EnvID, "email": email}, 200).JSON
	}
	if d := discover("bob@example.com"); d["method"] != "password" {
		t.Fatalf("unverified discover = %v", d)
	}
	domain := e.ID("POST", domains, fiber.Map{"domain": "example.com"})
	e.Must("POST", domains+"/"+domain+"/force-verify", e.Owner, nil, 200)
	if d := discover("Bob@Example.com"); d["method"] != "sso" || d["connection_id"] != conn || d["organization_id"] != e.Org || d["required"] != false {
		t.Fatalf("discover = %v", d)
	}
	if d := discover("bob@other.example"); d["method"] != "password" {
		t.Fatalf("other domain discover = %v", d)
	}

	// JIT without a default group: the account is created, access is not.
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "bob-sub", "email": "bob@example.com", "name": "Bob"}); r.Status != 403 {
		t.Fatalf("jit without roles: %d %v", r.Status, r.JSON)
	}
	var origin string
	if err := e.DB.Get(&origin, `SELECT x.origin FROM external_identities x JOIN users u ON u.id=x.user_id JOIN memberships m ON m.user_id=u.id AND m.organization_id=$2 WHERE x.connection_id=$1 AND u.email='bob@example.com' AND u.email_verified AND u.name='Bob'`, conn, e.Org); err != nil || origin != "jit" {
		t.Fatalf("jit bob: %q %v", origin, err)
	}

	// With a default group bound to a role, JIT users get access at once.
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": "00000000-0000-4000-8000-000000000000"}, 400)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": group}, 204)
	carol := e.sso(idp, conn, e.Org, map[string]any{"sub": "carol-sub", "email": "carol@example.com", "email_verified": true})
	if carol.Status != 200 || !equal(e.permissions(carol.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("jit carol: %d %v", carol.Status, carol.JSON)
	}
	// Linked on first login: the next login needs no email at all.
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "carol-sub"}); r.Status != 200 {
		t.Fatalf("returning carol: %d %v", r.Status, r.JSON)
	}

	// Refused: unverified provider email, foreign domain, other organization.
	for _, claims := range []map[string]any{
		{"sub": "dave-sub", "email": "dave@example.com", "email_verified": false},
		{"sub": "dave-sub", "email": "dave@example.com", "email_verified": "false"},
		{"sub": "dave-sub", "email": "dave@other.example"},
		{"sub": "dave-sub"},
	} {
		if r := e.sso(idp, conn, e.Org, claims); r.Status != 401 {
			t.Fatalf("jit %v: %d %v", claims, r.Status, r.JSON)
		}
	}
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Other"})
	if r := e.sso(idp, conn, other, map[string]any{"sub": "carol-sub"}); r.Status != 400 {
		t.Fatalf("cross-org start: %d %v", r.Status, r.JSON)
	}

	// An existing password user is adopted by email.
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-sub", "email": "alice@example.com"}); r.Status != 200 {
		t.Fatalf("adopt alice: %d %v", r.Status, r.JSON)
	}

	// Enforcement: verified-domain emails must use SSO, others need not.
	olga := e.User("Olga", "olga@other.example")
	e.Join(e.Org, olga)
	e.Grant(e.Org, olga, e.Res, "invoices:read")
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"enforcement": "enforced"}, 204)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Second", "issuer": idp.URL, "client_id": "second-client", "client_secret": "x", "enforcement": "enforced"}, 409)
	blocked := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 403)
	if code, _ := blocked.JSON["error"].(map[string]any)["code"].(string); code != "SSO_REQUIRED" {
		t.Fatalf("blocked = %s", blocked.Body)
	}
	// Same answer for an unknown account and a wrong password.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("nobody@example.com", "wrong"), 403)
	e.Login("olga@other.example")
	if d := discover("alice@example.com"); d["required"] != true {
		t.Fatalf("enforced discover = %v", d)
	}
	// Enforcement is per organization: alice may still use a password in
	// an organization that does not enforce SSO.
	e.Join(other, e.Alice)
	e.Grant(other, e.Alice, e.Res, "invoices:read")
	otherLogin := e.LoginBody(e.AliceEmail, e.Pass)
	otherLogin["organization_id"] = other
	e.Must("POST", "/identity/v1/login", "", otherLogin, 200)

	// Break-glass bypass.
	member := e.Base + "/organizations/" + e.Org + "/members/" + e.Alice
	e.Must("PATCH", member, e.Owner, fiber.Map{}, 400)
	e.Must("PATCH", member, e.Owner, fiber.Map{"sso_bypass": true}, 204)
	e.Login(e.AliceEmail)
	for _, m := range items(e.Must("GET", e.Base+"/organizations/"+e.Org+"/members", e.Owner, nil, 200)) {
		if (m["user_id"] == e.Alice) != (m["sso_bypass"] == true) {
			t.Fatalf("member view = %v", m)
		}
	}

	// The last verified domain cannot go while SSO is enforced.
	e.Must("DELETE", domains+"/"+domain, e.Owner, nil, 422)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"enforcement": "optional"}, 204)
	e.Must("DELETE", domains+"/"+domain, e.Owner, nil, 204)

	// Clearing the default group; identities list shows provenance.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": ""}, 204)
	if d := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON; d["jit_group_id"] != nil {
		t.Fatalf("group not cleared: %v", d)
	}
	ids := items(e.Must("GET", connections+"/"+conn+"/identities", e.Owner, nil, 200))
	if len(ids) != 3 {
		t.Fatalf("identities = %v", ids)
	}
}

// TestSealedConnectionBlocksPrivateProviders checks the guarded transport:
// without the test override, a sealed-secret connection cannot reach a
// provider on a loopback address.
func TestSealedConnectionBlocksPrivateProviders(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "acme-client")
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})
	// The console shows the organization's name for scoped connections.
	if got := e.Must("GET", e.Base+"/federation-connections/"+conn, e.Owner, nil, 200).JSON; got["organization_name"] == "" || got["organization_name"] == nil {
		t.Fatalf("connection detail without organization name: %v", got)
	}
	if list := items(e.Must("GET", e.Base+"/federation-connections", e.Owner, nil, 200)); len(list) != 1 || list[0]["organization_name"] != e.Must("GET", e.Base+"/federation-connections/"+conn, e.Owner, nil, 200).JSON["organization_name"] {
		t.Fatalf("connection list names = %v", list)
	}
	if r := e.sso(idp, conn, e.Org, nil); r.Status != 502 {
		t.Fatalf("loopback provider reached: %d %v", r.Status, r.JSON)
	}
}
