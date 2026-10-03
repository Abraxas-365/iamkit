package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TestMachineUserKeys: a machine user signs in with its own key through the
// RFC 7523 JWT-bearer grant — a generated pair (private half shown once) or
// an uploaded public key. The token is an ordinary application JWT on a
// session opened with the key; removing the key or deactivating the user
// ends it, and assertions are single use.
func TestMachineUserKeys(t *testing.T) {
	e := newEnv(t)
	bot := e.ID("POST", e.Base+"/users", fiber.Map{"kind": "machine", "name": "Deploy bot"})
	keys := e.Base + "/users/" + bot + "/keys"

	// Keys are for machine users only, public, and well formed.
	e.Must("POST", e.Base+"/users/"+e.Alice+"/keys", e.Owner, nil, 422)
	e.Must("POST", keys, e.Owner, fiber.Map{"public_key": fiber.Map{"kty": "RSA", "n": "AQAB", "e": "AQAB", "d": "AQAB"}}, 400)
	e.Must("POST", keys, e.Owner, fiber.Map{"public_key": fiber.Map{"kty": "oct", "k": "AAAA"}}, 400)
	e.Must("POST", keys, e.Owner, fiber.Map{"expires_in": "5m"}, 400)

	// A generated pair: the private key is returned once, never listed.
	issued := e.Must("POST", keys, e.Owner, nil, 201).JSON
	keyID, _ := issued["id"].(string)
	block, _ := pem.Decode([]byte(issued["private_key"].(string)))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("private key = %v", issued["private_key"])
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	listed := e.Must("GET", keys, e.Owner, nil, 200)
	if got := ids(listed, "id"); len(got) != 1 || got[0] != keyID || strings.Contains(listed.Body, "PRIVATE") {
		t.Fatalf("listed keys = %s", listed.Body)
	}

	grant := func(signed string, extra url.Values) Response {
		t.Helper()
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signed},
			"organization_id": {e.Org}, "application_id": {e.Client}, "resource_id": {e.Res}}
		for k, v := range extra {
			form[k] = v
		}
		return e.tokenRequest(form, "", "")
	}
	const tokenURL = "https://iam.example/oauth/token"
	sign := func(kid string) string {
		return assertion(t, jwt.SigningMethodRS256, parsed, kid, bot, tokenURL, uuid.NewString())
	}

	// Not a member yet: no access, like any sign-in.
	if r := grant(sign(keyID), nil); r.Status != 400 || r.JSON["error"] != "invalid_grant" {
		t.Fatalf("grant without membership = %d %s", r.Status, r.Body)
	}
	e.Join(e.Org, bot)
	e.Grant(e.Org, bot, e.Res, "invoices:read")

	signed := sign(keyID)
	r := grant(signed, url.Values{"environment_id": {e.EnvID}})
	if r.Status != 200 || r.JSON["token_type"] != "Bearer" || r.JSON["refresh_token"] != nil {
		t.Fatalf("grant = %d %s", r.Status, r.Body)
	}
	access := r.JSON["access_token"].(string)
	claims := claimsOf(t, access)
	if claims["sub"] != bot || claims["purpose"] != "application" || claims["organization_id"] != e.Org || claims["sid"] == nil {
		t.Fatalf("claims = %v", claims)
	}
	if amr, _ := claims["amr"].([]any); len(amr) != 1 || amr[0] != "swk" {
		t.Fatalf("amr = %v", claims["amr"])
	}
	if got := e.permissions(access); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("permissions = %v", got)
	}

	// Single use; the issuer is an accepted audience; the session is reused.
	if r := grant(signed, nil); r.Status != 400 || r.JSON["error"] != "invalid_grant" {
		t.Fatalf("replayed assertion = %d %s", r.Status, r.Body)
	}
	again := grant(assertion(t, jwt.SigningMethodRS256, parsed, keyID, bot, "https://iam.example", uuid.NewString()), nil)
	if again.Status != 200 || claimsOf(t, again.JSON["access_token"].(string))["sid"] != claims["sid"] {
		t.Fatalf("second grant = %d %s", again.Status, again.Body)
	}
	var used bool
	if err := e.DB.Get(&used, `SELECT last_used_at IS NOT NULL FROM user_keys WHERE id=$1`, keyID); err != nil || !used {
		t.Fatalf("last_used_at not recorded: %v", err)
	}

	// Refused assertions: every one is invalid_grant.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, bad := range map[string]Response{
		"unknown kid":       grant(sign(uuid.NewString()), nil),
		"no kid":            grant(sign(""), nil),
		"other signer":      grant(assertion(t, jwt.SigningMethodES256, other, keyID, bot, tokenURL, uuid.NewString()), nil),
		"other subject":     grant(assertion(t, jwt.SigningMethodRS256, parsed, keyID, e.Alice, tokenURL, uuid.NewString()), nil),
		"other audience":    grant(assertion(t, jwt.SigningMethodRS256, parsed, keyID, bot, "https://elsewhere.example/token", uuid.NewString()), nil),
		"other environment": grant(sign(keyID), url.Values{"environment_id": {uuid.NewString()}}),
		"no access":         grant(sign(keyID), url.Values{"resource_id": {uuid.NewString()}}),
	} {
		if bad.Status != 400 || bad.JSON["error"] != "invalid_grant" {
			t.Fatalf("%s = %d %s", name, bad.Status, bad.Body)
		}
	}
	if r := grant("", nil); r.Status != 400 || r.JSON["error"] != "invalid_request" {
		t.Fatalf("no assertion = %d %s", r.Status, r.Body)
	}
	if r := grant(sign(keyID), url.Values{"organization_id": {"x"}}); r.Status != 400 || r.JSON["error"] != "invalid_request" {
		t.Fatalf("bad organization = %d %s", r.Status, r.Body)
	}

	// An uploaded EC public key works the same way.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uploaded := e.Must("POST", keys, e.Owner, fiber.Map{"public_key": ecJWK(ecKey, "mine"), "expires_in": "720h"}, 201).JSON
	if uploaded["private_key"] != nil {
		t.Fatalf("uploaded key returned a private key: %v", uploaded)
	}
	ecID := uploaded["id"].(string)
	ecAccess := grant(assertion(t, jwt.SigningMethodES256, ecKey, ecID, bot, tokenURL, uuid.NewString()), nil)
	if ecAccess.Status != 200 {
		t.Fatalf("EC grant = %d %s", ecAccess.Status, ecAccess.Body)
	}

	// Deactivating the user ends the sessions and refuses new grants.
	e.Must("POST", e.Base+"/users/"+bot+"/deactivate", e.Owner, nil, 204)
	if e.active(access) || e.active(ecAccess.JSON["access_token"].(string)) {
		t.Fatal("key session of a deactivated machine user still active")
	}
	if r := grant(sign(keyID), nil); r.Status != 400 {
		t.Fatalf("grant for a deactivated user = %d %s", r.Status, r.Body)
	}
	e.Must("POST", e.Base+"/users/"+bot+"/reactivate", e.Owner, nil, 204)
	fresh := grant(sign(keyID), nil).JSON["access_token"].(string)
	ecFresh := grant(assertion(t, jwt.SigningMethodES256, ecKey, ecID, bot, tokenURL, uuid.NewString()), nil).JSON["access_token"].(string)

	// Removing a key ends its sessions only.
	e.Must("DELETE", keys+"/"+keyID, e.Owner, nil, 204)
	if e.active(fresh) {
		t.Fatal("session of a removed key still active")
	}
	if !e.active(ecFresh) {
		t.Fatal("removing one key ended another key's session")
	}
	if r := grant(sign(keyID), nil); r.Status != 400 {
		t.Fatalf("grant with a removed key = %d %s", r.Status, r.Body)
	}
	e.Must("DELETE", keys+"/"+keyID, e.Owner, nil, 404)
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/keys/"+ecID, e.Owner, nil, 404)

	// Audited, and advertised in discovery.
	var audited int
	if err := e.DB.Get(&audited, `SELECT count(*) FROM audit_events WHERE action IN ('user.key_added','user.key_removed') AND split_part(target_id,'?',1) IN ($1,$2)`, keyID, ecID); err != nil || audited != 3 {
		t.Fatalf("audit events = %d %v", audited, err)
	}
	// The events' subject is the machine user; data names the key.
	keyEvents := e.Must("GET", e.Base+"/events?type=user.key_added&subject="+bot, e.Owner, nil, 200).JSON["items"].([]any)
	if len(keyEvents) < 1 {
		t.Fatalf("key events of the bot = %v", keyEvents)
	}
	for _, it := range keyEvents {
		if data := it.(map[string]any)["data"].(map[string]any); data["user_id"] != bot || data["key_id"] == nil {
			t.Fatalf("key event = %v", it)
		}
	}
	discovery := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200)
	if !strings.Contains(discovery.Body, "urn:ietf:params:oauth:grant-type:jwt-bearer") {
		t.Fatalf("discovery = %s", discovery.Body)
	}

	// /api/v1 serves the same routes under iam:users:*.
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Grant(e.Org, bot, iam, "iam:users:read")
	reader := e.Must("POST", e.Base+"/users/"+bot+"/access-tokens", e.Owner, fiber.Map{"name": "reader", "organization_id": e.Org, "application_id": e.Client, "resource_id": iam}, 201).JSON["token"].(string)
	api := "/api/v1/environments/" + e.EnvID + "/users/" + bot + "/keys"
	if got := ids(e.Must("GET", api, reader, nil, 200), "id"); len(got) != 1 || got[0] != ecID {
		t.Fatalf("api keys = %v", got)
	}
	e.Must("POST", api, reader, nil, 403)
	e.Must("DELETE", api+"/"+ecID, reader, nil, 403)

	// At most ten keys per machine user.
	for i := 0; i < 9; i++ {
		e.Must("POST", keys, e.Owner, fiber.Map{"public_key": ecJWK(ecKey, "mine")}, 201)
	}
	e.Must("POST", keys, e.Owner, fiber.Map{"public_key": ecJWK(ecKey, "mine")}, 422)
}
