package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestMachineUsers: a machine user has no email or password, can never
// sign in, joins organizations and receives grants like a person, and
// authenticates with machine API keys — directly as a bearer (live
// permissions, no session) or exchanged for a session-backed JWT. Revoking
// a token or deactivating the user ends both at once.
func TestMachineUsers(t *testing.T) {
	e := newEnv(t)

	// Creation rules.
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"kind": "machine", "name": "bot", "email": "bot@example.com"}, 400)
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"kind": "machine", "name": "bot", "password": e.Pass}, 400)
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"kind": "robot", "name": "bot"}, 400)
	bot := e.ID("POST", e.Base+"/users", fiber.Map{"kind": "machine", "name": "Invoice sync"})
	found := e.Must("GET", e.Base+"/users/"+bot, e.Owner, nil, 200).JSON
	if found["kind"] != "machine" || found["email"] != "" {
		t.Fatalf("machine user = %v", found)
	}
	if got := ids(e.Must("GET", e.Base+"/users?kind=machine", e.Owner, nil, 200), "id"); len(got) != 1 || got[0] != bot {
		t.Fatalf("machine users = %v", got)
	}
	if got := ids(e.Must("GET", e.Base+"/users?kind=human", e.Owner, nil, 200), "id"); contains(got, bot) {
		t.Fatalf("human filter lists the machine user: %v", got)
	}
	e.Must("PATCH", e.Base+"/users/"+bot, e.Owner, fiber.Map{"username": "bot"}, 400)
	e.Must("PATCH", e.Base+"/users/"+bot, e.Owner, fiber.Map{"phone": "+14155550100"}, 400)
	e.Must("PATCH", e.Base+"/users/"+bot, e.Owner, fiber.Map{"name": "Invoice sync bot"}, 204)

	// No second factor, no linked identity, not even by the database.
	if _, err := e.DB.Exec(`INSERT INTO user_factors(id,environment_id,user_id,kind,secret_sealed) VALUES(gen_random_uuid(),$1,$2,'totp','x')`, e.EnvID, bot); err == nil || !strings.Contains(err.Error(), "machine users") {
		t.Fatalf("machine user got a second factor: %v", err)
	}

	// API keys need a membership and a machine user.
	create := func(user, name string, want int) Response {
		t.Helper()
		return e.Must("POST", e.Base+"/users/"+user+"/api-keys", e.Owner, fiber.Map{"name": name, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "expires_in": "720h"}, want)
	}
	create(bot, "ci", 400)
	create(e.Alice, "ci", 422)
	e.Join(e.Org, bot)
	e.Grant(e.Org, bot, e.Res, "invoices:read", "invoices:write")
	e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "ci", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "expires_in": "10m"}, 400)
	issued := create(bot, "ci", 201).JSON
	pat, _ := issued["value"].(string)
	if !strings.HasPrefix(pat, "ik_key_") {
		t.Fatalf("token = %v", issued)
	}
	tokenID := issued["id"].(string)
	listed := e.Must("GET", e.Base+"/users/"+bot+"/api-keys", e.Owner, nil, 200)
	if got := ids(listed, "id"); len(got) != 1 || got[0] != tokenID || strings.Contains(listed.Body, pat) {
		t.Fatalf("listed tokens = %s", listed.Body)
	}

	// A machine user never signs in with a password or code.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("", e.Pass), 401)

	// Direct bearer: introspection carries live permissions.
	if got := e.permissions(pat); !equal(got, []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("pat permissions = %v", got)
	}
	e.Grant(e.Org, bot, e.Res, "invoices:read")
	if got := e.permissions(pat); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("pat permissions after narrowing = %v", got)
	}
	claims := e.Must("POST", "/identity/v1/introspect", pat, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 200).JSON["claims"].(map[string]any)
	if claims["purpose"] != "api_key" || claims["sub"] != bot || claims["organization_id"] != e.Org {
		t.Fatalf("pat claims = %v", claims)
	}
	// Other audiences and environments do not accept it.
	if e.Must("POST", "/identity/v1/introspect", pat, fiber.Map{"environment_id": e.EnvID, "audience": "https://other.example"}, 200).JSON["active"] != false {
		t.Fatal("pat accepted for another audience")
	}
	var used bool
	if err := e.DB.Get(&used, `SELECT last_used_at IS NOT NULL FROM api_keys WHERE id=$1`, tokenID); err != nil || !used {
		t.Fatalf("last_used_at not recorded: %v", err)
	}

	// /api/v1 accepts it with the IAM permissions of its resource.
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Grant(e.Org, bot, iam, "iam:users:read")
	admin := e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "admin", "organization_id": e.Org, "application_id": e.Client, "resource_id": iam}, 201).JSON["value"].(string)
	api := "/api/v1/environments/" + e.EnvID
	e.Must("GET", api+"/users", admin, nil, 200)
	e.Must("POST", api+"/users", admin, fiber.Map{"name": "x", "email": "x@example.com"}, 403)
	e.Must("GET", api+"/users", pat, nil, 403) // Billing key: no iam permissions
	// Other API keys stay refused.
	e.Must("GET", api+"/users", "ik_svc_nope", nil, 401)
	e.Must("GET", api+"/users", "ik_key_nope", nil, 401)

	// Exchange: an application JWT backed by one reused session.
	exchanged := e.Must("POST", "/identity/v1/token-exchange", pat, nil, 200).JSON["access_token"].(string)
	if strings.HasPrefix(exchanged, "ik_") || !e.active(exchanged) {
		t.Fatal("exchanged token not active")
	}
	again := e.Must("POST", "/identity/v1/token-exchange", pat, nil, 200).JSON["access_token"].(string)
	var sessions int
	if err := e.DB.Get(&sessions, `SELECT count(*) FROM sessions WHERE api_key_id=$1`, tokenID); err != nil || sessions != 1 {
		t.Fatalf("sessions = %d, %v", sessions, err)
	}
	e.Must("POST", "/identity/v1/token-exchange", "ik_svc_nope", nil, 401)
	e.Must("POST", "/identity/v1/token-exchange", "", nil, 401)

	// Revoking the token ends both uses.
	e.Must("DELETE", e.Base+"/users/"+bot+"/api-keys/"+tokenID, e.Owner, nil, 204)
	if e.active(pat) || e.active(exchanged) || e.active(again) {
		t.Fatal("revoked token still active")
	}
	e.Must("POST", "/identity/v1/token-exchange", pat, nil, 401)
	e.Must("DELETE", e.Base+"/users/"+bot+"/api-keys/"+tokenID, e.Owner, nil, 204) // idempotent
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/api-keys/"+tokenID, e.Owner, nil, 404)

	// Deactivating the machine user ends every token at once.
	second := create(bot, "second", 201).JSON["value"].(string)
	session := e.Must("POST", "/identity/v1/token-exchange", second, nil, 200).JSON["access_token"].(string)
	e.Must("POST", e.Base+"/users/"+bot+"/deactivate", e.Owner, nil, 204)
	if e.active(second) || e.active(session) {
		t.Fatal("token of a deactivated machine user still active")
	}
	e.Must("POST", e.Base+"/users/"+bot+"/reactivate", e.Owner, nil, 204)
	if !e.active(second) {
		t.Fatal("token inactive after reactivation")
	}

	// Leaving the organization ends it too; the scoped API manages tokens.
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+bot, e.Owner, nil, 204)
	if e.active(second) {
		t.Fatal("token of a removed member still active")
	}
	writer := e.scopedToken("iam:users:read", "iam:users:write")
	e.Must("POST", api+"/users/"+bot+"/api-keys", writer, fiber.Map{"name": "api", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res}, 400) // no longer a member
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(beta, bot)
	other := e.Must("POST", api+"/users/"+bot+"/api-keys", writer, fiber.Map{"name": "api", "organization_id": beta, "application_id": e.Client, "resource_id": e.Res}, 201).JSON
	e.Must("GET", api+"/users/"+bot+"/api-keys", writer, nil, 200)
	e.Must("DELETE", api+"/users/"+bot+"/api-keys/"+other["id"].(string), writer, nil, 204)

	// Audit trail.
	var audited int
	if err := e.DB.Get(&audited, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action IN ('api_key.create','api_key.revoke')`, e.EnvID); err != nil || audited < 5 {
		t.Fatalf("audited = %d, %v", audited, err)
	}
	// The events' subject is the key; data names the machine user.
	keyEvents := e.Must("GET", e.Base+"/events?type=api_key.*&subject="+other["id"].(string), e.Owner, nil, 200)
	if got := eventTypes(keyEvents); !contains(got, "api_key.created") || got[0] != "api_key.revoked" {
		t.Fatalf("key events = %v", got)
	}
	if data := keyEvents.JSON["items"].([]any)[0].(map[string]any)["data"].(map[string]any); data["user_id"] != bot || data["name"] != "api" {
		t.Fatalf("revoked key event data = %v", data)
	}
}
