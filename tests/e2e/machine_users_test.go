package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestMachineUsers: a machine user has no email or password, can never
// sign in, joins organizations and receives grants like a person, and
// authenticates with personal access tokens — directly as a bearer (live
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

	// Tokens need a membership and a machine user.
	create := func(user, name string, want int) Response {
		t.Helper()
		return e.Must("POST", e.Base+"/users/"+user+"/access-tokens", e.Owner, fiber.Map{"name": name, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "expires_in": "720h"}, want)
	}
	create(bot, "ci", 400)
	create(e.Alice, "ci", 422)
	e.Join(e.Org, bot)
	e.Grant(e.Org, bot, e.Res, "invoices:read", "invoices:write")
	e.Must("POST", e.Base+"/users/"+bot+"/access-tokens", e.Owner, fiber.Map{"name": "ci", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "expires_in": "10m"}, 400)
	issued := create(bot, "ci", 201).JSON
	pat, _ := issued["token"].(string)
	if !strings.HasPrefix(pat, "ik_pat_") {
		t.Fatalf("token = %v", issued)
	}
	tokenID := issued["id"].(string)
	listed := e.Must("GET", e.Base+"/users/"+bot+"/access-tokens", e.Owner, nil, 200)
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
	if claims["purpose"] != "pat" || claims["sub"] != bot || claims["organization_id"] != e.Org {
		t.Fatalf("pat claims = %v", claims)
	}
	// Other audiences and environments do not accept it.
	if e.Must("POST", "/identity/v1/introspect", pat, fiber.Map{"environment_id": e.EnvID, "audience": "https://other.example"}, 200).JSON["active"] != false {
		t.Fatal("pat accepted for another audience")
	}
	var used bool
	if err := e.DB.Get(&used, `SELECT last_used_at IS NOT NULL FROM user_access_tokens WHERE id=$1`, tokenID); err != nil || !used {
		t.Fatalf("last_used_at not recorded: %v", err)
	}

	// /api/v1 accepts it with the IAM permissions of its resource.
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Grant(e.Org, bot, iam, "iam:users:read")
	admin := e.Must("POST", e.Base+"/users/"+bot+"/access-tokens", e.Owner, fiber.Map{"name": "admin", "organization_id": e.Org, "application_id": e.Client, "resource_id": iam}, 201).JSON["token"].(string)
	api := "/api/v1/environments/" + e.EnvID
	e.Must("GET", api+"/users", admin, nil, 200)
	e.Must("POST", api+"/users", admin, fiber.Map{"name": "x", "email": "x@example.com"}, 403)
	e.Must("GET", api+"/users", pat, nil, 403) // Billing token: no iam permissions
	// Other API keys stay refused.
	e.Must("GET", api+"/users", "ik_svc_nope", nil, 401)
	e.Must("GET", api+"/users", "ik_pat_nope", nil, 401)

	// Exchange: an application JWT backed by one reused session.
	exchanged := e.Must("POST", "/identity/v1/token-exchange", pat, nil, 200).JSON["access_token"].(string)
	if strings.HasPrefix(exchanged, "ik_") || !e.active(exchanged) {
		t.Fatal("exchanged token not active")
	}
	again := e.Must("POST", "/identity/v1/token-exchange", pat, nil, 200).JSON["access_token"].(string)
	var sessions int
	if err := e.DB.Get(&sessions, `SELECT count(*) FROM sessions WHERE access_token_id=$1`, tokenID); err != nil || sessions != 1 {
		t.Fatalf("sessions = %d, %v", sessions, err)
	}
	e.Must("POST", "/identity/v1/token-exchange", "ik_svc_nope", nil, 401)
	e.Must("POST", "/identity/v1/token-exchange", "", nil, 401)

	// Revoking the token ends both uses.
	e.Must("DELETE", e.Base+"/users/"+bot+"/access-tokens/"+tokenID, e.Owner, nil, 204)
	if e.active(pat) || e.active(exchanged) || e.active(again) {
		t.Fatal("revoked token still active")
	}
	e.Must("POST", "/identity/v1/token-exchange", pat, nil, 401)
	e.Must("DELETE", e.Base+"/users/"+bot+"/access-tokens/"+tokenID, e.Owner, nil, 204) // idempotent
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/access-tokens/"+tokenID, e.Owner, nil, 404)

	// Deactivating the machine user ends every token at once.
	second := create(bot, "second", 201).JSON["token"].(string)
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
	e.Must("POST", api+"/users/"+bot+"/access-tokens", writer, fiber.Map{"name": "api", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res}, 400) // no longer a member
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(beta, bot)
	other := e.Must("POST", api+"/users/"+bot+"/access-tokens", writer, fiber.Map{"name": "api", "organization_id": beta, "application_id": e.Client, "resource_id": e.Res}, 201).JSON
	e.Must("GET", api+"/users/"+bot+"/access-tokens", writer, nil, 200)
	e.Must("DELETE", api+"/users/"+bot+"/access-tokens/"+other["id"].(string), writer, nil, 204)

	// Audit trail.
	var audited int
	if err := e.DB.Get(&audited, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action IN ('user.access_token_created','user.access_token_revoked')`, e.EnvID); err != nil || audited < 5 {
		t.Fatalf("audited = %d, %v", audited, err)
	}
	// The events' subject is the machine user; data names the token.
	tokenEvents := e.Must("GET", e.Base+"/events?type=user.*&subject="+bot, e.Owner, nil, 200)
	if got := eventTypes(tokenEvents); !contains(got, "user.access_token_created") || got[0] != "user.access_token_revoked" {
		t.Fatalf("token events of the bot = %v", got)
	}
	if data := tokenEvents.JSON["items"].([]any)[0].(map[string]any)["data"].(map[string]any); data["access_token_id"] != other["id"] || data["user_id"] != bot {
		t.Fatalf("revoked token event data = %v", data)
	}
}

// TestMachineUsersInvisibleToSCIM: a SCIM directory neither lists machine
// users in its groups, nor adopts them, nor removes them from groups it
// replaces.
func TestMachineUsersInvisibleToSCIM(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	bot := e.ID("POST", e.Base+"/users", fiber.Map{"kind": "machine", "name": "bot"})
	e.Join(e.Org, bot)
	jdoe := s.user("jdoe@example.com", "obj-jdoe")
	group := s.must("POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[{"value":"`+jdoe+`"}]}`, 201).JSON["id"].(string)
	// Operators cannot edit directory groups; a machine user can only get
	// there behind the API's back, and SCIM must still leave it alone.
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/groups/"+group+"/members", e.Owner, fiber.Map{"add": []string{bot}}, 422)
	if _, err := e.DB.Exec(`INSERT INTO group_members(group_id,environment_id,organization_id,user_id) VALUES($1,$2,$3,$4)`, group, e.EnvID, e.Org, bot); err != nil {
		t.Fatal(err)
	}

	if m := memberIDs(s.must("GET", "/Groups/"+group, "", 200).JSON); len(m) != 1 || m[0] != jdoe {
		t.Fatalf("SCIM group members = %v", m)
	}
	if bad := s.do("PATCH", "/Groups/"+group, `{`+patchSchema+`,"Operations":[{"op":"add","path":"members","value":[{"value":"`+bot+`"}]}]}`); bad.Status != 400 {
		t.Fatalf("SCIM adopted a machine user: %d %s", bad.Status, bad.Body)
	}
	s.must("PUT", "/Groups/"+group, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[]}`, 200)
	var kept bool
	if err := e.DB.Get(&kept, `SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2)`, group, bot); err != nil || !kept {
		t.Fatalf("SCIM replace removed the machine user: %v", err)
	}
	if _, err := e.DB.Exec(`INSERT INTO provisioned_identities(connection_id,environment_id,user_id,external_id) VALUES($1,$2,$3,'x')`, s.connection, e.EnvID, bot); err == nil || !strings.Contains(err.Error(), "machine users") {
		t.Fatalf("machine user was provisioned: %v", err)
	}
}
