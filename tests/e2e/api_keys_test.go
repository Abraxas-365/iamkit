package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// keyPolicy saves the environment's API key policy.
func (e *Env) keyPolicy(userKeys, orgKeys bool, maxTTLDays any, perUser, perOrg int) {
	e.t.Helper()
	e.Must("PUT", e.Base+"/api-key-policy", e.Owner, fiber.Map{"user_keys": userKeys, "organization_keys": orgKeys, "max_ttl_days": maxTTLDays, "max_per_user": perUser, "max_per_organization": perOrg}, 200)
}

// allow sets the resource's API key allowlists.
func (e *Env) allow(resource string, user, org []string) {
	e.t.Helper()
	e.Must("PUT", e.Base+"/resources/"+resource+"/api-key-permissions", e.Owner, fiber.Map{"user": user, "organization": org}, 204)
}

// introspect asks /identity/v1/introspect about token for audience.
func (e *Env) introspect(token, audience string) map[string]any {
	e.t.Helper()
	return e.Must("POST", "/identity/v1/introspect", token, fiber.Map{"environment_id": e.EnvID, "audience": audience}, 200).JSON
}

// me is the query a user's /me/api-keys call carries.
func (e *Env) me() string {
	return "?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape(e.Audience)
}

// selfKey creates a key through /identity/v1/me/api-keys.
func (e *Env) selfKey(token string, body fiber.Map, want int) Response {
	e.t.Helper()
	return e.Must("POST", "/identity/v1/me/api-keys"+e.me(), token, body, want)
}

// keyBody is a create body for the billing resource.
func (e *Env) keyBody(name string, permissions ...string) fiber.Map {
	return fiber.Map{"name": name, "resource_id": e.Res, "permissions": permissions}
}

// makeOrgAdmin makes user an owner of org (the IAM resource linked to the app).
func (e *Env) makeOrgAdmin(org, user string) {
	e.t.Helper()
	e.Do("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.IAMResource()}) // 201, or already linked
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": org, "user_id": user, "role_id": e.systemRole("org_owner")}, 204)
}

func (e *Env) adminBase(org string) string {
	return "/api/v1/environments/" + e.EnvID + "/organizations/" + org + "/admin"
}

// machine creates a machine user in org with grants on the billing resource.
func (e *Env) machine(org, name string) string {
	e.t.Helper()
	bot := e.ID("POST", e.Base+"/users", fiber.Map{"kind": "machine", "name": name})
	e.Join(org, bot)
	e.Grant(org, bot, e.Res, "invoices:read", "invoices:write")
	return bot
}

func (e *Env) keyEvents(query string) Response {
	e.t.Helper()
	return e.Must("GET", e.Base+"/events?"+query, e.Owner, nil, 200)
}

// TestAPIKeyPolicyAndAllowlist: user and organization keys are off until the
// environment's policy turns them on, and carry only permissions the
// resource's allowlist for the kind names (never IAM's own).
func TestAPIKeyPolicyAndAllowlist(t *testing.T) {
	e := newEnv(t)
	e.Grant(e.Org, e.Alice, e.Res, "invoices:read", "invoices:write")
	alice := e.Login(e.AliceEmail)

	if p := e.Must("GET", e.Base+"/api-key-policy", e.Owner, nil, 200).JSON; p["user_keys"] != false || p["organization_keys"] != false || p["max_per_user"] != float64(10) || p["max_per_organization"] != float64(50) || p["max_ttl_days"] != nil {
		t.Fatalf("default policy = %v", p)
	}
	e.allow(e.Res, []string{"invoices:read"}, []string{"invoices:read"})

	// Off: both kinds are refused with API_KEYS_DISABLED.
	if r := e.selfKey(alice, e.keyBody("ci", "invoices:read"), 403); !strings.Contains(r.Body, "API_KEYS_DISABLED") {
		t.Fatalf("disabled user keys = %s", r.Body)
	}
	if r := e.Must("POST", e.Base+"/api-keys", e.Owner, fiber.Map{"organization_id": e.Org, "resource_id": e.Res, "name": "svc", "permissions": []string{"invoices:read"}}, 403); !strings.Contains(r.Body, "API_KEYS_DISABLED") {
		t.Fatalf("disabled organization keys = %s", r.Body)
	}
	if opts := e.Must("GET", "/identity/v1/me/api-keys/options"+e.me(), alice, nil, 200).JSON; opts["enabled"] != false {
		t.Fatalf("options while disabled = %v", opts)
	}

	// Policy validation.
	e.Must("PUT", e.Base+"/api-key-policy", e.Owner, fiber.Map{"user_keys": true, "organization_keys": true, "max_ttl_days": 366, "max_per_user": 10, "max_per_organization": 50}, 400)
	e.Must("PUT", e.Base+"/api-key-policy", e.Owner, fiber.Map{"user_keys": true, "organization_keys": true, "max_per_user": 0, "max_per_organization": 50}, 400)
	e.keyPolicy(true, true, nil, 10, 50)

	opts := e.Must("GET", "/identity/v1/me/api-keys/options"+e.me(), alice, nil, 200).JSON
	if opts["enabled"] != true {
		t.Fatalf("options = %v", opts)
	}
	resources := opts["resources"].([]any)
	if len(resources) != 1 || resources[0].(map[string]any)["id"] != e.Res || !equal(strs(resources[0].(map[string]any)["permissions"]), []string{"invoices:read"}) {
		t.Fatalf("option resources = %v", resources)
	}

	// Allowlist: write is outside it, even though Alice holds it.
	if r := e.selfKey(alice, e.keyBody("ci", "invoices:read", "invoices:write"), 422); !strings.Contains(r.Body, "invoices:write") {
		t.Fatalf("outside allowlist = %s", r.Body)
	}
	e.selfKey(alice, e.keyBody("ci"), 400)                                                   // user keys need permissions
	e.selfKey(alice, e.keyBody("ci", "invoices:nope"), 422)                                  // not a permission of the resource
	e.selfKey(alice, fiber.Map{"name": "ci", "permissions": []string{"invoices:read"}}, 400) // resource required
	created := e.selfKey(alice, e.keyBody("ci", "invoices:read"), 201).JSON
	if v, _ := created["value"].(string); !strings.HasPrefix(v, "ik_key_") || created["obfuscated_value"] != "ik_key_…"+v[len(v)-4:] {
		t.Fatalf("created = %v", created)
	}
	owner := created["owner"].(map[string]any)
	by := created["created_by"].(map[string]any)
	if owner["type"] != "user" || owner["user_id"] != e.Alice || created["organization_id"] != e.Org || created["resource_id"] != e.Res || created["expires"] != false || created["state"] != "active" || by["kind"] != "user" || by["id"] != e.Alice {
		t.Fatalf("created key = %v", created)
	}

	// The IAM resource refuses allowlists; so do unknown permissions.
	e.Must("PUT", e.Base+"/resources/"+e.IAMResource()+"/api-key-permissions", e.Owner, fiber.Map{"user": []string{"iam:users:read"}, "organization": []string{}}, 400)
	e.Must("PUT", e.Base+"/resources/"+e.Res+"/api-key-permissions", e.Owner, fiber.Map{"user": []string{"invoices:nope"}, "organization": []string{}}, 400)
	if r := e.Must("GET", e.Base+"/resources/"+e.Res, e.Owner, nil, 200).JSON["api_key_permissions"].(map[string]any); !equal(strs(r["user"]), []string{"invoices:read"}) {
		t.Fatalf("resource allowlist = %v", r)
	}

	// Operators create organization keys only (users create their own);
	// turning a kind off stops its existing keys.
	e.Must("POST", e.Base+"/api-keys", e.Owner, fiber.Map{"organization_id": e.Org, "resource_id": e.Res, "name": "x", "permissions": []string{"invoices:write"}}, 422)
	org := e.Must("POST", e.Base+"/api-keys", e.Owner, fiber.Map{"organization_id": e.Org, "resource_id": e.Res, "name": "svc", "permissions": []string{"invoices:read"}}, 201).JSON
	if org["owner"].(map[string]any)["type"] != "organization" || org["created_by"].(map[string]any)["kind"] != "operator" {
		t.Fatalf("operator key = %v", org)
	}
	userKey, orgKey := created["value"].(string), org["value"].(string)
	if !e.active(userKey) || !e.active(orgKey) {
		t.Fatal("new keys inactive")
	}
	e.keyPolicy(false, true, nil, 10, 50)
	if e.active(userKey) || !e.active(orgKey) {
		t.Fatal("policy did not switch user keys off alone")
	}
	e.keyPolicy(true, false, nil, 10, 50)
	if !e.active(userKey) || e.active(orgKey) {
		t.Fatal("policy did not switch organization keys off")
	}
	if got := eventTypes(e.keyEvents("type=api_key_policy.updated")); len(got) == 0 {
		t.Fatal("policy changes are not audited")
	}
	// Scoped /api/v1 tokens: read needs iam:api-keys:read, write its own.
	api := "/api/v1/environments/" + e.EnvID
	reader, writer := e.scopedToken("iam:api-keys:read"), e.scopedToken("iam:api-keys:read", "iam:api-keys:write")
	e.Must("GET", api+"/api-keys", reader, nil, 200)
	e.Must("GET", api+"/api-key-policy", reader, nil, 200)
	e.Must("PUT", api+"/api-key-policy", reader, fiber.Map{"user_keys": true, "organization_keys": true, "max_per_user": 10, "max_per_organization": 50}, 403)
	e.Must("DELETE", api+"/api-keys/"+org["id"].(string), reader, nil, 403)
	e.Must("DELETE", api+"/api-keys/"+org["id"].(string), writer, nil, 204)
	e.Must("DELETE", api+"/api-keys/"+org["id"].(string), writer, nil, 204) // idempotent
}

// TestAPIKeyUserKeyIntrospection: a user key is capped by the owner's live
// roles on every use, and validation answers the contract shape.
func TestAPIKeyUserKeyIntrospection(t *testing.T) {
	e := newEnv(t)
	e.keyPolicy(true, true, nil, 10, 50)
	e.allow(e.Res, []string{"invoices:read", "invoices:write"}, []string{"invoices:read", "invoices:write"})
	grant := e.Must("PUT", e.Base+"/grants", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "resource_id": e.Res, "permissions": []string{"invoices:read", "invoices:write"}}, 200).JSON["id"].(string)
	alice := e.Login(e.AliceEmail)
	issued := e.selfKey(alice, e.keyBody("ci", "invoices:read", "invoices:write"), 201).JSON
	key, id := issued["value"].(string), issued["id"].(string)

	got := e.introspect(key, e.Audience)
	claims, _ := got["claims"].(map[string]any)
	if got["active"] != true || claims["purpose"] != "api_key" || claims["sub"] != e.Alice || claims["environment_id"] != e.EnvID || claims["organization_id"] != e.Org || claims["resource_id"] != e.Res || claims["exp"] != float64(0) || !equal(strs(claims["aud"]), []string{e.Audience}) || !equal(strs(claims["permissions"]), []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("introspection = %v", got)
	}
	meta := claims["api_key"].(map[string]any)
	if meta["id"] != id || meta["name"] != "ci" || meta["resource_id"] != e.Res || !equal(strs(meta["permissions"]), []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("api_key claims = %v", meta)
	}
	if o := meta["owner"].(map[string]any); o["type"] != "user" || o["id"] != e.Alice || o["organization_id"] != e.Org {
		t.Fatalf("owner claims = %v", o)
	}

	// Another audience and another environment do not accept it.
	if e.introspect(key, "https://other.example")["active"] != false {
		t.Fatal("key accepted for another audience")
	}
	e.Must("POST", "/identity/v1/introspect", key, fiber.Map{"environment_id": "00000000-0000-4000-8000-00000000dead", "audience": e.Audience}, 200)
	var used bool
	if err := e.DB.Get(&used, `SELECT last_used_at IS NOT NULL FROM api_keys WHERE id=$1`, id); err != nil || !used {
		t.Fatalf("last_used_at not recorded: %v", err)
	}

	// Narrow the owner's role: the key's permission follows at once.
	e.Grant(e.Org, e.Alice, e.Res, "invoices:read")
	if p := e.permissions(key); !equal(p, []string{"invoices:read"}) {
		t.Fatalf("permissions after narrowing = %v", p)
	}
	e.Must("DELETE", e.Base+"/grants/"+grant, e.Owner, nil, 204)
	if e.active(key) {
		t.Fatal("key without any permission left is active")
	}
	// The key still exists (revoked only by explicit action or membership end).
	got2 := e.Must("GET", e.Base+"/api-keys/"+id, e.Owner, nil, 200).JSON
	if got2["state"] != "active" || got2["revoked_at"] != nil {
		t.Fatalf("key = %v", got2)
	}
	e.Grant(e.Org, e.Alice, e.Res, "invoices:write")
	if p := e.permissions(key); !equal(p, []string{"invoices:write"}) {
		t.Fatalf("permissions after regrant = %v", p)
	}

	// Deactivating the owner stops it; revoking ends it for good.
	e.Must("POST", e.Base+"/users/"+e.Alice+"/deactivate", e.Owner, nil, 204)
	if e.active(key) {
		t.Fatal("key of a deactivated user is active")
	}
	e.Must("POST", e.Base+"/users/"+e.Alice+"/reactivate", e.Owner, nil, 204)
	if !e.active(key) {
		t.Fatal("key inactive after reactivation")
	}
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/api-keys/"+id, e.Owner, nil, 204)
	if e.active(key) {
		t.Fatal("revoked key is active")
	}
	if k := e.Must("GET", e.Base+"/api-keys/"+id, e.Owner, nil, 200).JSON; k["state"] != "revoked" || k["revoked_at"] == nil {
		t.Fatalf("revoked key = %v", k)
	}
	e.Must("GET", e.Base+"/api-keys/00000000-0000-4000-8000-00000000dead", e.Owner, nil, 404)
}

// TestAPIKeyOrganizationKeys: an organization key outlives its creator's
// membership while a user key ends with it (event reason); the admin's own
// permissions bound the key; machine users' keys end with membership too.
func TestAPIKeyOrganizationKeys(t *testing.T) {
	e := newEnv(t)
	e.keyPolicy(true, true, nil, 10, 50)
	e.allow(e.Res, []string{"invoices:read", "invoices:write"}, []string{"invoices:read", "invoices:write"})
	e.makeOrgAdmin(e.Org, e.Alice)
	admin := e.orgAdminToken(e.Org, e.AliceEmail)
	base := e.adminBase(e.Org)
	userKey := e.selfKey(e.Login(e.AliceEmail), e.keyBody("mine", "invoices:read"), 201).JSON

	// Alice holds invoices:read only: the key cannot exceed her.
	if r := e.Must("POST", base+"/api-keys", admin, e.keyBody("svc", "invoices:read", "invoices:write"), 422); !strings.Contains(r.Body, "invoices:write") {
		t.Fatalf("granter check = %s", r.Body)
	}
	e.Must("POST", base+"/api-keys", admin, e.keyBody("svc"), 400)
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	foreign := e.keyBody("svc", "invoices:read")
	foreign["organization_id"] = other
	e.Must("POST", base+"/api-keys", admin, foreign, 400)
	if opts := e.Must("GET", base+"/api-keys/options", admin, nil, 200).JSON; opts["enabled"] != true || len(opts["resources"].([]any)) != 1 {
		t.Fatalf("admin options = %v", opts)
	} else if p := strs(opts["resources"].([]any)[0].(map[string]any)["permissions"]); !equal(p, []string{"invoices:read"}) {
		t.Fatalf("admin option permissions = %v", p)
	}
	org := e.Must("POST", base+"/api-keys", admin, e.keyBody("svc", "invoices:read"), 201).JSON
	key := org["value"].(string)
	if o := org["owner"].(map[string]any); o["type"] != "organization" || o["user_id"] != nil || org["created_by"].(map[string]any)["id"] != e.Alice {
		t.Fatalf("org key = %v", org)
	}
	claims := e.introspect(key, e.Audience)["claims"].(map[string]any)
	if claims["sub"] != "" || claims["organization_id"] != e.Org || claims["api_key"].(map[string]any)["owner"].(map[string]any)["type"] != "organization" {
		t.Fatalf("org key claims = %v", claims)
	}

	// The admin sees the organization's keys and members' user keys.
	listed := e.Must("GET", base+"/api-keys", admin, nil, 200)
	if got := ids(listed, "id"); len(got) != 2 || !contains(got, org["id"].(string)) || !contains(got, userKey["id"].(string)) {
		t.Fatalf("admin list = %s", listed.Body)
	}
	if got := ids(e.Must("GET", base+"/api-keys?owner_type=organization", admin, nil, 200), "id"); len(got) != 1 || got[0] != org["id"] {
		t.Fatalf("owner_type filter = %v", got)
	}
	if strings.Contains(listed.Body, key) {
		t.Fatal("list leaks the value")
	}

	// Organization-scoped events are visible to the admin.
	if got := ids(e.Must("GET", base+"/events?action=api", admin, nil, 200), "action"); !contains(got, "api_key.create") {
		t.Fatalf("admin events = %v", got)
	}

	// Alice leaves: her user key ends (reason), the organization key stays.
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+e.Alice, e.Owner, nil, 204)
	if k := e.Must("GET", e.Base+"/api-keys/"+userKey["id"].(string), e.Owner, nil, 200).JSON; k["state"] != "revoked" {
		t.Fatalf("user key after membership end = %v", k)
	}
	if !e.active(key) || !equal(e.permissions(key), []string{"invoices:read"}) {
		t.Fatal("organization key did not survive its creator")
	}
	ended := e.keyEvents("type=api_key.revoked&subject=" + userKey["id"].(string)).JSON["items"].([]any)
	if len(ended) != 1 {
		t.Fatalf("revoked events = %v", ended)
	}
	ev := ended[0].(map[string]any)
	if ev["data"].(map[string]any)["reason"] != "membership_ended" || ev["actor"].(map[string]any)["kind"] != "system" {
		t.Fatalf("membership-end event = %v", ev)
	}

	// Machine keys end with the membership as well.
	bot := e.machine(e.Org, "bot")
	machineKey := e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "m", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res}, 201).JSON
	if !e.active(machineKey["value"].(string)) {
		t.Fatal("machine key inactive")
	}
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+bot, e.Owner, nil, 204)
	if k := e.Must("GET", e.Base+"/api-keys/"+machineKey["id"].(string), e.Owner, nil, 200).JSON; k["state"] != "revoked" {
		t.Fatalf("machine key after membership end = %v", k)
	}
}

// TestAPIKeyLimitsAndLifetime: live-key limits (revoked keys do not count),
// the maximum lifetime and never-expiring keys.
func TestAPIKeyLimitsAndLifetime(t *testing.T) {
	e := newEnv(t)
	e.allow(e.Res, []string{"invoices:read"}, []string{"invoices:read"})
	e.Grant(e.Org, e.Alice, e.Res, "invoices:read")
	alice := e.Login(e.AliceEmail)
	e.keyPolicy(true, true, 30, 2, 1)

	// Lifetime: 30 days at most; "never" and an omitted expiry are refused.
	e.selfKey(alice, e.keyBody("a", "invoices:read"), 400)
	e.selfKey(alice, withTTL(e.keyBody("a", "invoices:read"), "never"), 400)
	e.selfKey(alice, withTTL(e.keyBody("a", "invoices:read"), "721h"), 400)
	e.selfKey(alice, withTTL(e.keyBody("a", "invoices:read"), "soon"), 400)
	e.selfKey(alice, withTTL(e.keyBody("a", "invoices:read"), "10m"), 400)
	first := e.selfKey(alice, withTTL(e.keyBody("a", "invoices:read"), "720h"), 201).JSON
	if first["expires"] != true || first["state"] != "active" {
		t.Fatalf("expiring key = %v", first)
	}
	if o := e.Must("GET", "/identity/v1/me/api-keys/options"+e.me(), alice, nil, 200).JSON; o["max_ttl_days"] != float64(30) {
		t.Fatalf("options = %v", o)
	}

	// Per-user limit of live keys: 2.
	second := e.selfKey(alice, withTTL(e.keyBody("b", "invoices:read"), "24h"), 201).JSON
	if r := e.selfKey(alice, withTTL(e.keyBody("c", "invoices:read"), "24h"), 422); !strings.Contains(r.Body, "API_KEY_LIMIT_REACHED") {
		t.Fatalf("limit = %s", r.Body)
	}
	e.Must("DELETE", "/identity/v1/me/api-keys/"+first["id"].(string)+e.me(), alice, nil, 204)
	e.selfKey(alice, withTTL(e.keyBody("c", "invoices:read"), "24h"), 201)
	e.Must("DELETE", "/identity/v1/me/api-keys/"+second["id"].(string)+e.me(), alice, nil, 204)

	// An expired key no longer counts, nor validates.
	var live int
	if err := e.DB.Get(&live, `SELECT count(*) FROM api_keys WHERE user_id=$1 AND revoked_at IS NULL`, e.Alice); err != nil || live != 1 {
		t.Fatalf("live keys = %d, %v", live, err)
	}
	if _, err := e.DB.Exec(`UPDATE api_keys SET expires_at=now()-interval '1 minute' WHERE user_id=$1 AND revoked_at IS NULL`, e.Alice); err != nil {
		t.Skipf("cannot age keys (schema differs): %v", err)
	}
	if got := ids(e.Must("GET", "/identity/v1/me/api-keys"+e.me()+"&state=expired", alice, nil, 200), "id"); len(got) != 1 {
		t.Fatalf("expired keys = %v", got)
	}
	e.selfKey(alice, withTTL(e.keyBody("d", "invoices:read"), "24h"), 201)
	e.selfKey(alice, withTTL(e.keyBody("e", "invoices:read"), "24h"), 201)
	e.selfKey(alice, withTTL(e.keyBody("f", "invoices:read"), "24h"), 422)

	// Organization keys: one live key.
	org := map[string]any{"organization_id": e.Org, "resource_id": e.Res, "name": "svc", "permissions": []string{"invoices:read"}, "expires_in": "24h"}
	k1 := e.Must("POST", e.Base+"/api-keys", e.Owner, org, 201).JSON
	if r := e.Must("POST", e.Base+"/api-keys", e.Owner, org, 422); !strings.Contains(r.Body, "API_KEY_LIMIT_REACHED") {
		t.Fatalf("organization limit = %s", r.Body)
	}
	e.Must("DELETE", e.Base+"/api-keys/"+k1["id"].(string), e.Owner, nil, 204)
	e.Must("POST", e.Base+"/api-keys", e.Owner, org, 201)

	// No maximum: keys may never expire (omitted or "never"), exp 0.
	e.keyPolicy(true, true, nil, 10, 50)
	forever := e.selfKey(alice, e.keyBody("forever", "invoices:read"), 201).JSON
	never := e.selfKey(alice, withTTL(e.keyBody("never", "invoices:read"), "never"), 201).JSON
	for _, k := range []map[string]any{forever, never} {
		if k["expires"] != false {
			t.Fatalf("never-expiring key = %v", k)
		}
		if c := e.introspect(k["value"].(string), e.Audience)["claims"].(map[string]any); c["exp"] != float64(0) || c["api_key"].(map[string]any)["expires_at"] == nil {
			t.Fatalf("claims = %v", c)
		}
	}
}

func withTTL(body fiber.Map, ttl string) fiber.Map {
	body["expires_in"] = ttl
	return body
}

// TestAPIKeyOrgAdminIsolation: administrators see and revoke only their
// organization's keys; machine keys are invisible to them; setup links
// and impersonated tokens do not manage keys; /admin/users hides machine
// users.
func TestAPIKeyOrgAdminIsolation(t *testing.T) {
	e := newEnv(t)
	e.keyPolicy(true, true, nil, 10, 50)
	e.allow(e.Res, []string{"invoices:read"}, []string{"invoices:read"})
	e.makeOrgAdmin(e.Org, e.Alice)
	alice := e.orgAdminToken(e.Org, e.AliceEmail)
	acme := e.adminBase(e.Org)

	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	gus := e.User("Gus", "gus@example.com")
	e.Join(globex, gus)
	e.Grant(globex, gus, e.Res, "invoices:read")
	e.makeOrgAdmin(globex, gus)
	gusToken := e.orgAdminToken(globex, "gus@example.com")
	theirs := e.adminBase(globex)

	acmeKey := e.Must("POST", acme+"/api-keys", alice, e.keyBody("acme", "invoices:read"), 201).JSON
	gusKey := e.Must("POST", theirs+"/api-keys", gusToken, e.keyBody("globex", "invoices:read"), 201).JSON
	botKey := e.Must("POST", e.Base+"/users/"+e.machine(e.Org, "bot")+"/api-keys", e.Owner, fiber.Map{"name": "m", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res}, 201).JSON

	if got := ids(e.Must("GET", acme+"/api-keys", alice, nil, 200), "id"); len(got) != 1 || got[0] != acmeKey["id"] {
		t.Fatalf("acme list = %v", got)
	}
	if got := ids(e.Must("GET", theirs+"/api-keys", gusToken, nil, 200), "id"); len(got) != 1 || got[0] != gusKey["id"] {
		t.Fatalf("globex list = %v", got)
	}
	// Other organizations' keys and machine keys: 404 for reads and revokes.
	for _, id := range []string{gusKey["id"].(string), botKey["id"].(string)} {
		e.Must("GET", acme+"/api-keys/"+id, alice, nil, 404)
		e.Must("DELETE", acme+"/api-keys/"+id, alice, nil, 404)
	}
	e.Must("GET", acme+"/api-keys?owner_type=machine", alice, nil, 200)
	if got := ids(e.Must("GET", acme+"/api-keys?owner_type=machine", alice, nil, 200), "id"); len(got) != 0 {
		t.Fatalf("machine keys visible: %v", got)
	}
	if !e.active(gusKey["value"].(string)) || !e.active(botKey["value"].(string)) {
		t.Fatal("a key was revoked across the boundary")
	}
	// Your own organization's key reads and revokes.
	e.Must("GET", acme+"/api-keys/"+acmeKey["id"].(string), alice, nil, 200)
	// A plain member (no iam:org permissions) has no access.
	bea := e.User("Bea", "bea@example.com")
	e.Join(e.Org, bea)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": bea, "role_id": e.systemRole("org_viewer")}, 204)
	viewer := e.orgAdminToken(e.Org, "bea@example.com")
	e.Must("GET", acme+"/api-keys", viewer, nil, 403)
	e.Must("POST", acme+"/api-keys", viewer, e.keyBody("x", "invoices:read"), 403)
	e.Must("GET", acme+"/api-keys", "", nil, 401)

	// Setup links: no keys, not even to read.
	link := e.Must("POST", e.Base+"/organizations/"+e.Org+"/setup-links", e.Owner, fiber.Map{"intents": []string{"sso", "directory", "domains"}}, 201).JSON
	setup := e.exchangeSetup(link["url"].(string), 200).JSON["access_token"].(string)
	e.Must("POST", acme+"/api-keys", setup, e.keyBody("x", "invoices:read"), 403)
	e.Must("GET", acme+"/api-keys", setup, nil, 403)
	e.Must("DELETE", acme+"/api-keys/"+acmeKey["id"].(string), setup, nil, 403)

	// Impersonated tokens administer nothing.
	imp := e.Must("POST", e.Base+"/impersonations", e.Owner, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.IAMResource(), "reason": "support ticket 7"}, 200).JSON["access_token"].(string)
	e.Must("GET", acme+"/api-keys", imp, nil, 403)
	e.Must("POST", acme+"/api-keys", imp, e.keyBody("x", "invoices:read"), 403)

	// Organization administrators never see machine users.
	bot := ids(e.Must("GET", e.Base+"/users?kind=machine", e.Owner, nil, 200), "id")[0]
	e.Must("PATCH", e.Base+"/users/"+bot, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	if got := ids(e.Must("GET", acme+"/users", alice, nil, 200), "id"); contains(got, bot) || !contains(got, e.Alice) {
		t.Fatalf("admin users = %v", got)
	}
	if got := ids(e.Must("GET", acme+"/members", alice, nil, 200), "user_id"); contains(got, bot) {
		t.Fatalf("admin members = %v", got)
	}
	e.Must("GET", acme+"/users/"+bot, alice, nil, 404)
	e.Must("PATCH", acme+"/users/"+bot, alice, fiber.Map{"name": "renamed"}, 404)
	e.Must("POST", acme+"/users/"+bot+"/deactivate", alice, nil, 404)

	// Revoke finally: the admin ends its own key; the other stays.
	e.Must("DELETE", acme+"/api-keys/"+acmeKey["id"].(string), alice, nil, 204)
	if e.active(acmeKey["value"].(string)) || !e.active(gusKey["value"].(string)) {
		t.Fatal("revoke affected the wrong key")
	}
}

// TestAPIKeySelfService: only application tokens of people use
// /me/api-keys, creating needs a recent sign-in, impersonated sessions read
// only, and users never touch another user's keys.
func TestAPIKeySelfService(t *testing.T) {
	e := newEnv(t)
	e.keyPolicy(true, true, nil, 10, 50)
	e.allow(e.Res, []string{"invoices:read"}, []string{"invoices:read"})
	other := e.Must("POST", e.Base+"/resources", e.Owner, fiber.Map{"name": "Other", "prefix": "other", "audience": "https://other.example", "permissions": []string{"other:read"}}, 201).JSON["id"].(string)
	e.allow(other, []string{"other:read"}, nil)
	e.Grant(e.Org, e.Alice, other, "other:read")
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")

	login := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200).JSON
	alice := login["access_token"].(string)
	bobToken := e.Login("bob@example.com")
	list := "/identity/v1/me/api-keys" + e.me()
	e.Must("GET", "/identity/v1/me/api-keys", alice, nil, 401) // no environment/audience: cannot be validated
	e.Must("GET", list, "", nil, 401)

	// Only linked resources: the application is not linked to Other.
	if r := e.selfKey(alice, fiber.Map{"name": "x", "resource_id": other, "permissions": []string{"other:read"}}, 400); !strings.Contains(r.Body, "resource") {
		t.Fatalf("unlinked resource = %s", r.Body)
	}
	// Only the caller's organization and user.
	e.selfKey(alice, fiber.Map{"name": "x", "resource_id": e.Res, "organization_id": e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"}), "permissions": []string{"invoices:read"}}, 400)

	mine := e.selfKey(alice, e.keyBody("mine", "invoices:read"), 201).JSON
	theirs := e.selfKey(bobToken, e.keyBody("bobs", "invoices:read"), 201).JSON
	if got := ids(e.Must("GET", list, alice, nil, 200), "id"); len(got) != 1 || got[0] != mine["id"] {
		t.Fatalf("alice keys = %v", got)
	}
	e.Must("DELETE", "/identity/v1/me/api-keys/"+theirs["id"].(string)+e.me(), alice, nil, 404)
	if !e.active(theirs["value"].(string)) {
		t.Fatal("alice revoked bob's key")
	}

	// Keys and other credentials cannot call the self-service routes.
	for _, bearer := range []string{mine["value"].(string), e.scopedToken("iam:users:read")} {
		if r := e.Do("GET", list, bearer, nil); r.Status != 401 && r.Status != 403 {
			t.Fatalf("self-service with a non-user token = %d", r.Status)
		}
		if r := e.Do("POST", "/identity/v1/me/api-keys"+e.me(), bearer, e.keyBody("x", "invoices:read")); r.Status != 401 && r.Status != 403 {
			t.Fatalf("self-service create with a non-user token = %d", r.Status)
		}
	}

	// Impersonated sessions read but never create or revoke.
	imp := e.Must("POST", e.Base+"/impersonations", e.Owner, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "reason": "support ticket 42"}, 200).JSON["access_token"].(string)
	e.Must("GET", list, imp, nil, 200)
	e.Must("GET", "/identity/v1/me/api-keys/options"+e.me(), imp, nil, 200)
	e.selfKey(imp, e.keyBody("x", "invoices:read"), 403)
	e.Must("DELETE", "/identity/v1/me/api-keys/"+mine["id"].(string)+e.me(), imp, nil, 403)

	// A session that signed in long ago cannot mint keys, even refreshed.
	if _, err := e.DB.Exec(`UPDATE sessions SET authenticated_at=now()-interval '1 hour' WHERE user_id=$1`, e.Alice); err != nil {
		t.Fatal(err)
	}
	refresh := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": login["refresh_token"]}
	stale := e.Must("POST", "/identity/v1/refresh", "", refresh, 200).JSON["access_token"].(string)
	if r := e.selfKey(stale, e.keyBody("late", "invoices:read"), 403); !strings.Contains(r.Body, "REAUTHENTICATION_REQUIRED") {
		t.Fatalf("stale session = %s", r.Body)
	}
	e.Must("GET", list, stale, nil, 200)
	e.Must("DELETE", "/identity/v1/me/api-keys/"+mine["id"].(string)+e.me(), stale, nil, 204)

	// Events name the user as actor; created_by names the user.
	created := e.keyEvents("type=api_key.created&subject=" + mine["id"].(string)).JSON["items"].([]any)
	if len(created) != 1 {
		t.Fatalf("created events = %v", created)
	}
	ev := created[0].(map[string]any)
	data := ev["data"].(map[string]any)
	if ev["actor"].(map[string]any)["id"] != e.Alice || ev["subject"].(map[string]any)["kind"] != "api_key" || data["owner_type"] != "user" || data["user_id"] != e.Alice || data["organization_id"] != e.Org || data["name"] != "mine" || data["resource_id"] != e.Res {
		t.Fatalf("created event = %v", ev)
	}
	if got := eventTypes(e.keyEvents("type=api_key.revoked&subject=" + mine["id"].(string))); len(got) != 1 {
		t.Fatalf("revoked events = %v", got)
	}
	if _, err := e.DB.Exec(`UPDATE users SET last_signed_in_at=NULL WHERE id=$1`, bob); err != nil {
		t.Fatal(err)
	}
	e.active(theirs["value"].(string))
	var signed bool
	if err := e.DB.Get(&signed, `SELECT last_signed_in_at IS NOT NULL FROM users WHERE id=$1`, bob); err != nil || signed {
		t.Fatalf("a user key marked a sign-in: %v", err)
	}
}

// TestAPIKeyMachineAndIAMAPI: only machine keys call the IAMKit API or
// exchange for a session; user and organization keys are refused there;
// revoking a machine key ends the sessions exchanged from it.
func TestAPIKeyMachineAndIAMAPI(t *testing.T) {
	e := newEnv(t)
	e.keyPolicy(true, true, nil, 10, 50)
	e.allow(e.Res, []string{"invoices:read"}, []string{"invoices:read"})
	e.Grant(e.Org, e.Alice, e.Res, "invoices:read", "invoices:write")
	api := "/api/v1/environments/" + e.EnvID

	userKey := e.selfKey(e.Login(e.AliceEmail), e.keyBody("u", "invoices:read"), 201).JSON["value"].(string)
	orgKey := e.Must("POST", e.Base+"/api-keys", e.Owner, fiber.Map{"organization_id": e.Org, "resource_id": e.Res, "name": "o", "permissions": []string{"invoices:read"}}, 201).JSON["value"].(string)

	// User and organization keys: 401 on /api/v1, no exchange, no self routes.
	for name, key := range map[string]string{"user": userKey, "organization": orgKey} {
		r := e.Must("GET", api+"/users", key, nil, 401)
		if !strings.Contains(r.Body, "API keys of users and organizations cannot call the IAMKit API") {
			t.Fatalf("%s key on /api/v1 = %s", name, r.Body)
		}
		e.Must("GET", api+"/organizations/"+e.Org+"/admin/api-keys", key, nil, 401)
		e.Must("POST", "/identity/v1/token-exchange", key, nil, 401)
		e.Must("GET", "/oauth/userinfo", key, nil, 401)
		e.Must("GET", "/identity/v1/me/sessions"+e.me(), key, nil, 401)
	}

	// A machine key with its own subset, and a machine key on the IAM API.
	bot := e.machine(e.Org, "bot")
	e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "m", "organization_id": e.Org, "resource_id": e.Res}, 400) // application required
	e.Must("POST", e.Base+"/users/"+e.Alice+"/api-keys", e.Owner, fiber.Map{"name": "m", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res}, 422)
	subset := e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "read", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "permissions": []string{"invoices:read"}, "expires_in": "24h"}, 201).JSON
	if subset["application_id"] != e.Client || subset["owner"].(map[string]any)["user_id"] != bot || !equal(strs(subset["permissions"]), []string{"invoices:read"}) {
		t.Fatalf("machine key = %v", subset)
	}
	all := e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "all", "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res}, 201).JSON
	if all["permissions"] != nil {
		t.Fatalf("machine key without a list = %v", all["permissions"])
	}
	if !equal(e.permissions(subset["value"].(string)), []string{"invoices:read"}) || !equal(e.permissions(all["value"].(string)), []string{"invoices:read", "invoices:write"}) {
		t.Fatal("machine key permissions")
	}
	if c := e.introspect(all["value"].(string), e.Audience)["claims"].(map[string]any); c["sub"] != bot || c["api_key"].(map[string]any)["owner"].(map[string]any)["type"] != "machine" {
		t.Fatalf("machine claims = %v", c)
	}
	var signedIn bool
	if err := e.DB.Get(&signedIn, `SELECT last_signed_in_at IS NOT NULL FROM users WHERE id=$1`, bot); err != nil || !signedIn {
		t.Fatalf("machine key use not recorded on the user: %v", err)
	}

	// Machine keys on the IAM resource reach /api/v1 with iam permissions only.
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Grant(e.Org, bot, iam, "iam:users:read")
	admin := e.Must("POST", e.Base+"/users/"+bot+"/api-keys", e.Owner, fiber.Map{"name": "admin", "organization_id": e.Org, "application_id": e.Client, "resource_id": iam}, 201).JSON
	e.Must("GET", api+"/users", admin["value"].(string), nil, 200)
	e.Must("POST", api+"/users", admin["value"].(string), fiber.Map{"name": "x", "email": "x@example.com"}, 403)
	e.Must("GET", api+"/users", subset["value"].(string), nil, 403)
	// The key listing of a user covers every kind; deletes stay in the user's scope.
	if got := ids(e.Must("GET", e.Base+"/users/"+bot+"/api-keys", e.Owner, nil, 200), "id"); len(got) != 3 {
		t.Fatalf("machine user keys = %v", got)
	}
	if got := ids(e.Must("GET", e.Base+"/users/"+e.Alice+"/api-keys", e.Owner, nil, 200), "id"); len(got) != 1 {
		t.Fatalf("alice keys = %v", got)
	}
	e.Must("DELETE", e.Base+"/users/"+bot+"/api-keys/"+admin["id"].(string), e.Owner, nil, 204)

	// Exchange: machine keys only, one reused session, ended by revoking.
	key := subset["value"].(string)
	exchanged := e.Must("POST", "/identity/v1/token-exchange", key, nil, 200).JSON["access_token"].(string)
	e.Must("POST", "/identity/v1/token-exchange", key, nil, 200)
	var sessions int
	if err := e.DB.Get(&sessions, `SELECT count(*) FROM sessions WHERE api_key_id=$1 AND revoked_at IS NULL`, subset["id"]); err != nil || sessions != 1 {
		t.Fatalf("sessions = %d, %v", sessions, err)
	}
	if !e.active(exchanged) {
		t.Fatal("exchanged token inactive")
	}
	e.Must("DELETE", e.Base+"/users/"+bot+"/api-keys/"+subset["id"].(string), e.Owner, nil, 204)
	if e.active(exchanged) || e.active(key) {
		t.Fatal("revoked machine key or its session still active")
	}
	if err := e.DB.Get(&sessions, `SELECT count(*) FROM sessions WHERE api_key_id=$1 AND revoked_at IS NULL`, subset["id"]); err != nil || sessions != 0 {
		t.Fatalf("live sessions after revoke = %d, %v", sessions, err)
	}
	e.Must("POST", "/identity/v1/token-exchange", key, nil, 401)

	// Events carry the operator as creator; machine keys' target is the key.
	ev := e.keyEvents("type=api_key.created&subject=" + subset["id"].(string)).JSON["items"].([]any)
	if len(ev) != 1 || ev[0].(map[string]any)["actor"].(map[string]any)["kind"] != "operator" || subset["created_by"].(map[string]any)["kind"] != "operator" {
		t.Fatalf("machine key created event = %v", ev)
	}
}
