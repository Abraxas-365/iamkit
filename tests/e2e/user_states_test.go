package e2e_test

import (
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestUserStates covers the derived user state: initial until the first
// sign-in, active, inactive without a live membership, locked by the
// password policy, suspended/reactivated (audited) through management and
// /api/v1, and the ?state= list filter.
func TestUserStates(t *testing.T) {
	e := newEnv(t)
	state := func(id string) string {
		t.Helper()
		return e.Must("GET", e.Base+"/users/"+id, e.Owner, nil, 200).JSON["state"].(string)
	}
	listed := func(s string) []string {
		t.Helper()
		items, _ := e.Must("GET", e.Base+"/users?state="+s, e.Owner, nil, 200).JSON["items"].([]any)
		out := []string{}
		for _, it := range items {
			out = append(out, it.(map[string]any)["id"].(string))
		}
		return out
	}

	if got := state(e.Alice); got != "initial" {
		t.Fatalf("new user state = %s", got)
	}
	e.Login(e.AliceEmail)
	u := e.Must("GET", e.Base+"/users/"+e.Alice, e.Owner, nil, 200).JSON
	if u["state"] != "active" || u["last_signed_in_at"] == nil {
		t.Fatalf("after sign-in = %v", u)
	}
	if !contains(listed("active"), e.Alice) || contains(listed("initial"), e.Alice) {
		t.Fatal("state filter")
	}
	e.Must("GET", e.Base+"/users?state=bogus", e.Owner, nil, 400)

	// No active organization → inactive.
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"active": false}, 204)
	if got := state(e.Alice); got != "inactive" || !contains(listed("inactive"), e.Alice) {
		t.Fatalf("without an active organization = %s", got)
	}
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"active": true}, 204)

	// Locked by the password policy.
	e.Must("PUT", e.Base+"/password-policy", e.Owner, fiber.Map{"min_length": 12, "lockout_threshold": 2, "lockout_minutes": 10}, 200)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "wrong password here"), 401)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "wrong password here"), 401)
	if got := state(e.Alice); got != "locked" || !contains(listed("locked"), e.Alice) {
		t.Fatalf("after lockout = %s", got)
	}
	e.Must("POST", e.Base+"/users/"+e.Alice+"/unlock", e.Owner, nil, 204)

	// Deactivate / reactivate, audited; deactivation ends sessions.
	token := e.Login(e.AliceEmail)
	e.Must("GET", "/identity/v1/me?environment_id="+e.EnvID+"&audience="+e.Audience, token, nil, 200)
	e.Must("POST", e.Base+"/users/"+e.Alice+"/deactivate", e.Owner, nil, 204)
	if got := state(e.Alice); got != "suspended" {
		t.Fatalf("after deactivate = %s", got)
	}
	e.Must("GET", "/identity/v1/me?environment_id="+e.EnvID+"&audience="+e.Audience, token, nil, 401)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 401)
	e.Must("POST", e.Base+"/users/"+e.Alice+"/reactivate", e.Owner, nil, 204)
	if got := state(e.Alice); got != "active" {
		t.Fatalf("after reactivate = %s", got)
	}
	if e.audited("user.deactivated", e.Alice) != 1 || e.audited("user.reactivated", e.Alice) != 1 {
		t.Fatal("state changes not audited")
	}
	// DELETE /users/:id keeps working as suspend (and is audited now).
	e.Must("DELETE", e.Base+"/users/"+e.Alice, e.Owner, nil, 204)
	if got := state(e.Alice); got != "suspended" || e.audited("user.deactivated", e.Alice) != 2 {
		t.Fatalf("legacy suspend = %s", got)
	}

	// /api/v1 needs iam:users:write.
	api := "/api/v1/environments/" + e.EnvID + "/users/" + e.Alice
	e.Must("POST", api+"/reactivate", e.scopedToken("iam:users:read"), nil, 403)
	e.Must("POST", api+"/reactivate", e.scopedToken("iam:users:write"), nil, 204)
	e.Must("POST", api+"/deactivate", e.scopedToken("iam:users:write"), nil, 204)
	e.Must("POST", e.Base+"/users/00000000-0000-0000-0000-000000000000/deactivate", e.Owner, nil, 404)
}
