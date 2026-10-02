package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestUsernames covers optional usernames: validation and normalization,
// uniqueness per environment, list search, headless password login and
// challenges by username (codes go to the account's email, unknown names
// answer like unknown emails), self profile and removal.
func TestUsernames(t *testing.T) {
	e := newEnv(t)
	user := e.Base + "/users/" + e.Alice
	for _, bad := range []string{"al", "alice@example", "_alice", "a b", strings.Repeat("a", 65)} {
		e.Must("PATCH", user, e.Owner, fiber.Map{"username": bad}, 400)
	}
	e.Must("PATCH", user, e.Owner, fiber.Map{"username": " Alice.Doe "}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["username"]; got != "alice.doe" {
		t.Fatalf("username = %v", got)
	}
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "other@example.com", "name": "Other", "username": "ALICE.DOE"}, 409)
	if got := e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "ALICE@example.com", "name": "Dup"}, 409).Body; !strings.Contains(got, "email is taken") {
		t.Fatalf("duplicate email = %s", got)
	}
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "other@example.com", "name": "Other", "username": "bad name"}, 400)
	other := e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "other@example.com", "name": "Other", "username": "other_1"}, 201).JSON["id"].(string)
	e.Must("PATCH", e.Base+"/users/"+other, e.Owner, fiber.Map{"username": "alice.doe"}, 409)
	e.Must("PATCH", user, e.Owner, fiber.Map{"name": "Alice"}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["username"]; got != "alice.doe" {
		t.Fatal("an update without username keeps it")
	}
	listed := items(e.Must("GET", e.Base+"/users?search=alice.d", e.Owner, nil, 200))
	if len(listed) != 1 || listed[0]["username"] != "alice.doe" {
		t.Fatalf("search by username = %v", listed)
	}
	api := "/api/v1/environments/" + e.EnvID + "/users/" + other
	e.Must("PATCH", api, e.scopedToken("iam:users:write"), fiber.Map{"username": "other.two"}, 204)

	// Headless login by username (login field), email still works.
	login := func(value, password string, status int) Response {
		t.Helper()
		body := e.LoginBody("", password)
		delete(body, "email")
		body["login"] = value
		return e.Must("POST", "/identity/v1/login", "", body, status)
	}
	token := login("Alice.Doe", e.Pass, 200).JSON["access_token"].(string)
	me := e.Must("GET", "/identity/v1/me?environment_id="+e.EnvID+"&audience="+e.Audience, token, nil, 200).JSON
	if me["username"] != "alice.doe" || me["email"] != e.AliceEmail {
		t.Fatalf("own profile = %v", me)
	}
	login(e.AliceEmail, e.Pass, 200)
	wrong := login("alice.doe", "wrong password!!", 401).Body
	unknown := login("nobody.here", e.Pass, 401).Body
	malformed := login("no such user", e.Pass, 401).Body
	if wrong != unknown || unknown != malformed {
		t.Fatalf("login failures differ: %s | %s | %s", wrong, unknown, malformed)
	}

	// Challenges by username go to the account's email.
	e.Must("PATCH", user, e.Owner, fiber.Map{"otp_enabled": true}, 204)
	sent := len(e.Mail.Sent)
	challenge := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "login": "alice.doe", "purpose": "login"}, 202).JSON["challenge_id"].(string)
	msg, ok := e.Mail.Last("login")
	if !ok || len(e.Mail.Sent) != sent+1 || msg.Email != e.AliceEmail {
		t.Fatalf("challenge by username sent %v to %q", ok, msg.Email)
	}
	verify := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "challenge_id": challenge, "code": msg.Code, "purpose": "login"}
	e.Must("POST", "/identity/v1/challenges/verify", "", verify, 200)
	if got := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "login": "nobody.here", "purpose": "login"}, 202).JSON["challenge_id"]; got == "" || len(e.Mail.Sent) != sent+1 {
		t.Fatal("an unknown username must answer like an unknown email, without sending")
	}

	// Removing the username stops username sign-in.
	e.Must("PATCH", user, e.Owner, fiber.Map{"username": ""}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["username"]; got != "" {
		t.Fatalf("removed username = %v", got)
	}
	login("alice.doe", e.Pass, 401)
	// Removing it frees it for someone else.
	e.Must("PATCH", e.Base+"/users/"+other, e.Owner, fiber.Map{"username": "alice.doe"}, 204)
}
