package e2e_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// loginAgent signs in with a User-Agent header (the harness' Do sends none).
func (e *Env) loginAgent(email, agent string) string {
	e.t.Helper()
	raw, _ := json.Marshal(e.LoginBody(email, e.Pass))
	r := httptest.NewRequest("POST", "/identity/v1/login", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", agent)
	res, err := e.App.Test(r, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	token, _ := out["access_token"].(string)
	if res.StatusCode != 200 || token == "" {
		e.t.Fatalf("login = %d %s", res.StatusCode, body)
	}
	return token
}

// TestMeSessions: a user lists and ends their own sessions; the address and
// User-Agent of the sign-in are kept; other users' sessions are 404;
// impersonated tokens may list but not revoke.
func TestMeSessions(t *testing.T) {
	e := newEnv(t)
	q := "?environment_id=" + e.EnvID + "&audience=" + e.Audience
	const agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15"

	first := e.loginAgent(e.AliceEmail, agent)
	second := e.Login(e.AliceEmail)
	third := e.Login(e.AliceEmail)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	bobToken := e.Login("bob@example.com")

	e.Must("GET", "/identity/v1/me/sessions"+q, "", nil, 401)
	list := e.Must("GET", "/identity/v1/me/sessions"+q, first, nil, 200).JSON
	items := list["items"].([]any)
	if len(items) != 3 || list["page"].(map[string]any)["total"] != float64(3) {
		t.Fatalf("sessions = %v", list)
	}
	// Newest first: the third sign-in leads; only the caller's is current.
	current := 0
	var firstID, secondID, thirdID string
	for i, raw := range items {
		s := raw.(map[string]any)
		if s["current"] == true {
			current++
			firstID = s["id"].(string)
			if s["user_agent"] != agent || s["ip_address"] != "0.0.0.0" {
				t.Fatalf("current session client info = %v %v", s["ip_address"], s["user_agent"])
			}
		}
		if s["organization"].(map[string]any)["name"] != "Acme" || s["application"].(map[string]any)["name"] != "web" || s["impersonated"] != false {
			t.Fatalf("session = %v", s)
		}
		if i == 0 {
			thirdID = s["id"].(string)
		}
		if i == 1 {
			secondID = s["id"].(string)
		}
	}
	if current != 1 || firstID == thirdID || firstID == secondID {
		t.Fatalf("current flags = %d first=%s", current, firstID)
	}
	if page := e.Must("GET", "/identity/v1/me/sessions"+q+"&limit=1&offset=1", first, nil, 200).JSON; len(page["items"].([]any)) != 1 || page["page"].(map[string]any)["total"] != float64(3) {
		t.Fatalf("page = %v", page)
	}
	// The management inventory shows the same client info.
	found := false
	for _, raw := range e.Must("GET", e.Base+"/sessions?user_id="+e.Alice, e.Owner, nil, 200).JSON["items"].([]any) {
		if s := raw.(map[string]any); s["id"] == firstID {
			found = s["user_agent"] == agent && s["ip_address"] == "0.0.0.0"
		}
	}
	if !found {
		t.Fatal("management session list lacks ip_address/user_agent")
	}

	// Bob cannot see or end Alice's sessions; unknown and malformed ids are 404 too.
	bobList := e.Must("GET", "/identity/v1/me/sessions"+q, bobToken, nil, 200).JSON["items"].([]any)
	if len(bobList) != 1 {
		t.Fatalf("bob sessions = %v", bobList)
	}
	e.Must("DELETE", "/identity/v1/me/sessions/"+thirdID+q, bobToken, nil, 404)
	e.Must("DELETE", "/identity/v1/me/sessions/00000000-0000-0000-0000-000000000000"+q, first, nil, 404)
	e.Must("DELETE", "/identity/v1/me/sessions/nope"+q, first, nil, 404)
	e.Must("GET", "/identity/v1/me"+q, third, nil, 200)

	// Impersonated tokens list but never revoke.
	imp := e.Must("POST", e.Base+"/impersonations", e.Owner, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "reason": "support ticket 42"}, 200).JSON["access_token"].(string)
	impList := e.Must("GET", "/identity/v1/me/sessions"+q, imp, nil, 200).JSON["items"].([]any)
	marked := 0
	for _, raw := range impList {
		if raw.(map[string]any)["impersonated"] == true {
			marked++
			// The operator's address and agent are not the user's to see.
			if ip, ua := raw.(map[string]any)["ip_address"], raw.(map[string]any)["user_agent"]; ip != nil || ua != nil {
				t.Fatalf("impersonated session shows the operator's client: ip=%v user_agent=%v", ip, ua)
			}
		}
	}
	if len(impList) != 4 || marked != 1 {
		t.Fatalf("impersonated list = %d items, %d marked", len(impList), marked)
	}
	e.Must("DELETE", "/identity/v1/me/sessions/"+thirdID+q, imp, nil, 403)
	e.Must("POST", "/identity/v1/me/sessions/revoke-others"+q, imp, nil, 403)

	// Revoke one: its token stops working, the rest are untouched.
	e.Must("DELETE", "/identity/v1/me/sessions/"+thirdID+q, first, nil, 204)
	e.Must("GET", "/identity/v1/me"+q, third, nil, 401)
	e.Must("DELETE", "/identity/v1/me/sessions/"+thirdID+q, first, nil, 404)
	e.Must("GET", "/identity/v1/me"+q, second, nil, 200)
	events := e.Must("GET", e.Base+"/events?type=session.revoked&subject="+thirdID, e.Owner, nil, 200).JSON["items"].([]any)
	if len(events) != 1 || events[0].(map[string]any)["actor"].(map[string]any)["id"] != e.Alice {
		t.Fatalf("session.revoked event = %v", events)
	}

	// Revoke the others: the count is the live ones (second + impersonation), the current stays.
	if got := e.Must("POST", "/identity/v1/me/sessions/revoke-others"+q, first, nil, 200).JSON["count"]; got != float64(2) {
		t.Fatalf("revoke-others count = %v", got)
	}
	e.Must("GET", "/identity/v1/me"+q, second, nil, 401)
	e.Must("GET", "/identity/v1/me"+q, imp, nil, 401)
	e.Must("GET", "/identity/v1/me"+q, first, nil, 200)
	e.Must("GET", "/identity/v1/me"+q, bobToken, nil, 200)
	if got := e.Must("POST", "/identity/v1/me/sessions/revoke-others"+q, first, nil, 200).JSON["count"]; got != float64(0) {
		t.Fatalf("second revoke-others count = %v", got)
	}
	// Only the call that ended sessions is audited; the empty one writes nothing.
	if got := e.audited("session.revoke_others", e.Alice); got != 1 {
		t.Fatalf("revoke-others audit rows = %d, want 1", got)
	}

	// Revoking the current session is allowed and signs the token out.
	e.Must("DELETE", "/identity/v1/me/sessions/"+firstID+q, first, nil, 204)
	e.Must("GET", "/identity/v1/me"+q, first, nil, 401)
}
