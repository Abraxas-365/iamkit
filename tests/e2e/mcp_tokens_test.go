package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/gofiber/fiber/v2"
)

// mcpActionTarget binds a pre_access_token target (answering claims) to an
// environment with an MCP server and returns its client.
func mcpActionTarget(t *testing.T, e *Env, receiver *actionReceiver, srvURL string) {
	t.Helper()
	created := e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Claims " + time.Now().Format("150405.000000000"), "url": srvURL}, 201).JSON
	receiver.secret = created["secret"].(string)
	e.Must("PUT", e.Base+"/action-executions/function:pre_access_token", e.Owner, fiber.Map{"targets": []string{created["id"].(string)}}, 200)
}

// TestResourceTokenClaimsAreNotForSale is L7: an action answering
// pre_access_token cannot set or override the resource indicator, the
// audience, the permissions, the scope or the subject of a resource flow
// token — at the first issuance and at every refresh — while a plain claim
// still lands and leaves with the target's answer.
func TestResourceTokenClaimsAreNotForSale(t *testing.T) {
	receiver := &actionReceiver{answers: map[string]string{}}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithActionTransport(http.DefaultTransport))
	client, _, _ := e.mcpServer(fiber.Map{})
	mcpActionTarget(t, e, receiver, srv.URL)

	issue := func() map[string]any {
		b := e.browser()
		code := b.signIn(b.get(resourceAuthorize(client, nil)))
		status, tokens, _ := e.tokenCall(codeForm(client, code, mcpURI), "")
		if status != 200 {
			t.Fatalf("code exchange: %d %v", status, tokens)
		}
		return tokens
	}
	check := func(when string, access map[string]any) {
		t.Helper()
		if access["resource"] != mcpURI || access["sub"] != e.Alice {
			t.Fatalf("%s: resource/sub = %v / %v", when, access["resource"], access["sub"])
		}
		if aud, _ := access["aud"].([]any); len(aud) != 1 || aud[0] != mcpURI {
			t.Fatalf("%s: aud = %v", when, access["aud"])
		}
		if perms := strs(access["permissions"]); !sameSet(perms, []string{"mcp:tools:read"}) {
			t.Fatalf("%s: permissions = %v", when, access["permissions"])
		}
		if !sameSet(strings.Fields(access["scope"].(string)), []string{"mcp:tools:read", "offline_access"}) && !sameSet(strings.Fields(access["scope"].(string)), []string{"mcp:tools:read"}) {
			t.Fatalf("%s: scope = %v", when, access["scope"])
		}
	}

	// Every reserved name, alone: the answer is invalid, the call is logged
	// as failed, and the token is the one IAMKit would have issued.
	reserved := map[string]string{
		"resource":    `"https://evil.example/mcp"`,
		"aud":         `["https://evil.example/mcp"]`,
		"permissions": `["mcp:tools:read","mcp:tools:write"]`,
		"scope":       `"mcp:tools:write"`,
		"sub":         `"someone-else"`,
	}
	failedCalls := func() []map[string]any {
		return items(e.Must("GET", e.Base+"/action-calls?condition=function:pre_access_token&outcome=failed", e.Owner, nil, 200))
	}
	for name, value := range reserved {
		// A target that keeps failing trips its breaker and is skipped: each
		// name gets a fresh target, so the refresh below runs the hook too.
		mcpActionTarget(t, e, receiver, srv.URL)
		before := len(failedCalls())
		receiver.answer("function:pre_access_token", `{"claims":{"`+name+`":`+value+`}}`)
		tokens := issue()
		check("issue "+name, claims(t, tokens["access_token"].(string)))
		if calls := failedCalls(); len(calls) != before+1 || !strings.Contains(calls[0]["error"].(string), "claim "+name+" is reserved") {
			t.Fatalf("%s: failed calls = %v", name, calls)
		}
		refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {tokens["refresh_token"].(string)}}, "", "")
		if refreshed.Status != 200 {
			t.Fatalf("%s: refresh: %s", name, refreshed.Body)
		}
		check("refresh "+name, claims(t, refreshed.JSON["access_token"].(string)))
		// The refresh ran the hook again and was refused the same way.
		if calls := failedCalls(); len(calls) != before+2 {
			t.Fatalf("%s: refresh did not run the hook: %d failed calls (before %d)", name, len(calls), before)
		}
	}

	mcpActionTarget(t, e, receiver, srv.URL)
	// Everything at once next to a legitimate claim: the whole answer is
	// refused (it is one answer), and a clean answer lands its claim.
	receiver.answer("function:pre_access_token", `{"claims":{"resource":"https://evil.example/mcp","permissions":["x"],"tier":"gold"}}`)
	if access := claims(t, issue()["access_token"].(string)); access["tier"] != nil {
		t.Fatalf("an answer with reserved names was partly applied: %v", access)
	} else {
		check("mixed", access)
	}
	receiver.answer("function:pre_access_token", `{"claims":{"tier":"gold"}}`)
	tokens := issue()
	access := claims(t, tokens["access_token"].(string))
	check("plain", access)
	if access["tier"] != "gold" {
		t.Fatalf("plain claim missing: %v", access)
	}
	// And it leaves with the target's next answer, without taking the
	// indicator with it.
	receiver.answer("function:pre_access_token", "")
	refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {tokens["refresh_token"].(string)}}, "", "")
	if refreshed.Status != 200 {
		t.Fatalf("refresh: %s", refreshed.Body)
	}
	after := claims(t, refreshed.JSON["access_token"].(string))
	check("refresh after", after)
	if after["tier"] != nil {
		t.Fatalf("claim survived the target's silence: %v", after)
	}
}

// TestAuthorizeErrorRedirectsCarryIssuer is L3: every error the client is
// sent back with names the issuer (RFC 9207) — access_denied from a token
// hook, login_required for prompt=none, a sign-in older than the request —
// for hosted and custom UI clients, MCP resource flow included. A ticket
// that expired has nobody to send back to: a page, never a redirect.
func TestAuthorizeErrorRedirectsCarryIssuer(t *testing.T) {
	receiver := &actionReceiver{answers: map[string]string{}}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithActionTransport(http.DefaultTransport))
	mcp, _, _ := e.mcpServer(fiber.Map{})
	mcpActionTarget(t, e, receiver, srv.URL)

	assertError := func(name, location, want string) {
		t.Helper()
		loc, err := url.Parse(location)
		if err != nil || loc.Query().Get("error") != want || loc.Query().Get("iss") != testIssuer || loc.Query().Get("state") != "unpredictable-state-123456" || loc.Query().Get("code") != "" {
			t.Fatalf("%s: %q", name, location)
		}
	}

	// access_denied: a token hook refuses at the end of the sign-in.
	receiver.answer("function:pre_access_token", `{"deny":true,"message":"No tokens today"}`)
	b := e.browser()
	start := b.get(resourceAuthorize(mcp, nil))
	tk := b.get(start.Location).field("ticket")
	denied := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if denied.Status != 303 {
		t.Fatalf("denied: %d %s", denied.Status, denied.Body)
	}
	assertError("access_denied", denied.Location, "access_denied")
	receiver.answer("function:pre_access_token", "")

	// login_required: prompt=none, before any ticket (redirect and JSON).
	none := e.browser().get(resourceAuthorize(mcp, url.Values{"prompt": {"none"}, "scope": {""}}))
	if none.Status != 303 {
		t.Fatalf("prompt=none: %d %s", none.Status, none.Body)
	}
	assertError("prompt=none", none.Location, "login_required")
	req := httptest.NewRequest("GET", resourceAuthorize(mcp, url.Values{"prompt": {"none"}}), nil)
	req.Header.Set("Accept", "application/json")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var done map[string]string
	json.NewDecoder(res.Body).Decode(&done)
	res.Body.Close()
	assertError("prompt=none as JSON", done["redirect_to"], "login_required")

	// login_required: a custom UI whose sign-in is older than the request
	// (prompt=login / max_age=0), at /oauth/authorize/complete.
	custom := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true}, 201).JSON["client_id"].(string)
	older := e.Login(e.AliceEmail)
	time.Sleep(1100 * time.Millisecond) // auth_time has whole-second precision
	for _, extra := range []url.Values{{"prompt": {"login"}}, {"max_age": {"0"}}} {
		b := e.browser()
		var begin map[string]any
		json.Unmarshal([]byte(b.get(authorizeQuery(custom, extra)).Body), &begin)
		body, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
		req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+older)
		for _, c := range b.cookies {
			req.AddCookie(c)
		}
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		assertError("stale sign-in "+extra.Encode(), res.Header.Get("Location"), "login_required")
	}

	// An expired ticket cannot name a client to return to: a refusal page.
	b = e.browser()
	start = b.get(resourceAuthorize(mcp, nil))
	tk = b.get(start.Location).field("ticket")
	e.DB.MustExec(`UPDATE oauth_authorizations SET expires_at=now()-interval '1 minute' WHERE consumed_at IS NULL`)
	page := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if strings.Contains(page.Location, "code=") || strings.HasPrefix(page.Location, "https://app.example/callback") || page.Status < 300 {
		t.Fatalf("expired ticket: %d %q", page.Status, page.Location)
	}
}
