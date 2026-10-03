package e2e_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/action/adapters/actionhook"
	"github.com/gofiber/fiber/v2"
)

// actionReceiver is a loopback action target: it verifies the signature,
// records each input and answers what the test tells it per condition.
type actionReceiver struct {
	mu      sync.Mutex
	secret  string
	answers map[string]string // condition → JSON body ("" = 204)
	status  int
	inputs  []map[string]any
	bad     int
}

func (r *actionReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	want, _ := actionhook.Sign([]string{r.secret}, req.Header.Get("webhook-id"), req.Header.Get("webhook-timestamp"), body)
	if !strings.Contains(" "+req.Header.Get("webhook-signature")+" ", " "+want+" ") {
		r.bad++
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	r.inputs = append(r.inputs, in)
	if r.status != 0 {
		w.WriteHeader(r.status)
		return
	}
	answer := r.answers[in["condition"].(string)]
	if answer == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(answer))
}

func (r *actionReceiver) answer(condition, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[condition] = body
}

func (r *actionReceiver) fail(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
}

func (r *actionReceiver) last(condition string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.inputs) - 1; i >= 0; i-- {
		if r.inputs[i]["condition"] == condition {
			return r.inputs[i]
		}
	}
	return nil
}

// TestActions: targets bound to conditions deny sign-ins, add token
// claims (re-run on refresh, reserved names refused), extend UserInfo,
// patch or refuse management requests; failures interrupt only with
// interrupt_on_error; the feature flag turns them off; target changes and
// failures are events.
func TestActions(t *testing.T) {
	receiver := &actionReceiver{answers: map[string]string{}}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithActionTransport(http.DefaultTransport))

	// Management: validation, the catalog, secrets shown once.
	conditions := items(e.Must("GET", e.Base+"/action-conditions", e.Owner, nil, 200))
	if len(conditions) != 9 || conditions[0]["name"] != "function:pre_sign_in" {
		t.Fatalf("conditions = %v", conditions)
	}
	e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Risk", "url": "http://risk.example"}, 400)
	e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Risk", "url": srv.URL, "timeout_ms": 20000}, 400)
	e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Risk", "url": srv.URL, "kind": "async", "interrupt_on_error": true}, 400)
	// httptest URLs are http://127.0.0.1 — allowed for loopback development.
	created := e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Risk", "url": srv.URL}, 201).JSON
	target, secret := created["id"].(string), created["secret"].(string)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret = %q", secret)
	}
	receiver.secret = secret
	if got := e.Must("GET", e.Base+"/action-targets/"+target, e.Owner, nil, 200); strings.Contains(got.Body, "whsec_") || got.JSON["kind"] != "call" || got.JSON["timeout_ms"] != float64(5000) {
		t.Fatalf("target = %s", got.Body)
	}
	e.Must("PUT", e.Base+"/action-executions/function:nope", e.Owner, fiber.Map{"targets": []string{target}}, 404)
	e.Must("PUT", e.Base+"/action-executions/function:pre_sign_in", e.Owner, fiber.Map{"targets": []string{}}, 400)
	e.Must("PUT", e.Base+"/action-executions/function:pre_sign_in", e.Owner, fiber.Map{"targets": []string{"00000000-0000-4000-8000-000000000001"}}, 404)

	// Test invoke: logged, never applied.
	receiver.answer("function:pre_sign_in", `{"deny":true,"message":"Blocked"}`)
	tested := e.Must("POST", e.Base+"/action-targets/"+target+"/test", e.Owner, fiber.Map{"condition": "function:pre_sign_in", "input": fiber.Map{"user": fiber.Map{"email": "x@example.com"}}}, 200).JSON
	if tested["outcome"] != "denied" || tested["response"].(map[string]any)["message"] != "Blocked" {
		t.Fatalf("test = %v", tested)
	}

	// pre_sign_in denies every session path with the receiver's message.
	e.Must("PUT", e.Base+"/action-executions/function.pre_sign_in", e.Owner, fiber.Map{"targets": []string{target}}, 200)
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 403); errorOf(r)["code"] != "ACTION_DENIED" || errorOf(r)["message"] != "Blocked" {
		t.Fatalf("deny = %s", r.Body)
	}
	in := receiver.last("function:pre_sign_in")
	if in["environment_id"] != e.EnvID || in["organization_id"] != e.Org || in["user"].(map[string]any)["email"] != e.AliceEmail || in["amr"].([]any)[0] != "pwd" {
		t.Fatalf("input = %v", in)
	}
	var sessions int
	e.DB.Get(&sessions, `SELECT count(*) FROM sessions WHERE user_id=$1`, e.Alice)
	if sessions != 0 {
		t.Fatalf("a denied sign-in left %d sessions", sessions)
	}
	// The hosted page shows the message too.
	client := e.hostedClient()
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 || !strings.Contains(p.Body, "Blocked") {
		t.Fatalf("hosted deny: %d %s", p.Status, p.Body)
	}

	// A failing target is skipped unless it interrupts.
	receiver.answer("function:pre_sign_in", "")
	receiver.fail(500)
	e.Login(e.AliceEmail)
	e.Must("PATCH", e.Base+"/action-targets/"+target, e.Owner, fiber.Map{"interrupt_on_error": true}, 200)
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 502); errorOf(r)["code"] != "ACTION_FAILED" {
		t.Fatalf("interrupt = %s", r.Body)
	}
	calls := items(e.Must("GET", e.Base+"/action-calls?outcome=failed", e.Owner, nil, 200))
	if len(calls) < 2 || calls[0]["status"] != float64(500) || calls[0]["error"] != "endpoint answered 500" {
		t.Fatalf("calls = %v", calls)
	}
	failed := e.Must("GET", e.Base+"/events?type=action.failed", e.Owner, nil, 200)
	if len(items(failed)) < 2 {
		t.Fatalf("action.failed events = %s", failed.Body)
	}
	receiver.fail(0)
	e.Must("PATCH", e.Base+"/action-targets/"+target, e.Owner, fiber.Map{"interrupt_on_error": false}, 200)
	e.Must("DELETE", e.Base+"/action-executions/function:pre_sign_in", e.Owner, nil, 204)

	// Token claims: added to access and ID tokens, refreshed, UserInfo too.
	for _, condition := range []string{"function:pre_access_token", "function:pre_id_token", "function:pre_userinfo"} {
		e.Must("PUT", e.Base+"/action-executions/"+url.PathEscape(condition), e.Owner, fiber.Map{"targets": []string{target}}, 200)
	}
	receiver.answer("function:pre_access_token", `{"claims":{"tier":"gold","https://example.com/roles":["admin"]}}`)
	receiver.answer("function:pre_id_token", `{"claims":{"nickname":"al"}}`)
	receiver.answer("function:pre_userinfo", `{"claims":{"plan":"pro"}}`)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	tokens := b.exchange(client, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	access, id := claims(t, tokens["access_token"].(string)), claims(t, tokens["id_token"].(string))
	if access["tier"] != "gold" || access["https://example.com/roles"] == nil || id["nickname"] != "al" || access["nickname"] != nil || id["tier"] != nil {
		t.Fatalf("claims: access %v id %v", access, id)
	}
	if in = receiver.last("function:pre_access_token"); in["client_id"] != client || in["application_id"] != e.Client {
		t.Fatalf("token input = %v", in)
	}
	info := e.Must("GET", "/oauth/userinfo", tokens["access_token"].(string), nil, 200).JSON
	if info["plan"] != "pro" || info["sub"] != e.Alice {
		t.Fatalf("userinfo = %v", info)
	}
	// Refresh runs pre_access_token again: a removed claim disappears.
	receiver.answer("function:pre_access_token", `{"claims":{"tier":"silver"}}`)
	refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {tokens["refresh_token"].(string)}}, "", "")
	if refreshed.Status != 200 {
		t.Fatalf("refresh: %s", refreshed.Body)
	}
	if again := claims(t, refreshed.JSON["access_token"].(string)); again["tier"] != "silver" || again["https://example.com/roles"] != nil || again["sub"] != e.Alice {
		t.Fatalf("refreshed claims = %v", again)
	}
	// A reserved claim is an invalid answer: the token is issued without it.
	receiver.answer("function:pre_access_token", `{"claims":{"sub":"someone-else"}}`)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	tokens = b.exchange(client, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	if access = claims(t, tokens["access_token"].(string)); access["sub"] != e.Alice {
		t.Fatalf("reserved claim applied: %v", access)
	}
	if calls = items(e.Must("GET", e.Base+"/action-calls?condition=function:pre_access_token&outcome=failed", e.Owner, nil, 200)); len(calls) != 1 || !strings.Contains(calls[0]["error"].(string), "reserved") {
		t.Fatalf("reserved call = %v", calls)
	}
	// A denial at token time refuses the authorization: the client gets
	// access_denied with the message on its redirect URI.
	receiver.answer("function:pre_access_token", `{"deny":true,"message":"No tokens today"}`)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 303 || !strings.Contains(p.Location, "error=access_denied") || !strings.Contains(p.Location, "No+tokens+today") {
		t.Fatalf("token deny: %d %q %s", p.Status, p.Location, p.Body)
	}
	receiver.answer("function:pre_access_token", "")

	// Management requests: patch and deny.
	e.Must("PUT", e.Base+"/action-executions/request:user.create", e.Owner, fiber.Map{"targets": []string{target}}, 200)
	e.Must("PUT", e.Base+"/action-executions/request:membership.create", e.Owner, fiber.Map{"targets": []string{target}}, 200)
	receiver.answer("request:user.create", `{"patch":{"name":"Bob (verified)"}}`)
	bob := e.User("Bob", "bob@example.com")
	if got := e.Must("GET", e.Base+"/users/"+bob, e.Owner, nil, 200).JSON; got["name"] != "Bob (verified)" {
		t.Fatalf("patched user = %v", got)
	}
	if in = receiver.last("request:user.create"); in["request"].(map[string]any)["email"] != "bob@example.com" || in["request"].(map[string]any)["password"] != nil {
		t.Fatalf("request input = %v", in)
	}
	receiver.answer("request:user.create", `{"patch":{"name":""}}`)
	if r := e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"name": "Carol", "email": "carol@example.com"}, 422); errorOf(r)["code"] != "ACTION_FAILED" {
		t.Fatalf("invalid patch = %s", r.Body)
	}
	receiver.answer("request:membership.create", `{"deny":true,"message":"Contractors stay out of Acme"}`)
	if r := e.Must("POST", e.Base+"/memberships", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": bob}, 403); errorOf(r)["message"] != "Contractors stay out of Acme" {
		t.Fatalf("membership deny = %s", r.Body)
	}
	if contains(e.Members(e.Org), bob) {
		t.Fatal("denied membership added")
	}

	// The feature flag turns every action off.
	e.Must("PUT", e.Base+"/features/actions", e.Owner, fiber.Map{"enabled": false}, 200)
	e.Join(e.Org, bob)
	e.Must("PUT", e.Base+"/features/actions", e.Owner, fiber.Map{"enabled": true}, 200)

	// Rotation: both secrets sign during the overlap.
	rotated := e.Must("POST", e.Base+"/action-targets/"+target+"/rotate-secret", e.Owner, nil, 200).JSON["secret"].(string)
	receiver.mu.Lock()
	receiver.secret = rotated
	receiver.mu.Unlock()
	e.Must("POST", e.Base+"/action-targets/"+target+"/test", e.Owner, fiber.Map{"condition": "function:pre_sign_in"}, 200)
	if receiver.bad != 0 {
		t.Fatalf("%d unsigned calls", receiver.bad)
	}

	// Deleting a target removes it from its executions; changes are events.
	e.Must("DELETE", e.Base+"/action-targets/"+target, e.Owner, nil, 204)
	if left := items(e.Must("GET", e.Base+"/action-executions", e.Owner, nil, 200)); len(left) != 0 {
		t.Fatalf("executions = %v", left)
	}
	types := map[string]bool{}
	for _, ev := range items(e.Must("GET", e.Base+"/events?limit=200", e.Owner, nil, 200)) {
		types[ev["type"].(string)] = true
	}
	for _, want := range []string{"action_target.created", "action_target.updated", "action_target.secret_rotated", "action_target.deleted", "action_execution.updated", "action_execution.deleted", "action.failed"} {
		if !types[want] {
			t.Errorf("no %s event", want)
		}
	}
}

// TestRegistrationActions: pre_registration refuses self-service and
// federated sign-ups before any user exists; post_federation renames or
// refuses a verified external identity.
func TestRegistrationActions(t *testing.T) {
	receiver := &actionReceiver{answers: map[string]string{}}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithActionTransport(http.DefaultTransport))
	created := e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Registry", "url": srv.URL}, 201).JSON
	target := created["id"].(string)
	receiver.secret = created["secret"].(string)
	for _, condition := range []string{"function:pre_registration", "function:post_federation"} {
		e.Must("PUT", e.Base+"/action-executions/"+condition, e.Owner, fiber.Map{"targets": []string{target}}, 200)
	}
	receiver.answer("function:pre_registration", `{"deny":true,"message":"Invite only"}`)

	// Self-service sign-up: refused when verified, before the user exists.
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true, "allow_signup": true, "signup_organization_id": e.Org}, 200)
	challenge := e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "new@example.com", "name": "New", "password": "a long enough password"}, 202).JSON["challenge_id"]
	m, _ := e.Mail.Last("email_verification")
	if r := e.Must("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": challenge, "code": m.Code}, 403); errorOf(r)["code"] != "ACTION_DENIED" {
		t.Fatalf("signup deny = %s", r.Body)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='new@example.com'`); n != 0 {
		t.Fatal("denied sign-up created a user")
	}
	if in := receiver.last("function:pre_registration"); in["user"].(map[string]any)["email"] != "new@example.com" || in["organization_id"] != e.Org || fmt.Sprint(in["amr"]) != "[pwd]" {
		t.Fatalf("signup input = %v", in)
	}

	// Federation: post_federation sees the identity and may rename it.
	idp := newFakeIdP(t, e.Key, "social-client")
	e.IdP.Set(idp.Client().Transport)
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"name": "Social", "issuer": idp.URL, "client_id": "social-client", "client_secret": "sealed-secret",
		"signup": true, "signup_organization_id": e.Org, "link_email": true})
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "dave-sub", "email": "dave@example.net", "email_verified": true, "name": "Dave"}); r.Status != 403 || r.JSON["error"].(map[string]any)["code"] != "ACTION_DENIED" {
		t.Fatalf("federated sign-up not refused: %d %v", r.Status, r.JSON)
	}
	if in := receiver.last("function:post_federation"); in["identity"].(map[string]any)["subject"] != "dave-sub" || in["identity"].(map[string]any)["connection_id"] != conn {
		t.Fatalf("federation input = %v", in)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='dave@example.net'`); n != 0 {
		t.Fatal("denied federated sign-up created a user")
	}
	receiver.answer("function:pre_registration", "")
	receiver.answer("function:post_federation", `{"patch":{"name":"Dave (Social)"}}`)
	// Signed up (without access to the application: no sign-up group).
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "dave-sub", "email": "dave@example.net", "email_verified": true, "name": "Dave"}); r.Status != 403 || r.JSON["error"].(map[string]any)["code"] == "ACTION_DENIED" {
		t.Fatalf("federated sign-up: %d %v", r.Status, r.JSON)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='dave@example.net' AND name='Dave (Social)'`); n != 1 {
		t.Fatal("post_federation name not applied")
	}
	// An existing user linking is not a registration, but can be refused.
	receiver.answer("function:pre_registration", `{"deny":true}`)
	receiver.answer("function:post_federation", `{"deny":true,"message":"Use your work account"}`)
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-social", "email": e.AliceEmail, "email_verified": true}); r.Status != 403 || r.JSON["error"].(map[string]any)["message"] != "Use your work account" {
		t.Fatalf("post_federation deny: %d %v", r.Status, r.JSON)
	}
	receiver.answer("function:post_federation", "")
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-social", "email": e.AliceEmail, "email_verified": true}); r.Status != 200 {
		t.Fatalf("link ran pre_registration: %d %v", r.Status, r.JSON)
	}
}
