package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
)

// TestDeliveryWebhookGuarded: without the test transport, an environment
// webhook on a private or loopback address is refused before any request
// is sent, with a reason that does not reveal the address.
func TestDeliveryWebhookGuarded(t *testing.T) {
	var mu sync.Mutex
	hit := false
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit = true
		mu.Unlock()
	}))
	defer hook.Close()
	e := newEnv(t)
	for _, url := range []string{hook.URL + "/mail", strings.Replace(hook.URL, "127.0.0.1", "localhost", 1) + "/mail"} {
		e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": url, "webhook_token": "t"}, 204)
		a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
		if a["delivered"] != false || a["status"] != nil || a["reason"] != "webhook address is not allowed" {
			t.Fatalf("%s: %v", url, a)
		}
	}
	// A real challenge through the refused webhook is still answered 202.
	e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "password_reset"}, 202)
	mu.Lock()
	defer mu.Unlock()
	if hit {
		t.Fatal("guarded webhook reached a loopback receiver")
	}
}

// TestDeliveryStatusAndTest covers the effective delivery source, test
// sends through the global and environment webhooks, recorded activity
// (last attempt, sticky last failure), audit, permissions and rate limit.
func TestDeliveryStatusAndTest(t *testing.T) {
	// Environment webhooks are guarded; this receiver is on loopback.
	e := newEnv(t, bootstrap.WithMail(authmodule.Mail{WebhookClient: http.DefaultTransport}))
	status := func() map[string]any { return e.Must("GET", e.Base+"/delivery/status", e.Owner, nil, 200).JSON }

	// No override yet: the harness global sender serves the environment.
	s := status()
	if s["source"] != "global" || s["global_configured"] != true || s["hosted_invitation_url"] != "https://iam.example/hosted/invite" || s["last_attempt"] != nil || s["last_failure"] != nil {
		t.Fatalf("initial status = %v", s)
	}

	// Test send via global: code-less "test" payload, recorded and audited.
	e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "nope"}, 400)
	a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": " Ops@Example.com "}, 200).JSON
	if a["delivered"] != true || a["source"] != "global" || a["purpose"] != "test" || a["reason"] != nil {
		t.Fatalf("global test = %v", a)
	}
	if m, ok := e.Mail.Last("test"); !ok || m.Email != "ops@example.com" || m.Code != "" || m.Token != "" {
		t.Fatalf("test mail = %+v", m)
	}
	if e.audited("delivery.test", "global") != 1 {
		t.Fatal("test send not audited")
	}

	// A real challenge is recorded too.
	e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "password_reset"}, 202)
	if last := status()["last_attempt"].(map[string]any); last["purpose"] != "password_reset" || last["delivered"] != true {
		t.Fatalf("challenge activity = %v", last)
	}

	// Environment webhook: first rejecting, then accepting.
	var mu sync.Mutex
	code, bodies, signatures := 503, []string{}, []string{}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		bodies = append(bodies, string(b))
		signatures = append(signatures, r.Header.Get("webhook-signature"))
		if want := authmail.SignWebhook("t", r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), b); r.Header.Get("webhook-signature") != want {
			signatures[len(signatures)-1] = "bad"
		}
		w.WriteHeader(code)
		w.Write([]byte("internal secret detail"))
	}))
	defer hook.Close()
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": hook.URL + "/mail", "webhook_token": "t"}, 204)
	var plain, sealed string
	if err := e.DB.QueryRow(`SELECT webhook_token, secret_sealed FROM delivery_configs WHERE environment_id=$1`, e.EnvID).Scan(&plain, &sealed); err != nil || plain != "" || sealed == "" {
		t.Fatalf("webhook token at rest: plain %q sealed %q (%v)", plain, sealed, err)
	}
	if cfg := e.Must("GET", e.Base+"/delivery", e.Owner, nil, 200).JSON; cfg["has_token"] != true || cfg["has_secret"] != false {
		t.Fatalf("sealed token config = %v", cfg)
	}
	if s = status(); s["source"] != "environment" {
		t.Fatalf("override status = %v", s)
	}
	a = e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != false || a["source"] != "environment" || a["status"] != float64(503) || a["reason"] != "webhook rejected the request" {
		t.Fatalf("rejected test = %v", a)
	}
	var sent authentication.Message
	if len(bodies) != 1 || json.Unmarshal([]byte(bodies[0]), &sent) != nil || sent.Purpose != "test" || bodies[0] != `{"email":"ops@example.com","purpose":"test"}` {
		t.Fatalf("webhook body = %v", bodies)
	}
	if len(signatures) != 1 || !strings.HasPrefix(signatures[0], "v1,") {
		t.Fatalf("webhook signature = %v", signatures)
	}
	mu.Lock()
	code = 204
	mu.Unlock()
	e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200)
	s = status()
	last, failure := s["last_attempt"].(map[string]any), s["last_failure"].(map[string]any)
	if last["delivered"] != true || last["source"] != "environment" || failure["status"] != float64(503) || failure["purpose"] != "test" {
		t.Fatalf("activity = %v", s)
	}
	if raw := e.Must("GET", e.Base+"/delivery/status", e.Owner, nil, 200).Body; strings.Contains(raw, "secret") || strings.Contains(raw, hook.URL) {
		t.Fatalf("status leaks: %s", raw)
	}

	// Unreachable webhook.
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": "http://127.0.0.1:1/hook", "webhook_token": "t"}, 204)
	a = e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != false || a["status"] != nil || a["reason"] != "webhook could not be reached" {
		t.Fatalf("unreachable test = %v", a)
	}

	// Rate limit: five test sends per minute per environment and client.
	e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 429)
	if n := e.audited("delivery.test", "environment"); n != 3 {
		t.Fatalf("audited environment tests = %d", n)
	}

	// Viewers read status but cannot send tests or change the webhook.
	viewer := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201).JSON["secret"].(string)
	e.Must("GET", e.Base+"/delivery/status", viewer, nil, 200)
	e.Must("POST", e.Base+"/delivery/test", viewer, fiber.Map{"email": "ops@example.com"}, 403)
	e.Must("PUT", e.Base+"/delivery", viewer, fiber.Map{"webhook_url": "https://evil.example/hook", "webhook_token": "t"}, 403)
	e.Must("DELETE", e.Base+"/delivery", viewer, nil, 403)
	e.Must("GET", "/management/v1/environments/00000000-0000-4000-8000-000000000000/delivery/status", e.Owner, nil, 404)

	// Configuration changes are audited without the URL or token; a failed
	// or refused change is not.
	target := "/environments/" + e.EnvID + "/delivery"
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": "ftp://bad", "webhook_token": "t"}, 400)
	if n := e.audited("delivery.update", target); n != 2 {
		t.Fatalf("audited updates = %d", n)
	}
	e.Must("DELETE", e.Base+"/delivery", e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/delivery", e.Owner, nil, 404)
	if n := e.audited("delivery.delete", target); n != 1 {
		t.Fatalf("audited deletes = %d", n)
	}
	var actor string
	if err := e.DB.Get(&actor, `SELECT a.actor_id::text FROM audit_events a WHERE a.environment_id=$1 AND a.action='delivery.delete'`, e.EnvID); err != nil || actor == "" {
		t.Fatalf("delete actor = %q %v", actor, err)
	}
	var leaked int
	if err := e.DB.Get(&leaked, `SELECT count(*) FROM audit_events WHERE action LIKE 'delivery.%' AND (target_id LIKE '%127.0.0.1%' OR target_id LIKE '%hook%')`); err != nil || leaked != 0 {
		t.Fatalf("audit leaks webhook: %d %v", leaked, err)
	}
}
