package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// TestBackchannelLogout: a client with a backchannel_logout_uri receives a
// signed logout token when a session it was authorized for ends; failed
// deliveries are retried, given up (audited) and retried by operators.
func TestBackchannelLogout(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	httpClient := &http.Client{Transport: appTransport{e.App}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	var mu sync.Mutex
	var received []string
	status := 200
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, r.PostFormValue("logout_token"))
		w.WriteHeader(status)
	}))
	defer rp.Close()
	e.IdP.Set(rp.Client().Transport)
	setStatus := func(code int) { mu.Lock(); status = code; mu.Unlock() }
	tokens := func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), received...) }
	dispatch := func() {
		t.Helper()
		if _, err := e.Server.LogoutDispatcher.DispatchLogouts(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	bc := rp.URL + "/backchannel"
	e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "backchannel_logout_uri": "http://rp.example/bc"}, 400)
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "backchannel_logout_uri": bc, "backchannel_logout_session_required": true}, 201).JSON
	clientID, secret := registered["client_id"].(string), registered["client_secret"].(string)
	view := e.Must("GET", e.Base+"/oauth-clients/"+clientID, e.Owner, nil, 200).JSON
	if view["backchannel_logout_uri"] != bc || view["backchannel_logout_session_required"] != true {
		t.Fatalf("client view = %v", view)
	}
	e.Must("PATCH", e.Base+"/oauth-clients/"+clientID, e.Owner, fiber.Map{"backchannel_logout_uri": "https://u:p@rp.example/"}, 400)

	provider, err := oidc.NewProvider(ctx, "https://iam.example")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	provider.Claims(&meta)
	if meta["backchannel_logout_supported"] != true || meta["backchannel_logout_session_supported"] != true {
		t.Fatalf("discovery = %v", meta)
	}
	config := oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: "https://app.example/callback", Scopes: []string{oidc.ScopeOpenID}}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	signIn := func() (sid string, idToken string) {
		t.Helper()
		pkce := oauth2.GenerateVerifier()
		res, err := httpClient.Get(config.AuthCodeURL("unpredictable-state-123456", oauth2.S256ChallengeOption(pkce), oidc.Nonce("unpredictable-nonce-123456")))
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("authorize: %v %v", err, res)
		}
		var begin map[string]any
		json.NewDecoder(res.Body).Decode(&begin)
		res.Body.Close()
		body, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
		req, _ := http.NewRequest("POST", "https://iam.example/oauth/authorize/complete", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+e.Login(e.AliceEmail))
		req.AddCookie(res.Cookies()[0])
		done, err := httpClient.Do(req)
		if err != nil || done.StatusCode != 303 {
			t.Fatalf("complete: %v %v", err, done)
		}
		location, _ := url.Parse(done.Header.Get("Location"))
		token, err := config.Exchange(ctx, location.Query().Get("code"), oauth2.VerifierOption(pkce))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := token.Extra("id_token").(string)
		idt, err := verifier.Verify(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			SID string `json:"sid"`
		}
		idt.Claims(&claims)
		return claims.SID, raw
	}

	// The /identity/v1/login sessions signIn creates are not bound to the
	// client: only OAuth sessions queue notifications.
	sid, hint := signIn()
	dispatch()
	if got := tokens(); len(got) != 0 {
		t.Fatalf("notified before logout: %d", len(got))
	}
	res, err := httpClient.Get("https://iam.example/oauth/end_session?" + url.Values{"id_token_hint": {hint}}.Encode())
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("end_session: %v %v", err, res)
	}
	dispatch()
	got := tokens()
	if len(got) != 1 {
		t.Fatalf("logout tokens = %d", len(got))
	}
	logout, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, got[0])
	if err != nil {
		t.Fatalf("logout token: %v", err)
	}
	var claims map[string]any
	logout.Claims(&claims)
	events, _ := claims["events"].(map[string]any)
	if claims["sid"] != sid || claims["sub"] != e.Alice || claims["jti"] == nil || claims["nonce"] != nil || events["http://schemas.openid.net/event/backchannel-logout"] == nil {
		t.Fatalf("logout claims = %v", claims)
	}
	list := e.Must("GET", e.Base+"/logout-deliveries?status=delivered", e.Owner, nil, 200).JSON
	items, _ := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["session_id"] != sid || items[0].(map[string]any)["user_email"] != e.AliceEmail {
		t.Fatalf("delivered list = %v", list)
	}
	dispatch()
	if len(tokens()) != 1 {
		t.Fatal("a delivered notification was sent twice")
	}

	// Operator revocation notifies too; a failing RP is retried, then given up.
	setStatus(500)
	sid, _ = signIn()
	e.Must("DELETE", e.Base+"/sessions/"+sid, e.Owner, nil, 204)
	dispatch()
	pending := e.Must("GET", e.Base+"/logout-deliveries?status=pending", e.Owner, nil, 200).JSON["items"].([]any)
	if len(pending) != 1 || pending[0].(map[string]any)["attempts"] != float64(1) || !strings.Contains(pending[0].(map[string]any)["last_error"].(string), "500") {
		t.Fatalf("pending = %v", pending)
	}
	dispatch() // not due yet
	if len(tokens()) != 2 {
		t.Fatalf("retried before its backoff: %d", len(tokens()))
	}
	e.DB.MustExec(`UPDATE logout_notifications SET attempts=7, next_attempt_at=now() WHERE session_id=$1`, sid)
	dispatch()
	failed := e.Must("GET", e.Base+"/logout-deliveries?status=failed", e.Owner, nil, 200).JSON["items"].([]any)
	if len(failed) != 1 {
		t.Fatalf("failed = %v", failed)
	}
	var audits int
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action='oauth.backchannel_failed' AND target_id=$2 AND actor_id=$3`, e.EnvID, clientID, e.Alice)
	if audits != 1 {
		t.Fatalf("backchannel_failed audits = %d", audits)
	}
	id := failed[0].(map[string]any)["id"].(string)
	e.Must("POST", e.Base+"/logout-deliveries/"+id+"/retry", e.Owner, nil, 202)
	e.Must("POST", e.Base+"/logout-deliveries/"+id+"/retry", e.Owner, nil, 404)
	e.Must("POST", e.Base+"/logout-deliveries/abc/retry", e.Owner, nil, 404)
	setStatus(204)
	dispatch()
	if len(tokens()) != 4 || len(e.Must("GET", e.Base+"/logout-deliveries?status=delivered", e.Owner, nil, 200).JSON["items"].([]any)) != 2 {
		t.Fatalf("manual retry not delivered: %d", len(tokens()))
	}
	e.Must("GET", e.Base+"/logout-deliveries?status=sent", e.Owner, nil, 400)

	// Clearing the URI stops notifications.
	e.Must("PATCH", e.Base+"/oauth-clients/"+clientID, e.Owner, fiber.Map{"backchannel_logout_uri": ""}, 204)
	sid, _ = signIn()
	e.Must("DELETE", e.Base+"/sessions/"+sid, e.Owner, nil, 204)
	var queued int
	e.DB.Get(&queued, `SELECT count(*) FROM logout_notifications WHERE session_id=$1`, sid)
	if queued != 0 {
		t.Fatalf("queued without a URI: %d", queued)
	}

	// Another environment cannot see the deliveries.
	other := e.ID("POST", "/management/v1/projects/"+e.ID("POST", "/management/v1/projects", fiber.Map{"name": "Other"})+"/environments", fiber.Map{"name": "staging"})
	if n := e.Must("GET", "/management/v1/environments/"+other+"/logout-deliveries", e.Owner, nil, 200).JSON["page"].(map[string]any)["total"]; n != float64(0) {
		t.Fatalf("cross-environment deliveries = %v", n)
	}
}
