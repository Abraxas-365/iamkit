package e2e_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// metadataHost serves Client ID Metadata Documents and key sets by URL
// through the harness's CIMD transport, counting reads.
type metadataHost struct {
	mu    sync.Mutex
	docs  map[string]any
	reads map[string]int
}

func (e *Env) metadataHost() *metadataHost {
	h := &metadataHost{docs: map[string]any{}, reads: map[string]int{}}
	e.CIMD.Set(h)
	return h
}

func (h *metadataHost) Put(location string, doc any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.docs[location] = doc
}

func (h *metadataHost) Reads(location string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads[location]
}

func (h *metadataHost) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reads[r.URL.String()]++
	doc, ok := h.docs[r.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}
	body, _ := json.Marshal(doc)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"max-age=3600"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

const (
	claudeCodeID = "https://claude.ai/oauth/claude-code-client-metadata"
	chatGPTID    = "https://chatgpt.com/oauth/client.json"
	chatGPTJWKS  = "https://chatgpt.com/oauth/jwks.json"
)

// TestExternalClients is MCP authorization phase (b) end to end: a client
// named by its Client ID Metadata Document URL authorizes at a protected
// resource (public with PKCE on a loopback port, or private_key_jwt with a
// jwks_uri on its origin), refreshes and revokes; admission, blocking, the
// feature flag and a server that takes registered clients only refuse it.
func TestExternalClients(t *testing.T) {
	e := newEnv(t)
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()

	if d := e.Must("GET", "/.well-known/oauth-authorization-server", "", nil, 200).JSON; d["client_id_metadata_document_supported"] != true || d["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("discovery: %v", d)
	}

	// Claude Code: public, loopback redirect on whatever port it listens.
	host.Put(claudeCodeID, map[string]any{"client_id": claudeCodeID, "client_name": "Claude Code", "redirect_uris": []string{"http://localhost/callback", "http://127.0.0.1/callback"}, "grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"})
	redirect := "http://localhost:53682/callback"
	authorize := func(client string, extra url.Values) string {
		q := url.Values{"redirect_uri": {redirect}}
		for k, v := range extra {
			q[k] = v
		}
		return resourceAuthorize(client, q)
	}

	// A resource is required: without it nothing names the server.
	if p := e.browser().get(authorize(claudeCodeID, url.Values{"resource": nil})); p.Status != 400 || p.Location != "" {
		t.Fatalf("no resource: %d %q", p.Status, p.Location)
	}
	// Not on the allowlist: discovered as pending, and the sign-in ends on
	// a page, never at the client with a code.
	b := e.browser()
	start := b.get(authorize(claudeCodeID, nil))
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
		t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
	}
	var admission, rowID string
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE external_id=$1 AND protected_resource_id=$2`, claudeCodeID, protected)
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	if admission != "pending" {
		t.Fatalf("admission = %q", admission)
	}
	tk := b.get(start.Location).field("ticket")
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if done.Status != 403 || done.Location != "" {
		t.Fatalf("pending client: %d %q %s", done.Status, done.Location, done.Body)
	}
	var discovered int
	e.DB.Get(&discovered, `SELECT count(*) FROM events WHERE type='oauth_client.discovered' AND subject_id=$1`, rowID)
	if discovered != 1 {
		t.Fatalf("discovered events = %d", discovered)
	}

	// Approved: the full flow, client_id = the URL throughout.
	e.DB.MustExec(`UPDATE oauth_clients SET admission='approved' WHERE id=$1`, rowID)
	b = e.browser()
	code := b.signInTo(b.get(authorize(claudeCodeID, nil)), redirect)
	form := codeForm(claudeCodeID, code)
	form.Set("redirect_uri", redirect)
	status, tokens, _ := e.tokenCall(form, "")
	if status != 200 || tokens["refresh_token"] == nil {
		t.Fatalf("code exchange: %d %v", status, tokens)
	}
	c := claims(t, tokens["access_token"].(string))
	if !equal(strs(c["aud"]), []string{mcpURI}) || c["oauth_client_id"] != rowID {
		t.Fatalf("claims: %v", c)
	}
	status, refreshed, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), "")
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	// The document is cached: one read for all of the above.
	if n := host.Reads(claudeCodeID); n != 1 {
		t.Fatalf("document reads = %d", n)
	}
	// Grants a URL client may never use.
	for _, grant := range []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:device_code"} {
		if status, out, _ := e.tokenCall(url.Values{"grant_type": {grant}, "client_id": {claudeCodeID}}, ""); status != 400 || out["error"] != "unauthorized_client" {
			t.Errorf("%s: %d %v", grant, status, out)
		}
	}
	// Another URL cannot use this client's refresh token.
	if status, _, _ := e.tokenCall(refreshForm("https://claude.ai/oauth/other", refreshed["refresh_token"].(string)), ""); status != 401 {
		t.Fatalf("foreign client_id refresh: %d", status)
	}
	// Revocation by client_id URL; the refresh token is gone.
	rev := httpForm(t, e, "/oauth/revoke", url.Values{"client_id": {claudeCodeID}, "token": {refreshed["refresh_token"].(string)}})
	if rev != 200 {
		t.Fatalf("revoke: %d", rev)
	}
	if status, _, _ := e.tokenCall(refreshForm(claudeCodeID, refreshed["refresh_token"].(string)), ""); status != 400 {
		t.Fatalf("refresh after revoke: %d", status)
	}
	// Another loopback host never matches (D14), nor an unlisted path.
	for _, bad := range []string{"http://127.0.0.2:4000/callback", "http://localhost:53682/other", "https://evil.example/callback"} {
		if p := e.browser().get(authorize(claudeCodeID, url.Values{"redirect_uri": {bad}})); p.Status != 400 || p.Location != "" {
			t.Errorf("redirect %s: %d %q", bad, p.Status, p.Location)
		}
	}

	// Blocked: a page at authorize, invalid_grant at refresh.
	b = e.browser()
	code = b.signInTo(b.get(authorize(claudeCodeID, nil)), redirect)
	form = codeForm(claudeCodeID, code)
	form.Set("redirect_uri", redirect)
	_, live, _ := e.tokenCall(form, "")
	e.DB.MustExec(`UPDATE oauth_clients SET admission='blocked' WHERE id=$1`, rowID)
	if p := e.browser().get(authorize(claudeCodeID, nil)); p.Status != 403 || p.Location != "" {
		t.Fatalf("blocked authorize: %d %q", p.Status, p.Location)
	}
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, live["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("blocked refresh: %d %v", status, out)
	}

	// Invalid documents are pages, never redirects.
	host.Put("https://claude.ai/oauth/mismatch", map[string]any{"client_id": "https://claude.ai/oauth/else", "redirect_uris": []string{"http://localhost/callback"}})
	host.Put("https://claude.ai/oauth/secret", map[string]any{"client_id": "https://claude.ai/oauth/secret", "redirect_uris": []string{"http://localhost/callback"}, "client_secret": "x"})
	for _, id := range []string{"https://claude.ai/oauth/mismatch", "https://claude.ai/oauth/secret", "https://claude.ai/oauth/missing", "https://claude.ai/oauth/x?y=1"} {
		if p := e.browser().get(authorize(id, nil)); p.Status != 400 || p.Location != "" {
			t.Errorf("%s: %d %q", id, p.Status, p.Location)
		}
	}

	// ChatGPT: private_key_jwt with a jwks_uri on its origin; an
	// allowlisted URL is approved on discovery.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	host.Put(chatGPTID, map[string]any{"client_id": chatGPTID, "client_name": "ChatGPT", "redirect_uris": []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "RS256", "jwks_uri": chatGPTJWKS})
	host.Put(chatGPTJWKS, map[string]any{"keys": []any{rsaJWK(key, "k1")}})
	e.DB.MustExec(`INSERT INTO oauth_client_allowlist(id,environment_id,origin,path_prefix) VALUES(gen_random_uuid(),$1,'https://chatgpt.com','/oauth/client.json')`, e.EnvID)
	redirect = "https://chatgpt.com/connector_platform_oauth_redirect"
	b = e.browser()
	code = b.signInTo(b.get(authorize(chatGPTID, nil)), redirect)
	signed := func() string {
		return assertion(t, jwt.SigningMethodRS256, key, "k1", chatGPTID, testIssuer+"/oauth/token", uuid.NewString())
	}
	form = codeForm(chatGPTID, code)
	form.Set("redirect_uri", redirect)
	form.Set("client_assertion_type", assertionType)
	form.Set("client_assertion", signed())
	status, tokens, _ = e.tokenCall(form, "")
	if status != 200 {
		t.Fatalf("private_key_jwt exchange: %d %v", status, tokens)
	}
	// The same assertion is spent.
	replay := refreshForm(chatGPTID, tokens["refresh_token"].(string))
	replay.Set("client_assertion_type", assertionType)
	replay.Set("client_assertion", form.Get("client_assertion"))
	if status, out, _ := e.tokenCall(replay, ""); status != 400 || out["error"] != "jti_known" {
		t.Fatalf("replayed assertion: %d %v", status, out)
	}
	// No assertion: a confidential client cannot refresh.
	if status, _, _ := e.tokenCall(refreshForm(chatGPTID, tokens["refresh_token"].(string)), ""); status != 401 {
		t.Fatalf("refresh without assertion: %d", status)
	}

	// The feature flag and the server's switch refuse URL clients.
	e.Must("PUT", e.Base+"/features/client_metadata_documents", e.Owner, fiber.Map{"enabled": false}, 200)
	if p := e.browser().get(authorize(chatGPTID, nil)); p.Status != 403 {
		t.Fatalf("feature off: %d %q", p.Status, p.Location)
	}
	e.Must("PUT", e.Base+"/features/client_metadata_documents", e.Owner, fiber.Map{"enabled": true}, 200)
	e.DB.MustExec(`UPDATE protected_resources SET allow_client_metadata=false WHERE id=$1`, protected)
	if p := e.browser().get(authorize(chatGPTID, nil)); p.Status != 403 {
		t.Fatalf("registered clients only: %d %q", p.Status, p.Location)
	}
}

// signInTo runs the hosted sign-in and returns the code sent to redirect.
func (b *browser) signInTo(start page, redirect string) string {
	b.t.Helper()
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
		b.t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
	}
	tk := b.get(start.Location).field("ticket")
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {b.e.AliceEmail}, "password": {b.e.Pass}})
	loc, err := url.Parse(done.Location)
	if done.Status != 303 || err != nil || !strings.HasPrefix(done.Location, redirect+"?") || loc.Query().Get("code") == "" || loc.Query().Get("iss") != testIssuer {
		b.t.Fatalf("finish: %d %q %s", done.Status, done.Location, done.Body)
	}
	return loc.Query().Get("code")
}

// httpForm posts form to path and returns the status.
func httpForm(t *testing.T, e *Env, path string, form url.Values) int {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// TestExternalClientConstraint holds D16 + D18 in the database: an
// oauth_clients row of source cimd is a public client or a private_key_jwt
// client with a jwks_uri on its client_id's origin, uses the code flow and
// refreshes only, and never carries a secret, inline keys or the delegated
// grants. Each clause is broken once on top of a row that passes.
func TestExternalClientConstraint(t *testing.T) {
	e := newEnv(t)
	_, protected, resource := e.mcpServer(fiber.Map{})

	insert := func(overrides map[string]string) error {
		cols := map[string]string{
			"source":                     "'cimd'",
			"external_id":                "'https://claude.ai/oauth/claude-code-client-metadata'",
			"protected_resource_id":      "'" + protected + "'",
			"token_endpoint_auth_method": "'none'",
			"public":                     "true",
			"jwks_uri":                   "''",
			"grant_types":                "'{authorization_code,refresh_token}'",
			"hosted_login":               "true",
		}
		for k, v := range overrides {
			cols[k] = v
		}
		names, values := []string{"id", "environment_id", "application_id", "resource_id", "redirect_uris"}, []string{"gen_random_uuid()", "$1", "$2", "$3", "'{http://localhost/callback}'"}
		for k, v := range cols {
			names, values = append(names, k), append(values, v)
		}
		tx, err := e.DB.Beginx()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		_, err = tx.Exec(`INSERT INTO oauth_clients (`+strings.Join(names, ",")+`) VALUES (`+strings.Join(values, ",")+`)`, e.EnvID, e.Client, resource)
		return err
	}

	// The two shapes the constraint admits (Claude Code, ChatGPT).
	if err := insert(nil); err != nil {
		t.Fatalf("public cimd client refused: %v", err)
	}
	chatgpt := map[string]string{"external_id": "'https://chatgpt.com/oauth/client.json'", "token_endpoint_auth_method": "'private_key_jwt'", "public": "false", "jwks_uri": "'https://chatgpt.com/oauth/jwks.json'"}
	if err := insert(chatgpt); err != nil {
		t.Fatalf("private_key_jwt cimd client refused: %v", err)
	}
	with := func(base map[string]string, k, v string) map[string]string {
		out := map[string]string{k: v}
		for bk, bv := range base {
			if bk != k {
				out[bk] = bv
			}
		}
		return out
	}

	for name, overrides := range map[string]map[string]string{
		"client_credentials":        {"grant_types": "'{authorization_code,client_credentials}'"},
		"token exchange":            {"grant_types": "'{authorization_code,urn:ietf:params:oauth:grant-type:token-exchange}'"},
		"jwt-bearer":                {"grant_types": "'{authorization_code,urn:ietf:params:oauth:grant-type:jwt-bearer}'"},
		"device code":               {"grant_types": "'{authorization_code,urn:ietf:params:oauth:grant-type:device_code}'"},
		"no authorization_code":     {"grant_types": "'{refresh_token}'"},
		"secret method":             {"token_endpoint_auth_method": "'client_secret_basic'", "public": "false"},
		"secret hash":               {"secret_hash": `'\x01'`},
		"confidential none":         {"public": "false"},
		"public private_key_jwt":    with(chatgpt, "public", "true"),
		"jwks_uri other origin":     with(chatgpt, "jwks_uri", "'https://keys.example/jwks.json'"),
		"jwks_uri subdomain":        with(chatgpt, "jwks_uri", "'https://cdn.chatgpt.com/jwks.json'"),
		"jwks_uri origin prefix":    with(chatgpt, "jwks_uri", "'https://chatgpt.com.evil.example/jwks.json'"),
		"jwks_uri missing":          with(chatgpt, "jwks_uri", "''"),
		"inline jwks":               with(chatgpt, "jwks", `'{"keys":[]}'`),
		"none with jwks_uri":        {"jwks_uri": "'https://claude.ai/jwks.json'"},
		"no external_id":            {"external_id": "NULL"},
		"no protected resource":     {"protected_resource_id": "NULL"},
		"http external_id":          {"external_id": "'http://claude.ai/x'"},
		"external_id with query":    {"external_id": "'https://claude.ai/x?y=1'"},
		"not hosted":                {"hosted_login": "false"},
		"system client":             {"system": "'org_admin'"},
		"allowed origins":           {"allowed_origins": "'{https://claude.ai}'"},
		"backchannel logout":        {"backchannel_logout_uri": "'https://claude.ai/logout'"},
		"initiate login":            {"initiate_login_uri": "'https://claude.ai/login'"},
		"registered with url":       {"source": "'registered'"},
		"registered pending":        {"source": "'registered'", "external_id": "NULL", "protected_resource_id": "NULL", "admission": "'pending'"},
		"unknown source":            {"source": "'dcr'"},
		"unknown admission":         {"admission": "'maybe'"},
		"preset on external client": {"preset": "'claude_code'"},
	} {
		if err := insert(overrides); err == nil || !strings.Contains(err.Error(), "violates check constraint") {
			t.Errorf("%s: %v", name, err)
		}
	}

	// One row per (protected resource, document URL).
	tx, _ := e.DB.Beginx()
	defer tx.Rollback()
	q := `INSERT INTO oauth_clients (id, environment_id, application_id, resource_id, redirect_uris, public, token_endpoint_auth_method, hosted_login, source, external_id, protected_resource_id) VALUES (gen_random_uuid(), $1, $2, $3, '{http://localhost/callback}', true, 'none', true, 'cimd', 'https://claude.ai/oauth/x', $4)`
	if _, err := tx.Exec(q, e.EnvID, e.Client, resource, protected); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(q, e.EnvID, e.Client, resource, protected); err == nil || !strings.Contains(err.Error(), "oauth_clients_external_key") {
		t.Fatalf("duplicate external client: %v", err)
	}
}
