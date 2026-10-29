package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestProtectedResourceClients(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"items":[{"id":"c1","host":"claude.ai","admission":"pending","preset_name":"Claude Code"}],"page":{"total":1}}`),
		"protected-resources", "clients", "list", "p1", "--admission", "pending")
	if err != nil || !strings.Contains(out, "claude.ai") || seen[0].Path != base+"/protected-resources/p1/clients" || seen[0].Query != "admission=pending" {
		t.Fatalf("list: %v %s %+v", err, out, seen)
	}
	// Approving names the document reviewed: the hash given, or the one the
	// client has now (read first).
	_, _, seen, err = runCLI(t, ok(200, `{"id":"c1"}`), "protected-resources", "clients", "approve", "p1", "c1", "--expires", "2027-01-31", "--metadata-hash", "h1")
	if err != nil || len(seen) != 1 || seen[0].Path != base+"/protected-resources/p1/clients/c1/approve" ||
		!reflect.DeepEqual(seen[0].Body, map[string]any{"expires_at": "2027-01-31T23:59:59Z", "metadata_hash": "h1"}) {
		t.Fatalf("approve: %v %+v", err, seen)
	}
	_, stderr, seen, err := runCLI(t, func(r seenRequest) (int, string) {
		if r.Method == "GET" {
			return 200, `{"id":"c1","client_id":"https://claude.ai/x","host":"claude.ai","redirect_uris":["http://localhost/cb"],"token_endpoint_auth_method":"none","metadata_hash":"h2"}`
		}
		return 200, `{"id":"c1"}`
	}, "protected-resources", "clients", "approve", "p1", "c1")
	if err != nil || len(seen) != 2 || seen[0].Method != "GET" || !reflect.DeepEqual(seen[1].Body, map[string]any{"metadata_hash": "h2"}) || !strings.Contains(stderr, "http://localhost/cb") || !strings.Contains(stderr, "h2") {
		t.Fatalf("approve without a hash: %v %q %+v", err, stderr, seen)
	}
	out, _, seen, err = runCLI(t, ok(200, `{"active_sessions":4,"users":3}`), "protected-resources", "clients", "impact", "p1", "c1")
	if err != nil || seen[0].Method != "GET" || seen[0].Path != base+"/protected-resources/p1/clients/c1/impact" || !strings.Contains(out, "4") {
		t.Fatalf("impact: %v %s %+v", err, out, seen)
	}
	for _, verb := range []string{"block", "unblock"} {
		_, _, seen, err = runCLI(t, ok(200, `{"id":"c1"}`), "protected-resources", "clients", verb, "p1", "c1")
		if err != nil || seen[0].Method != "POST" || seen[0].Path != base+"/protected-resources/p1/clients/c1/"+verb {
			t.Fatalf("%s: %v %+v", verb, err, seen)
		}
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "protected-resources", "clients", "forget", "p1", "c1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/protected-resources/p1/clients/c1" {
		t.Fatalf("forget: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(201, `{"preset":"cursor","client":{"client_id":"x"}}`), "protected-resources", "clients", "from-template", "p1", "cursor")
	if err != nil || seen[0].Path != base+"/protected-resources/p1/client-templates" || !reflect.DeepEqual(seen[0].Body, map[string]any{"preset": "cursor"}) {
		t.Fatalf("template: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{}`), "protected-resources", "clients", "approve", "p1", "c1", "--expires", "soon", "--metadata-hash", "h")
	if err == nil || len(seen) != 0 {
		t.Fatalf("bad expiry accepted: %v %+v", err, seen)
	}
}

func TestProtectedResourceUpdateAndImpact(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"id":"p1"}`), "protected-resources", "update", "p1", "--allow-client-metadata", "--allow-dynamic-registration=false", "--client-admission", "open")
	if err != nil || seen[0].Method != "PATCH" || !reflect.DeepEqual(seen[0].Body, map[string]any{"allow_client_metadata": true, "allow_dynamic_registration": false, "client_admission": "open"}) {
		t.Fatalf("update: %v %+v", err, seen)
	}
	for _, args := range [][]string{{"protected-resources", "update", "p1"}, {"protected-resources", "update", "p1", "--client-admission", "maybe"}} {
		if _, _, seen, err = runCLI(t, ok(200, `{}`), args...); err == nil || len(seen) != 0 {
			t.Fatalf("%v: %v %+v", args, err, seen)
		}
	}
	out, _, seen, err := runCLI(t, ok(200, `{"active_sessions":3,"external_clients":2}`), "protected-resources", "impact", "p1")
	if err != nil || seen[0].Path != base+"/protected-resources/p1/impact" || !strings.Contains(out, "external_clients") {
		t.Fatalf("impact: %v %s %+v", err, out, seen)
	}
}

func TestClientAllowlistAndPresets(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(201, `{"id":"e1"}`), "client-allowlist", "add", "--origin", "https://tools.example", "--path-prefix", "/oauth/")
	if err != nil || seen[0].Path != base+"/oauth-client-allowlist" ||
		!reflect.DeepEqual(seen[0].Body, map[string]any{"origin": "https://tools.example", "path_prefix": "/oauth/"}) {
		t.Fatalf("add: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(201, `{"id":"e1"}`), "client-allowlist", "add", "--preset", "claude_code", "--resource", "p1")
	if err != nil || !reflect.DeepEqual(seen[0].Body, map[string]any{"preset": "claude_code", "protected_resource_id": "p1"}) {
		t.Fatalf("add preset: %v %+v", err, seen)
	}
	if _, _, seen, err = runCLI(t, ok(200, `{}`), "client-allowlist", "add", "--preset", "x", "--origin", "https://a.example"); err == nil || len(seen) != 0 {
		t.Fatalf("mixed accepted: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"items":[]}`), "client-allowlist", "list", "--resource", "p1")
	if err != nil || seen[0].Query != "protected_resource_id=p1" {
		t.Fatalf("list: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "client-allowlist", "remove", "e1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/oauth-client-allowlist/e1" {
		t.Fatalf("remove: %v %+v", err, seen)
	}
	out, _, _, err := runCLI(t, ok(200, `{"items":[{"key":"claude","name":"Claude","mechanism":"metadata_document","network":"public"}]}`), "client-presets", "list")
	if err != nil || !strings.Contains(out, "metadata_document") {
		t.Fatalf("presets: %v %s", err, out)
	}
	_, _, seen, err = runCLI(t, ok(201, `{"preset":"cursor"}`), "client-presets", "apply", "cursor", "--resource", "p1")
	if err != nil || seen[0].Path != base+"/oauth-client-presets" || !reflect.DeepEqual(seen[0].Body, map[string]any{"preset": "cursor", "protected_resource_id": "p1"}) {
		t.Fatalf("apply: %v %+v", err, seen)
	}
}

func TestProtectedResourceConsent(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"id":"p1"}`), "protected-resources", "update", "p1", "--consent-mode", "admin_granted", "--access-token-ttl-seconds", "900")
	if err != nil || seen[0].Method != "PATCH" || !reflect.DeepEqual(seen[0].Body, map[string]any{"consent_mode": "admin_granted", "access_token_ttl_seconds": float64(900)}) {
		t.Fatalf("update: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(201, `{"id":"p1"}`), "protected-resources", "create", "--application", "a1", "--resource", "r1", "--name", "Notes", "--consent-mode", "per_user", "--access-token-ttl-seconds", "600")
	if err != nil || seen[0].Body["consent_mode"] != "per_user" || seen[0].Body["access_token_ttl_seconds"] != float64(600) {
		t.Fatalf("create: %v %+v", err, seen)
	}
	if _, _, seen, err = runCLI(t, ok(200, `{}`), "protected-resources", "update", "p1", "--consent-mode", "maybe"); err == nil || len(seen) != 0 {
		t.Fatalf("bad consent mode accepted: %v %+v", err, seen)
	}

	_, _, seen, err = runCLI(t, ok(200, `{"max_idle_ttl_seconds":600,"max_lifetime_ttl_seconds":7200,"consent_ui":"custom"}`),
		"protected-resources", "policy", "set", "--max-idle-ttl-seconds", "600", "--max-lifetime-ttl-seconds", "7200", "--consent-ui", "custom")
	if err != nil || seen[0].Method != "PUT" || seen[0].Path != base+"/protected-resource-policy" ||
		!reflect.DeepEqual(seen[0].Body, map[string]any{"max_idle_ttl_seconds": float64(600), "max_lifetime_ttl_seconds": float64(7200), "consent_ui": "custom"}) {
		t.Fatalf("policy set: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{}`), "protected-resources", "policy", "set", "--max-idle-ttl-seconds", "600", "--max-lifetime-ttl-seconds", "7200")
	if err != nil || len(seen[0].Body) != 2 {
		t.Fatalf("policy set without consent-ui: %v %+v", err, seen)
	}
	if _, _, seen, err = runCLI(t, ok(200, `{}`), "protected-resources", "policy", "set", "--max-idle-ttl-seconds", "600", "--max-lifetime-ttl-seconds", "7200", "--consent-ui", "x"); err == nil || len(seen) != 0 {
		t.Fatalf("bad consent ui accepted: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"consent_ui":"hosted"}`), "protected-resources", "policy", "get")
	if err != nil || seen[0].Method != "GET" || seen[0].Path != base+"/protected-resource-policy" {
		t.Fatalf("policy get: %v %+v", err, seen)
	}
}

func TestProtectedResourceClientGrants(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"items":[{"id":"g1","scopes":["notes:read"],"organization_id":"o1"}]}`), "protected-resources", "clients", "grants", "list", "p1", "c1", "--revoked")
	if err != nil || !strings.Contains(out, "g1") || seen[0].Method != "GET" || seen[0].Path != base+"/protected-resources/p1/clients/c1/grants" || seen[0].Query != "revoked=true" {
		t.Fatalf("list: %v %s %+v", err, out, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"id":"g1"}`), "protected-resources", "clients", "grants", "set", "p1", "c1", "--scopes", "notes:read,notes:write", "--organization", "o1", "--expires", "2027-01-31")
	if err != nil || seen[0].Method != "PUT" || seen[0].Path != base+"/protected-resources/p1/clients/c1/grants" ||
		!reflect.DeepEqual(seen[0].Body, map[string]any{"scopes": []any{"notes:read", "notes:write"}, "organization_id": "o1", "expires_at": "2027-01-31T23:59:59Z"}) {
		t.Fatalf("set: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "protected-resources", "clients", "grants", "revoke", "p1", "c1", "g1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/protected-resources/p1/clients/c1/grants/g1" {
		t.Fatalf("revoke: %v %+v", err, seen)
	}
	if _, _, seen, err = runCLI(t, ok(200, `{}`), "protected-resources", "clients", "grants", "set", "p1", "c1"); err == nil || len(seen) != 0 {
		t.Fatalf("set without scopes: %v %+v", err, seen)
	}
	if _, _, seen, err = runCLI(t, ok(200, `{}`), "protected-resources", "clients", "grants", "set", "p1", "c1", "--scopes", "a", "--expires", "soon"); err == nil || len(seen) != 0 {
		t.Fatalf("bad expiry accepted: %v %+v", err, seen)
	}
}

func TestUserConnectedApps(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"items":[{"client":{"id":"c1","host":"claude.ai","name":"Claude"},"resource_name":"Notes","organization_id":"o1","scopes":["notes:read"],"active_sessions":2}]}`),
		"users", "connected-apps", "list", "u1", "--organization", "o1")
	if err != nil || !strings.Contains(out, "claude.ai") || seen[0].Method != "GET" || seen[0].Path != base+"/users/u1/connected-apps" || seen[0].Query != "organization_id=o1" {
		t.Fatalf("list: %v %s %+v", err, out, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "users", "connected-apps", "disconnect", "u1", "c1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/users/u1/connected-apps/c1" || seen[0].Query != "" {
		t.Fatalf("disconnect: %v %+v", err, seen)
	}
}

func TestOAuthClientConsentPolicy(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{}`), "oauth-clients", "update", "c1", "--consent-policy", "required")
	if err != nil || seen[0].Method != "PATCH" || !reflect.DeepEqual(seen[0].Body, map[string]any{"consent_policy": "required"}) {
		t.Fatalf("update: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(201, `{"id":"c1"}`), "oauth-clients", "create", "--app", "a1", "--resource", "r1", "--consent-policy", "skip")
	if err != nil || seen[0].Body["consent_policy"] != "skip" {
		t.Fatalf("create: %v %+v", err, seen)
	}
	if _, _, seen, err = runCLI(t, ok(200, `{}`), "oauth-clients", "update", "c1", "--consent-policy", "never"); err == nil || len(seen) != 0 {
		t.Fatalf("bad policy accepted: %v %+v", err, seen)
	}
}
