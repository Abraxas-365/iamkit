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
	_, _, seen, err := runCLI(t, ok(200, `{"id":"p1"}`), "protected-resources", "update", "p1", "--allow-client-metadata", "--client-admission", "open")
	if err != nil || seen[0].Method != "PATCH" || !reflect.DeepEqual(seen[0].Body, map[string]any{"allow_client_metadata": true, "client_admission": "open"}) {
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
