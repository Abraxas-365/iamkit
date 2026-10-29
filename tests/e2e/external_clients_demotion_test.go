package e2e_test

import (
	"context"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// demotionClient registers a document for a client at host, authorizes it
// (the caller made sure something admits it) and returns its row and tokens.
func (e *Env) liveExternal(id string) (row string, refresh string) {
	e.t.Helper()
	status, tokens := e.authorizeExternal(id)
	if status != 200 || tokens["refresh_token"] == nil {
		e.t.Fatalf("authorize %s: %d %v", id, status, tokens)
	}
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, id)
	return row, tokens["refresh_token"].(string)
}

func (e *Env) wantDemoted(id, row, refresh, reason string) {
	e.t.Helper()
	var admission, source string
	e.DB.QueryRow(`SELECT admission, admission_source FROM oauth_clients WHERE id=$1`, row).Scan(&admission, &source)
	if admission != "pending" || source != "" {
		e.t.Fatalf("%s after %s: admission %q source %q", id, reason, admission, source)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, row); n != 0 {
		e.t.Fatalf("%s: %d sessions outlived %s", id, n, reason)
	}
	if n := e.count(`SELECT count(*) FROM oauth_authorizations WHERE client_id=$1`, row); n != 0 {
		e.t.Fatalf("%s: %d grants outlived %s", id, n, reason)
	}
	if status, out, _ := e.tokenCall(refreshForm(id, refresh), ""); status != 400 || out["error"] != "invalid_grant" {
		e.t.Fatalf("%s refresh after %s: %d %v", id, reason, status, out)
	}
	if n := e.count(`SELECT count(*) FROM events WHERE type='oauth_client.demoted' AND subject_id=$1 AND data->>'reason'=$2`, row, reason); n != 1 {
		e.t.Fatalf("%s: %d oauth_client.demoted events for %s", id, n, reason)
	}
}

// wantStays refreshes (rotating the token) and returns the new refresh token.
func (e *Env) wantStays(id, row, refresh string) string {
	e.t.Helper()
	var admission string
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, row)
	if admission != "approved" {
		e.t.Fatalf("%s lost its approval: %q", id, admission)
	}
	status, out, _ := e.tokenCall(refreshForm(id, refresh), "")
	if status != 200 {
		e.t.Fatalf("%s refresh: %d %v", id, status, out)
	}
	return out["refresh_token"].(string)
}

func docOf(id string) map[string]any {
	return map[string]any{"client_id": id, "client_name": "App", "redirect_uris": []string{"http://localhost/callback"}, "grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"}
}

// TestPolicyApprovalsEndWithThePolicy is M-2: a client approved by policy
// (allowlist entry, open server) goes back to pending, with its grants and
// sessions revoked, when the policy no longer admits it; a manual approval
// survives that, but not the server refusing document clients.
func TestPolicyApprovalsEndWithThePolicy(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	base := e.Base + "/protected-resources/" + protected
	listed, manual, other := "https://listed.example/c/one", "https://manual.example/c/one", "https://listed.example/c/two"
	for _, id := range []string{listed, manual, other} {
		host.Put(id, docOf(id))
	}

	// One entry admits two clients; a second entry would still admit one.
	entry := e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://listed.example", "path_prefix": "/c/one", "protected_resource_id": protected}, 201).JSON["id"].(string)
	listedRow, listedRefresh := e.liveExternal(listed)
	// Pending, approved by hand, with a live grant.
	if p := e.loginAndAsk(manual); p.Status != 403 {
		t.Fatalf("manual pending: %d", p.Status)
	}
	var manualRow string
	e.DB.Get(&manualRow, `SELECT id FROM oauth_clients WHERE external_id=$1`, manual)
	e.approveClient(base, manualRow)
	_, manualRefresh := e.liveExternal(manual)

	// Deleting the entry demotes what only it admitted; the manual one stays.
	e.Must("DELETE", e.Base+"/oauth-client-allowlist/"+entry, e.Owner, nil, 204)
	e.wantDemoted(listed, listedRow, listedRefresh, "admission_policy_ended")
	manualRefresh = e.wantStays(manual, manualRow, manualRefresh)

	// An entry that still admits the client keeps it (relabelled).
	e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://listed.example", "path_prefix": "/c", "protected_resource_id": protected}, 201)
	otherRow, otherRefresh := e.liveExternal(other)
	e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://listed.example", "path_prefix": "/c/two", "protected_resource_id": protected}, 201)
	var firstEntry string
	e.DB.Get(&firstEntry, `SELECT id FROM oauth_client_allowlist WHERE path_prefix='/c'`)
	e.Must("DELETE", e.Base+"/oauth-client-allowlist/"+firstEntry, e.Owner, nil, 204)
	e.wantStays(other, otherRow, otherRefresh)

	// Open server: admitted by discovery; back to allowlist ends it.
	e.Must("PATCH", base, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	opened := "https://opened.example/c/one"
	host.Put(opened, docOf(opened))
	openRow, openRefresh := e.liveExternal(opened)
	var source string
	e.DB.Get(&source, `SELECT admission_source FROM oauth_clients WHERE id=$1`, openRow)
	if source != "open" {
		t.Fatalf("admission_source = %q", source)
	}
	e.Must("PATCH", base, e.Owner, fiber.Map{"client_admission": "allowlist"}, 200)
	e.wantDemoted(opened, openRow, openRefresh, "admission_policy_ended")
	manualRefresh = e.wantStays(manual, manualRow, manualRefresh)

	// L-3: turning the server open again admits what waits.
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1 AND admission='pending'`, openRow); n != 1 {
		t.Fatal("the demoted client is not pending")
	}
	e.Must("PATCH", base, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	if got := e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1 AND admission='approved' AND admission_source='open'`, openRow); got != 1 {
		t.Fatal("opening the server did not admit the pending client")
	}
	e.Must("PATCH", base, e.Owner, fiber.Map{"client_admission": "allowlist"}, 200)

	// The server stops taking document clients: every approval goes,
	// manual ones too, and the approved never come back by themselves.
	e.Must("PATCH", base, e.Owner, fiber.Map{"allow_client_metadata": false}, 200)
	e.wantDemoted(manual, manualRow, manualRefresh, "metadata_documents_disabled")
	e.Must("PATCH", base, e.Owner, fiber.Map{"allow_client_metadata": true}, 200)
	if got := e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1 AND admission='pending'`, manualRow); got != 1 {
		t.Fatal("a manual approval came back with allow_client_metadata")
	}
}

// TestDocumentsFeatureOffStopsApprovedClients is M-2 for the feature flag:
// at use it refuses at once, and the reconcile job then demotes (flag is
// another module's, so no transaction of ours sees the change).
func TestDocumentsFeatureOffStopsApprovedClients(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	host := e.metadataHost()
	id := "https://apps.example/c/feature"
	host.Put(id, docOf(id))
	row, refresh := e.liveExternal(id)

	e.Must("PUT", e.Base+"/features/client_metadata_documents", e.Owner, fiber.Map{"enabled": false}, 200)
	// At use, before any job: the refresh is refused and the row still says approved.
	if status, out, _ := e.tokenCall(refreshForm(id, refresh), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh with the feature off: %d %v", status, out)
	}
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_documents_reconcile"); !found || err != nil {
		t.Fatalf("reconcile job: %v %v", found, err)
	}
	e.wantDemoted(id, row, refresh, "feature_disabled")

	// Back on: nothing returns by itself, but the open server admits it
	// the next time a user asks (it is pending, discovery re-approves).
	e.Must("PUT", e.Base+"/features/client_metadata_documents", e.Owner, fiber.Map{"enabled": true}, 200)
	if got := e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1 AND admission='pending'`, row); got != 1 {
		t.Fatal("client approved by itself")
	}
}
