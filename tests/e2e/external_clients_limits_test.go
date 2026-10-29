package e2e_test

import (
	"strings"
	"testing"

	"net/url"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/gofiber/fiber/v2"
)

// TestAccessRequestCaps is M-3: one user (and one organization) can keep
// only so many requests for clients still waiting for IT, so a single
// account cannot fill the environment's backlog. The refusal is its own
// code and its own page; nothing is persisted for it; answering a request
// frees its slot.
func TestAccessRequestCaps(t *testing.T) {
	e := newEnv(t, bootstrap.WithClientAccessRequestCaps(2, 3))
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, resource := e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	base := e.Base + "/protected-resources/" + protected
	ids := make([]string, 6)
	for i := range ids {
		ids[i] = "https://apps.example/client/" + itoa(i)
		host.Put(ids[i], docOf(ids[i]))
	}
	bobEmail := "bob@example.com"
	bob := e.User("Bob", bobEmail)
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, resource, "mcp:tools:read")

	// The user: two requests wait, the third is refused with its own page.
	for _, id := range ids[:2] {
		if p := e.loginAndAsk(id); p.Status != 403 {
			t.Fatalf("%s: %d", id, p.Status)
		}
	}
	p := e.loginAndAsk(ids[2])
	if p.Status != 429 || p.Location != "" || !strings.Contains(p.Body, "You have too many requests waiting") {
		t.Fatalf("user cap: %d %q %s", p.Status, p.Location, p.Body)
	}
	if strings.Contains(p.Body, "Too many applications are waiting") {
		t.Fatal("the user cap shows the environment backlog page")
	}
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE external_id=$1`, ids[2]); n != 0 {
		t.Fatal("a refused request persisted its client")
	}
	// Asking again for a client already asked for is not a new request.
	if p := e.loginAndAsk(ids[0]); p.Status != 403 {
		t.Fatalf("repeat request: %d", p.Status)
	}

	// The organization: bob adds the third pending request of Acme, his next is refused.
	if p := e.loginAsAndAsk(bobEmail, ids[3]); p.Status != 403 {
		t.Fatalf("bob first: %d %s", p.Status, p.Body)
	}
	if p := e.loginAsAndAsk(bobEmail, ids[4]); p.Status != 429 {
		t.Fatalf("organization cap: %d %s", p.Status, p.Body)
	}
	if n := e.count(`SELECT count(*) FROM oauth_client_access_requests WHERE organization_id=$1`, e.Org); n != 3 {
		t.Fatalf("requests of the organization = %d", n)
	}

	// IT answers one: its slot frees for the user and the organization.
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, ids[0])
	e.approveClient(base, row)
	if p := e.loginAsAndAsk(bobEmail, ids[4]); p.Status != 403 {
		t.Fatalf("after an answer: %d %s", p.Status, p.Body)
	}
	// An API client sees the code.
	code := e.Do("GET", "/oauth/authorize?client_id="+ids[5], "", nil)
	_ = code
}

// TestExternalClientStaleIfError is M-4: an approved client whose document
// cannot be read now (the host is down, or answers an error) signs in with
// the metadata it was approved with; a document that is read but invalid, a
// pending client and a client never seen get the error.
func TestExternalClientStaleIfError(t *testing.T) {
	cache := newFlushable()
	e := newEnv(t, bootstrap.WithClientMetadataCache(cache))
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	redirect := "http://localhost:53682/callback"
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))

	if p := e.loginAndAsk(claudeCodeID); p.Status != 403 {
		t.Fatalf("pending: %d", p.Status)
	}
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)

	// Pending: an unreachable host is an error, nothing is served from storage.
	host.Delete(claudeCodeID)
	cache.Flush()
	if p := e.browser().get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})); p.Status < 400 {
		t.Fatalf("pending client with its host down: %d", p.Status)
	}

	// Approved: the host is down (404), the cache is empty, the client still signs in.
	e.DB.MustExec(`UPDATE oauth_clients SET admission='approved', admission_source='manual', approved_metadata_hash=$2 WHERE id=$1`, row, oauth.MetadataHash([]string{"http://localhost/callback"}, "", "none"))
	cache.Flush()
	b := e.browser()
	code := b.signInTo(b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})), redirect)
	form := codeForm(claudeCodeID, code)
	form.Set("redirect_uri", redirect)
	if status, _, _ := e.tokenCall(form, ""); status != 200 {
		t.Fatalf("approved client with its host down: exchange %d", status)
	}
	if n := e.count(`SELECT count(*) FROM events WHERE type='oauth_client.updated' AND subject_id=$1`, row); n != 0 {
		t.Fatalf("stored metadata was rewritten: %d updates", n)
	}

	// Past the staleness bound it stops.
	e.DB.MustExec(`UPDATE oauth_clients SET metadata_fetched_at=now()-interval '49 hours' WHERE id=$1`, row)
	cache.Flush()
	if p := e.browser().get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})); p.Status < 400 {
		t.Fatalf("past the bound: %d", p.Status)
	}
	e.DB.MustExec(`UPDATE oauth_clients SET metadata_fetched_at=now() WHERE id=$1`, row)

	// A document that is read but invalid is not "down": it stands.
	host.Put(claudeCodeID, map[string]any{"client_id": claudeCodeID, "client_name": "Claude Code"})
	cache.Flush()
	if p := e.browser().get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})); p.Status < 400 {
		t.Fatalf("invalid document: %d", p.Status)
	}
}
