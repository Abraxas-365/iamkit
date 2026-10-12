package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/crewjam/saml"
	"github.com/gofiber/fiber/v2"
)

// testLink opens a test connection link like a browser tab: the GET shows the
// interstitial (which must spend nothing), its button posts the ticket. It
// returns the status of the first answer that is not the page (the POST's, or
// the GET's when it is no page), the redirect to the identity provider and the
// binding cookie.
func (e *Env) testLink(link string) (int, string, *http.Cookie, string) {
	e.t.Helper()
	path := strings.TrimPrefix(link, "https://iam.example")
	page := e.follow(path, nil)
	if page.Status != 200 {
		return page.Status, "", nil, messageOf(page)
	}
	if !strings.Contains(page.Body, `method="post"`) || !strings.Contains(page.Body, `name="ticket"`) {
		e.t.Fatalf("interstitial has no form: %s", page.Body)
	}
	return e.testPost(link)
}

func messageOf(r Response) string {
	msg, _ := r.JSON["message"].(string)
	return msg
}

// testPost posts the link's ticket like the interstitial's button does.
func (e *Env) testPost(link string) (int, string, *http.Cookie, string) {
	e.t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		e.t.Fatal(err)
	}
	form := url.Values{"ticket": {u.Query().Get("ticket")}}
	req := httptest.NewRequest("POST", u.Path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var cookie *http.Cookie
	if c := res.Cookies(); len(c) > 0 {
		cookie = c[0]
	}
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	msg, _ := body["message"].(string)
	return res.StatusCode, res.Header.Get("Location"), cookie, msg
}

// sessionsAndUsers counts what a sign-in would have created.
func (e *Env) sessionsAndUsers() (sessions, users, links int) {
	e.t.Helper()
	if err := e.DB.Get(&sessions, `SELECT count(*) FROM sessions`); err != nil {
		e.t.Fatal(err)
	}
	if err := e.DB.Get(&users, `SELECT count(*) FROM users`); err != nil {
		e.t.Fatal(err)
	}
	if err := e.DB.Get(&links, `SELECT count(*) FROM external_identities`); err != nil {
		e.t.Fatal(err)
	}
	return
}

// TestSAMLDraftConnectionJourney: a draft gives the SP values before the
// identity provider's metadata exists, is invisible to sign-in until it is
// enabled, can be tested without creating anything, and signs in after.
func TestSAMLDraftConnectionJourney(t *testing.T) {
	e := newEnv(t)
	idp := samltest.New("https://idp.example.com")
	connections := e.Base + "/federation-connections"

	// Drafts are SAML only and carry no metadata yet.
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "draft": true, "options": fiber.Map{"metadata_xml": idp.Metadata()}}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "oidc", "draft": true, "issuer": "https://idp.example.com", "client_id": "c", "client_secret": "s"}, 400)
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "draft": true})

	// The SP values are there at once.
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON
	sp, _ := detail["saml"].(map[string]any)
	if detail["draft"] != true || detail["active"] != false || sp == nil || sp["entity_id"] == "" || sp["acs_url"] != "https://iam.example/identity/v1/federation/saml/acs" || sp["metadata_url"] == "" {
		t.Fatalf("draft detail = %v", detail)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.created' AND data->>'draft'='true'`); n != 1 {
		t.Fatalf("connection.created with data.draft = %d", n)
	}
	metadataPath := strings.TrimPrefix(sp["metadata_url"].(string), "https://iam.example")
	metadata := e.follow(metadataPath, nil)
	if metadata.Status != 200 || !strings.Contains(metadata.Body, `entityID="`+sp["entity_id"].(string)+`"`) {
		t.Fatalf("draft SP metadata: %d %s", metadata.Status, metadata.Body)
	}
	if err := idp.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}

	// Nothing can sign in through a draft; it is not listed for sign-in.
	body, _ := json.Marshal(fiber.Map{"connection_id": conn, "environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res})
	req := httptest.NewRequest("POST", "/identity/v1/federation/start", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if res, err := e.App.Test(req, 10000); err != nil || res.StatusCode < 400 {
		t.Fatalf("start through a draft: %v %v", res, err)
	}
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	if d := e.Must("POST", "/identity/v1/discover", "", fiber.Map{"environment_id": e.EnvID, "email": "carol@example.com"}, 200).JSON; d["connection_id"] != nil && d["connection_id"] != "" {
		t.Fatalf("discovery routed to a draft: %v", d)
	}

	// It cannot be enabled, or tested, before the metadata is set.
	e.Must("POST", connections+"/"+conn+"/enable", e.Owner, nil, 422)
	e.Must("POST", connections+"/"+conn+"/test", e.Owner, nil, 422)

	// The metadata is a PATCH away; the connection stays a draft.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata()}}, 204)
	if d := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON; d["draft"] != true || d["active"] != false || d["issuer"] != idp.EntityID() {
		t.Fatalf("patched draft = %v", d)
	}

	// Test connection: a one-time link, bound to the connection.
	sessions, users, links := e.sessionsAndUsers()
	ticket := e.Must("POST", connections+"/"+conn+"/test", e.Owner, nil, 200).JSON
	link, _ := ticket["url"].(string)
	if !strings.Contains(link, "/identity/v1/federation/test/"+e.EnvID+"/"+conn+"?ticket=ik_fedtest_") || ticket["expires_at"] == nil {
		t.Fatalf("ticket = %v", ticket)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_tests WHERE position('ik_fedtest_' in ticket_hash::text)>0`); n != 0 {
		t.Fatal("the raw ticket is stored")
	}
	// Asking for the link is a typed event: actor and the connection as subject.
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.test_requested' AND subject_kind='connection' AND subject_id=$1 AND actor_kind='operator' AND actor_id<>''`, conn); n != 1 {
		t.Fatalf("connection.test_requested events = %d", n)
	}
	// Link scanners and prefetchers only GET: the interstitial spends
	// nothing and says nothing about the ticket, however often it is opened.
	path := strings.TrimPrefix(link, "https://iam.example")
	for range 3 {
		scan := e.follow(path, nil)
		if scan.Status != 200 || !strings.Contains(scan.Body, `method="post"`) || !strings.Contains(scan.Body, "Start test sign-in") || strings.Contains(scan.Body, "<script") {
			t.Fatalf("interstitial: %d %s", scan.Status, scan.Body)
		}
		if !strings.Contains(scan.Body, `action="/identity/v1/federation/test/`+e.EnvID+"/"+conn+`"`) {
			t.Fatalf("interstitial action: %s", scan.Body)
		}
	}
	scanReq := httptest.NewRequest("GET", path, nil)
	scanRes, err := e.App.Test(scanReq, 10000)
	if err != nil {
		t.Fatal(err)
	}
	scanRes.Body.Close()
	csp := scanRes.Header.Get("Content-Security-Policy")
	if scanRes.Header.Get("Cache-Control") != "no-store" || scanRes.Header.Get("Referrer-Policy") != "no-referrer" || strings.Contains(csp, "form-action") || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("interstitial headers: %v", scanRes.Header)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_tests WHERE consumed_at IS NOT NULL`); n != 0 {
		t.Fatalf("opening the link spent the ticket (%d)", n)
	}
	// A malformed ticket is refused without a lookup; a wrong one on POST.
	if r := e.follow(path[:strings.Index(path, "?")]+"?ticket=nope", nil); r.Status != 401 {
		t.Fatalf("interstitial with a malformed ticket: %d", r.Status)
	}
	if status, _, _, _ := e.testPost(path[:strings.Index(path, "?")] + "?ticket=ik_fedtest_nope"); status != 401 {
		t.Fatalf("POST with a wrong ticket: %d", status)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_tests WHERE consumed_at IS NOT NULL`); n != 0 {
		t.Fatal("a wrong ticket spent another")
	}
	// The ticket is not accepted from the query of a POST: it is a form field.
	if r := e.Do("POST", path, "", nil); r.Status != 401 {
		t.Fatalf("POST without a form ticket: %d", r.Status)
	}
	status, redirect, cookie, msg := e.testLink(link)
	if status != 303 || !strings.HasPrefix(redirect, "https://idp.example.com/sso?SAMLRequest=") || cookie == nil {
		t.Fatalf("test start: %d %q %v %s", status, redirect, cookie, msg)
	}
	// The binding cookie survives the top-level POST: Lax, Secure, host-only.
	if cookie.Name != "__Host-iamkit-federation" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("binding cookie = %+v", cookie)
	}
	// A spent ticket opens nothing.
	if status, _, _, _ = e.testPost(link); status != 401 {
		t.Fatalf("reused ticket: %d", status)
	}
	user := samltest.User{NameID: "00u-tess", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "tess@example.com", Name: "Tess"}
	form, err := idp.Answer(redirect, user)
	if err != nil {
		t.Fatal(err)
	}
	status, location := e.acs(form)
	if status != 303 || !strings.HasPrefix(location, "/identity/v1/federation/callback?code=ik_saml_") {
		t.Fatalf("acs: %d %q", status, location)
	}
	page := e.follow(location, cookie)
	for _, want := range []string{"tess@example.com", "00u-tess", "Tess", "Connection test succeeded"} {
		if page.Status != 200 || !strings.Contains(page.Body, want) {
			t.Fatalf("result page lacks %q: %d %s", want, page.Status, page.Body)
		}
	}
	if strings.Contains(page.Body, "<script") || strings.Contains(page.Body, "ik_saml_") || strings.Contains(page.Body, "SAMLResponse") {
		t.Fatalf("result page leaks: %s", page.Body)
	}
	// The binding cookie is single use too.
	if r := e.follow(location, cookie); r.Status != 401 {
		t.Fatalf("callback reused: %d", r.Status)
	}
	// Nothing was created: no session, user or link; one tested event.
	if s, u, l := e.sessionsAndUsers(); s != sessions || u != users || l != links {
		t.Fatalf("a test sign-in created sessions %d→%d users %d→%d links %d→%d", sessions, s, users, u, links, l)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.tested' AND data->>'success'='true' AND data->>'connection_id'=$1`, conn); n != 1 {
		t.Fatalf("connection.tested events = %d", n)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.tested' AND data::text LIKE '%tess@example.com%'`); n != 0 {
		t.Fatal("the event carries the user's claims")
	}

	// A link for another connection or environment does not work.
	other := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Other", "provider": "saml", "draft": true})
	e.Must("PATCH", connections+"/"+other, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata()}}, 204)
	link = e.Must("POST", connections+"/"+conn+"/test", e.Owner, nil, 200).JSON["url"].(string)
	crossed := strings.Replace(link, "/"+conn+"?", "/"+other+"?", 1)
	if status, _, _, _ = e.testLink(crossed); status != 401 {
		t.Fatalf("ticket of another connection: %d", status)
	}
	// (A ticket tried against the wrong connection is not spent, but only
	// its own connection ever accepts it.)

	// An identity provider answer that fails verification is a failed test.
	link = e.Must("POST", connections+"/"+conn+"/test", e.Owner, nil, 200).JSON["url"].(string)
	_, redirect, cookie, _ = e.testLink(link)
	forger := samltest.New("https://idp.example.com")
	_ = forger.Trust([]byte(metadata.Body))
	form, _ = forger.Answer(redirect, user)
	_, location = e.acs(form)
	failed := e.follow(location, cookie)
	if failed.Status != 200 || !strings.Contains(failed.Body, "Connection test failed") || strings.Contains(failed.Body, "tess@example.com") {
		t.Fatalf("failed test page: %d %s", failed.Status, failed.Body)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.tested' AND data->>'success'='false'`); n != 1 {
		t.Fatalf("failed connection.tested events = %d", n)
	}
	if s, u, l := e.sessionsAndUsers(); s != sessions || u != users || l != links {
		t.Fatal("a failed test created something")
	}

	// Enable: now it signs in (JIT).
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": group}, 204)
	e.Must("POST", connections+"/"+conn+"/enable", e.Owner, nil, 204)
	if d := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON; d["draft"] != false || d["active"] != true {
		t.Fatalf("enabled = %v", d)
	}
	if r, _ := e.samlLogin(idp, conn, user); r.Status != 200 || r.JSON["access_token"] == nil {
		t.Fatalf("sign-in after enable: %d %s", r.Status, r.Body)
	}

	// The test works for an enabled connection too, still creating nothing.
	sessions, users, links = e.sessionsAndUsers()
	link = e.Must("POST", connections+"/"+conn+"/test", e.Owner, nil, 200).JSON["url"].(string)
	_, redirect, cookie, _ = e.testLink(link)
	form, _ = idp.Answer(redirect, user)
	_, location = e.acs(form)
	if r := e.follow(location, cookie); r.Status != 200 || !strings.Contains(r.Body, "Connection test succeeded") {
		t.Fatalf("test of an enabled connection: %d %s", r.Status, r.Body)
	}
	if s, u, l := e.sessionsAndUsers(); s != sessions || u != users || l != links {
		t.Fatal("test of an enabled connection created something")
	}

	// Pruning removes stale drafts only, even one whose test sign-in left a
	// replay row (saml_assertions does not cascade).
	stale := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Stale", "provider": "saml", "draft": true})
	e.DB.MustExec(`INSERT INTO saml_assertions(connection_id,assertion_id,expires_at) VALUES($1,'stale-test',now()+interval '1 hour')`, stale)
	e.DB.MustExec(`UPDATE federation_connections SET created_at = now() - interval '8 days' WHERE id IN ($1, $2)`, stale, conn)
	if found, err := e.Server.Workers.RunOnce(t.Context(), "federation_draft_prune"); !found || err != nil {
		t.Fatalf("prune: %v %v", found, err)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_connections WHERE id=$1`, stale); n != 0 {
		t.Fatal("stale draft kept")
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_connections WHERE id=$1`, conn); n != 1 {
		t.Fatal("an enabled connection was pruned")
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_connections WHERE id=$1`, other); n != 1 {
		t.Fatal("a fresh draft was pruned")
	}
}

// TestOIDCConnectionTest: the test flow for an OIDC connection reports the
// claims and mapped values without signing anyone in; LDAP says it cannot.
func TestOIDCConnectionTest(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(idp.Client().Transport)
	connections := e.Base + "/federation-connections"
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})

	// An inactive connection can be tested (before enabling it).
	e.Must("DELETE", connections+"/"+conn, e.Owner, nil, 204)
	sessions, users, links := e.sessionsAndUsers()
	link := e.Must("POST", connections+"/"+conn+"/test", e.Owner, nil, 200).JSON["url"].(string)
	status, redirect, cookie, msg := e.testLink(link)
	if status != 303 || cookie == nil || !strings.HasPrefix(redirect, idp.URL+"/authorize?") {
		t.Fatalf("test start: %d %q %v %s", status, redirect, cookie, msg)
	}
	authorization, _ := url.Parse(redirect)
	idp.mu.Lock()
	idp.nonce, idp.claims = authorization.Query().Get("nonce"), map[string]any{"sub": "u-9", "email": "ivy@example.com", "email_verified": true, "name": "Ivy <b>Bold</b>", "groups": []string{"eng", "ops"}}
	idp.mu.Unlock()
	callback := "/identity/v1/federation/callback?code=provider-code&state=" + url.QueryEscape(authorization.Query().Get("state"))
	page := e.follow(callback, cookie)
	for _, want := range []string{"Connection test succeeded", "ivy@example.com", "u-9", "eng", "ops"} {
		if page.Status != 200 || !strings.Contains(page.Body, want) {
			t.Fatalf("page lacks %q: %d %s", want, page.Status, page.Body)
		}
	}
	// Everything is escaped, and no secret reaches the page.
	if strings.Contains(page.Body, "<b>Bold</b>") || !strings.Contains(page.Body, "&lt;b&gt;Bold&lt;/b&gt;") || strings.Contains(page.Body, "sealed-secret") || strings.Contains(page.Body, "upstream") {
		t.Fatalf("page: %s", page.Body)
	}
	if s, u, l := e.sessionsAndUsers(); s != sessions || u != users || l != links {
		t.Fatalf("created sessions %d→%d users %d→%d links %d→%d", sessions, s, users, u, links, l)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM federation_connections WHERE id=$1 AND NOT active`, conn); n != 1 {
		t.Fatal("testing changed the connection")
	}

	// The same state cannot be replayed.
	if r := e.follow(callback, cookie); r.Status != 401 {
		t.Fatalf("callback replay: %d", r.Status)
	}

	// An organization administrator asks for the link through the portal's
	// API: the event names the connection and the organization.
	e.makeOrgAdmin(e.Org, e.Alice)
	admin := e.orgAdminToken(e.Org, e.AliceEmail)
	before := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.test_requested'`)
	adminLink := e.Must("POST", e.adminBase(e.Org)+"/connections/"+conn+"/test", admin, nil, 200).JSON["url"].(string)
	if !strings.Contains(adminLink, "/identity/v1/federation/test/"+e.EnvID+"/"+conn+"?ticket=ik_fedtest_") {
		t.Fatalf("org-admin link = %s", adminLink)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.test_requested' AND subject_kind='connection' AND subject_id=$1 AND organization_id=$2 AND actor_kind='user' AND actor_id=$3`, conn, e.Org, e.Alice); n != 1 {
		t.Fatalf("org-admin connection.test_requested events = %d", n)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE type='connection.test_requested'`); n != before+1 {
		t.Fatalf("connection.test_requested total = %d, want %d", n, before+1)
	}

	// Unknown connection, bad tickets.
	e.Must("POST", connections+"/"+"00000000-0000-4000-8000-000000000000"+"/test", e.Owner, nil, 404)
	for _, bad := range []string{"", "?ticket=", "?ticket=ik_fedtest_nope"} {
		if status, _, _, _ := e.testLink("https://iam.example/identity/v1/federation/test/" + e.EnvID + "/" + conn + bad); status != 401 {
			t.Fatalf("ticket %q: %d", bad, status)
		}
	}

	// LDAP has no browser sign-in to test.
	ldap := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Directory", "provider": "ldap", "client_secret": "bind-password",
		"options": fiber.Map{"url": "ldaps://ldap.example.com", "bind_dn": "cn=svc,dc=example,dc=com", "user_base_dn": "dc=example,dc=com", "user_filter": "(mail={email})"}})
	if r := e.Must("POST", connections+"/"+ldap+"/test", e.Owner, nil, 422); !strings.Contains(r.Body, "LDAP") {
		t.Fatalf("ldap test: %s", r.Body)
	}
}
