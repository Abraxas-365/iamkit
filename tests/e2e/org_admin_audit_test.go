package e2e_test

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/gofiber/fiber/v2"
)

// TestOrgAdminAuditLogs: an organization's administrators read and export
// their own organization's app audit log (never another's), manage its log
// streams (the secret is shown once), a setup link with the log_streams
// intent configures streams but cannot read the log, and stream changes
// show up in the organization's own …/admin/events.
func TestOrgAdminAuditLogs(t *testing.T) {
	receiver := &streamReceiver{}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithLogStreamTransport(http.DefaultTransport))
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)

	// Alice owns Acme; Mallory only manages its users.
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	mallory := e.User("Mallory", "mallory@example.com")
	e.Join(e.Org, mallory)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": mallory, "role_id": e.systemRole("org_user_manager")}, 204)
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})

	alice := e.orgAdminToken(e.Org, e.AliceEmail)
	malloryToken := e.orgAdminToken(e.Org, "mallory@example.com")
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	globexAdmin := "/api/v1/environments/" + e.EnvID + "/organizations/" + globex + "/admin"

	// ── The log: only the organization's own events ──
	e.auditRow(e.Org, "doc.view")
	e.auditRow(e.Org, "doc.edit")
	e.auditRow(globex, "doc.delete")
	e.auditRow(globex, "doc.view")

	list := e.Must("GET", admin+"/audit-logs", alice, nil, 200)
	items := list.JSON["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("list = %s", list.Body)
	}
	for _, it := range items {
		if it.(map[string]any)["organization_id"] != e.Org {
			t.Fatalf("foreign event: %v", it)
		}
	}
	// organization_id is not a filter here: the caller's organization wins.
	forced := e.Must("GET", admin+"/audit-logs?organization_id="+globex, alice, nil, 200)
	if n := len(forced.JSON["items"].([]any)); n != 2 || strings.Contains(forced.Body, globex) {
		t.Fatalf("organization_id leaked another organization: %s", forced.Body)
	}
	if n := len(e.Must("GET", admin+"/audit-logs?action=doc.delete", alice, nil, 200).JSON["items"].([]any)); n != 0 {
		t.Fatalf("another organization's action visible: %d", n)
	}
	one := e.Must("GET", admin+"/audit-logs?action=doc.edit&limit=1", alice, nil, 200)
	if n := len(one.JSON["items"].([]any)); n != 1 || one.JSON["items"].([]any)[0].(map[string]any)["action"] != "doc.edit" {
		t.Fatalf("filtered = %s", one.Body)
	}
	e.Must("GET", admin+"/audit-logs?occurred_after=yesterday", alice, nil, 400)
	// Globex's administrators are not Acme's.
	e.Must("GET", globexAdmin+"/audit-logs", alice, nil, 403)

	// Export: oldest first, NDJSON or CSV, own events only.
	nd := e.Do("GET", admin+"/audit-logs/export", alice, nil)
	if nd.Status != 200 {
		t.Fatalf("export = %d %s", nd.Status, nd.Body)
	}
	lines := strings.Split(strings.TrimSpace(nd.Body), "\n")
	if len(lines) != 2 {
		t.Fatalf("ndjson = %s", nd.Body)
	}
	var first, second map[string]any
	if json.Unmarshal([]byte(lines[0]), &first) != nil || json.Unmarshal([]byte(lines[1]), &second) != nil ||
		first["action"] != "doc.view" || second["action"] != "doc.edit" || first["organization_id"] != e.Org || second["organization_id"] != e.Org {
		t.Fatalf("ndjson = %s", nd.Body)
	}
	cs := e.Do("GET", admin+"/audit-logs/export?format=csv&organization_id="+globex, alice, nil)
	rows, err := csv.NewReader(strings.NewReader(cs.Body)).ReadAll()
	if cs.Status != 200 || err != nil || len(rows) != 3 || strings.Contains(cs.Body, "doc.delete") {
		t.Fatalf("csv = %d %v\n%s", cs.Status, err, cs.Body)
	}
	e.Must("GET", admin+"/audit-logs/export?format=xml", alice, nil, 400)
	e.Must("GET", admin+"/audit-logs/export?before=5", alice, nil, 400)

	// ── No permission, no access ──
	for _, p := range []string{"/audit-logs", "/audit-logs/export", "/log-streams"} {
		e.Must("GET", admin+p, malloryToken, nil, 403)
	}
	e.Must("POST", admin+"/log-streams", malloryToken, fiber.Map{"name": "SIEM", "destination": "https", "config": fiber.Map{"url": srv.URL}}, 403)
	e.Must("GET", admin+"/audit-logs", "", nil, 401)

	// ── Streams: organization-only, audit logs only ──
	ls := admin + "/log-streams"
	e.Must("POST", ls, alice, fiber.Map{"name": "bad", "destination": "https", "config": fiber.Map{"url": srv.URL}, "sources": []string{"events"}}, 400)
	e.Must("POST", ls, alice, fiber.Map{"name": "bad", "destination": "https", "config": fiber.Map{"url": srv.URL}, "sources": []string{"events", "audit_logs"}}, 400)
	e.Must("POST", ls, alice, fiber.Map{"name": "bad", "destination": "https", "config": fiber.Map{"url": srv.URL}, "organization_id": globex}, 400)
	e.Must("POST", ls, alice, fiber.Map{"name": "bad", "destination": "https", "config": fiber.Map{"url": "ftp://x"}}, 400)
	created := e.Must("POST", ls, alice, fiber.Map{"name": "SIEM", "destination": "https", "config": fiber.Map{"url": srv.URL}}, 201).JSON
	stream, secret := created["id"].(string), created["secret"].(string)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("created = %v", created)
	}
	receiver.set(0, secret)
	got := e.Must("GET", ls+"/"+stream, alice, nil, 200)
	if strings.Contains(got.Body, "whsec_") || got.JSON["secret_set"] != true || got.JSON["active"] != true ||
		got.JSON["organization_id"] != e.Org || got.JSON["sources"].([]any)[0] != "audit_logs" || len(got.JSON["sources"].([]any)) != 1 {
		t.Fatalf("stream = %s", got.Body)
	}
	if all := e.Must("GET", ls, alice, nil, 200); strings.Contains(all.Body, "whsec_") || len(all.JSON["items"].([]any)) != 1 {
		t.Fatalf("list = %s", all.Body)
	}

	// Another organization's stream and an environment's are not found.
	foreign := e.Must("POST", e.Base+"/log-streams", e.Owner, fiber.Map{"name": "Globex SIEM", "destination": "https", "config": fiber.Map{"url": srv.URL}, "organization_id": globex}, 201).JSON["id"].(string)
	envStream := e.Must("POST", e.Base+"/log-streams", e.Owner, fiber.Map{"name": "Ops", "destination": "https", "config": fiber.Map{"url": srv.URL}}, 201).JSON["id"].(string)
	for _, other := range []string{foreign, envStream} {
		e.Must("GET", ls+"/"+other, alice, nil, 404)
		e.Must("PATCH", ls+"/"+other, alice, fiber.Map{"name": "mine now"}, 404)
		e.Must("POST", ls+"/"+other+"/test", alice, fiber.Map{}, 404)
		e.Must("POST", ls+"/"+other+"/enable", alice, fiber.Map{}, 404)
		e.Must("POST", ls+"/"+other+"/rotate-secret", alice, fiber.Map{}, 404)
		e.Must("GET", ls+"/"+other+"/deliveries", alice, nil, 404)
		e.Must("DELETE", ls+"/"+other, alice, nil, 404)
	}
	e.Must("GET", ls+"/not-a-uuid", alice, nil, 404)
	// The operator still sees all three.
	if n := len(e.Must("GET", e.Base+"/log-streams", e.Owner, nil, 200).JSON["items"].([]any)); n != 3 {
		t.Fatalf("operator streams = %d", n)
	}

	// Update, pause, test, rotate, resume.
	renamed := e.Must("PATCH", ls+"/"+stream, alice, fiber.Map{"name": "Acme SIEM"}, 200).JSON
	if renamed["name"] != "Acme SIEM" || renamed["organization_id"] != e.Org {
		t.Fatalf("renamed = %v", renamed)
	}
	e.Must("PATCH", ls+"/"+stream, alice, fiber.Map{"sources": []string{"events"}}, 400)
	if paused := e.Must("PATCH", ls+"/"+stream, alice, fiber.Map{"active": false}, 200).JSON; paused["active"] != false {
		t.Fatalf("paused = %v", paused)
	}
	if resumed := e.Must("POST", ls+"/"+stream+"/enable", alice, fiber.Map{}, 200).JSON; resumed["active"] != true {
		t.Fatalf("resumed = %v", resumed)
	}
	if res := e.Must("POST", ls+"/"+stream+"/test", alice, fiber.Map{}, 200).JSON; res["delivered"] != true {
		t.Fatalf("test = %v", res)
	}
	rotated := e.Must("POST", ls+"/"+stream+"/rotate-secret", alice, fiber.Map{}, 200).JSON
	fresh := rotated["secret"].(string)
	if !strings.HasPrefix(fresh, "whsec_") || fresh == secret {
		t.Fatalf("rotated = %v", rotated)
	}
	receiver.set(0, secret, fresh)

	// New audit events of this organization (only) reach the stream.
	e.auditRow(e.Org, "doc.share")
	e.auditRow(globex, "doc.share")
	e.drainStreams()
	var shared int
	for _, r := range receiver.records() {
		if r["source"] == "audit_logs" && r["action"] == "doc.share" {
			shared++
		}
		if r["source"] == "events" {
			t.Fatalf("an organization stream received an IAMKit event: %v", r)
		}
	}
	if shared != 1 {
		t.Fatalf("doc.share records = %d, want 1 (batches: %v)", shared, receiver.records())
	}
	e.Must("GET", ls+"/"+stream+"/deliveries?status=delivered", alice, nil, 200)
	e.Must("GET", ls+"/"+stream+"/deliveries?status=nope", alice, nil, 400)
	e.Must("POST", ls+"/"+stream+"/deliveries/999999/retry", alice, fiber.Map{}, 404)

	// ── The organization sees its stream changes in …/admin/events ──
	events := e.Must("GET", admin+"/events?limit=100", alice, nil, 200)
	for _, want := range []string{"log_stream.create", "log_stream.update", "log_stream.rotate_secret"} {
		if !strings.Contains(events.Body, want) {
			t.Fatalf("admin events lack %s: %s", want, events.Body)
		}
	}
	if strings.Contains(events.Body, "Globex SIEM") || strings.Contains(events.Body, foreign) || strings.Contains(events.Body, envStream) {
		t.Fatalf("admin events show another stream: %s", events.Body)
	}
	if strings.Contains(events.Body, secret) || strings.Contains(events.Body, fresh) {
		t.Fatalf("admin events leak a secret: %s", events.Body)
	}
	// The IAMKit event carries the organization (webhooks and the operator's log see it too).
	var typed int
	if err := e.DB.Get(&typed, `SELECT count(*) FROM events WHERE type='log_stream.created' AND organization_id=$1 AND subject_id=$2`, e.Org, stream); err != nil || typed != 1 {
		t.Fatalf("log_stream.created events = %d %v", typed, err)
	}

	e.Must("DELETE", ls+"/"+stream, alice, nil, 204)
	e.Must("GET", ls+"/"+stream, alice, nil, 404)
	e.Must("DELETE", ls+"/"+stream, alice, nil, 404)
	if !strings.Contains(e.Must("GET", admin+"/events?limit=100", alice, nil, 200).Body, "log_stream.delete") {
		t.Fatal("deletion not visible in admin events")
	}
}

// TestOrgAdminLogStreamSetupLink: a setup link with the log_streams intent
// creates and tests a stream, but cannot read the audit log or anything else.
func TestOrgAdminLogStreamSetupLink(t *testing.T) {
	receiver := &streamReceiver{}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithLogStreamTransport(http.DefaultTransport))
	links := e.Base + "/organizations/" + e.Org + "/setup-links"
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"

	e.auditRow(e.Org, "doc.view")
	issued := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"log_streams"}}, 201).JSON
	linkID := issued["id"].(string)
	bearer := e.exchangeSetup(issued["url"].(string), 200).JSON["access_token"].(string)

	// Streams: create, read back, test, rotate, update, resume, delete.
	ls := admin + "/log-streams"
	created := e.Must("POST", ls, bearer, fiber.Map{"name": "SIEM", "destination": "https", "config": fiber.Map{"url": srv.URL}}, 201).JSON
	stream, secret := created["id"].(string), created["secret"].(string)
	receiver.set(0, secret)
	if got := e.Must("GET", ls+"/"+stream, bearer, nil, 200); strings.Contains(got.Body, "whsec_") {
		t.Fatalf("stream = %s", got.Body)
	}
	e.Must("GET", ls, bearer, nil, 200)
	e.Must("GET", ls+"/"+stream+"/deliveries", bearer, nil, 200)
	if res := e.Must("POST", ls+"/"+stream+"/test", bearer, fiber.Map{}, 200).JSON; res["delivered"] != true {
		t.Fatalf("test = %v", res)
	}
	e.Must("PATCH", ls+"/"+stream, bearer, fiber.Map{"name": "Renamed"}, 200)
	e.Must("POST", ls+"/"+stream+"/enable", bearer, fiber.Map{}, 200)
	e.Must("POST", ls+"/"+stream+"/rotate-secret", bearer, fiber.Map{}, 200)

	// The log itself and everything else stay closed.
	for _, p := range []string{"/audit-logs", "/audit-logs/export", "/events", "/members", "/users"} {
		e.Must("GET", admin+p, bearer, nil, 403)
	}
	// Another organization's routes too.
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/organizations/"+globex+"/admin/log-streams", bearer, nil, 403)
	// An sso-only link cannot touch streams.
	sso := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso"}}, 201).JSON
	ssoBearer := e.exchangeSetup(sso["url"].(string), 200).JSON["access_token"].(string)
	e.Must("GET", ls, ssoBearer, nil, 403)
	e.Must("POST", ls, ssoBearer, fiber.Map{"name": "SIEM", "destination": "https", "config": fiber.Map{"url": srv.URL}}, 403)

	// The link is the actor of the audited changes, visible to the operator
	// and to the organization.
	var kind string
	if err := e.DB.Get(&kind, `SELECT actor_kind FROM audit_events WHERE action='log_stream.create' AND actor_id=$1`, linkID); err != nil || kind != "setup_link" {
		t.Fatalf("log_stream.create actor kind = %q %v", kind, err)
	}
	var org string
	if err := e.DB.Get(&org, `SELECT organization_id::text FROM audit_events WHERE action='log_stream.create' AND actor_id=$1`, linkID); err != nil || org != e.Org {
		t.Fatalf("audit organization = %q %v", org, err)
	}
	var evKind string
	if err := e.DB.Get(&evKind, `SELECT actor_kind FROM events WHERE type='log_stream.created' AND organization_id=$1 AND actor_id=$2`, e.Org, linkID); err != nil || evKind != "setup_link" {
		t.Fatalf("log_stream.created actor kind = %q %v", evKind, err)
	}

	// Revoking the link ends the bearer.
	e.Must("DELETE", links+"/"+linkID, e.Owner, nil, 204)
	e.Must("GET", ls, bearer, nil, 401)
}
