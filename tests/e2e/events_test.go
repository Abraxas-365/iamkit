package e2e_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// eventTypes returns the types of an events page, in order.
func eventTypes(res Response) []string {
	items, _ := res.JSON["items"].([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(map[string]any)["type"].(string))
	}
	return out
}

// TestEvents: writes land in the event log in their own transaction with a
// resolved actor; the log reads newest first (before) or as a feed (after),
// filters by type family and subject, is served on /api/v1 only with
// iam:events:read, and is pruned past the retention.
func TestEvents(t *testing.T) {
	e := newEnv(t)
	all := e.Must("GET", e.Base+"/events?limit=200", e.Owner, nil, 200)
	types := eventTypes(all)
	for _, want := range []string{"organization.created", "application.created", "resource.created", "application.resource_linked", "user.created", "membership.created", "grant.updated"} {
		if !contains(types, want) {
			t.Fatalf("missing %s in %v", want, types)
		}
	}
	first := all.JSON["items"].([]any)[0].(map[string]any)
	if actor := first["actor"].(map[string]any); actor["kind"] != "operator" || actor["id"] == "" {
		t.Fatalf("actor = %v", actor)
	}

	// Family and subject filters.
	users := e.Must("GET", e.Base+"/events?type=user.*&subject="+e.Alice, e.Owner, nil, 200)
	if got := eventTypes(users); len(got) != 1 || got[0] != "user.created" {
		t.Fatalf("user events = %v", got)
	}
	data := users.JSON["items"].([]any)[0].(map[string]any)["data"].(map[string]any)
	if data["origin"] != "api" {
		t.Fatalf("user.created data = %v", data)
	}

	// Feed: after=0 reads oldest first; the cursor stays put when nothing is new.
	feed := e.Must("GET", e.Base+"/events?after=0&limit=2", e.Owner, nil, 200)
	items := feed.JSON["items"].([]any)
	next := int64(feed.JSON["next"].(float64))
	if len(items) != 2 || int64(items[1].(map[string]any)["id"].(float64)) != next || items[0].(map[string]any)["id"].(float64) > items[1].(map[string]any)["id"].(float64) {
		t.Fatalf("feed = %s", feed.Body)
	}
	newest := int64(all.JSON["items"].([]any)[0].(map[string]any)["id"].(float64))
	tail := e.Must("GET", fmt.Sprintf("%s/events?after=%d", e.Base, newest), e.Owner, nil, 200)
	if len(tail.JSON["items"].([]any)) != 0 || int64(tail.JSON["next"].(float64)) != newest {
		t.Fatalf("tail = %s", tail.Body)
	}

	// Newest-first pages chain through before.
	page := e.Must("GET", e.Base+"/events?limit=3", e.Owner, nil, 200)
	before := int64(page.JSON["next"].(float64))
	older := e.Must("GET", fmt.Sprintf("%s/events?limit=3&before=%d", e.Base, before), e.Owner, nil, 200)
	if o := older.JSON["items"].([]any); len(o) == 0 || int64(o[0].(map[string]any)["id"].(float64)) >= before {
		t.Fatalf("older = %s", older.Body)
	}

	e.Must("GET", e.Base+"/events?type=nope", e.Owner, nil, 400)
	e.Must("GET", e.Base+"/events?after=1&before=2", e.Owner, nil, 400)

	// Create and assignment routes name their subject and ids in data.
	role := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "auditor", "resource_id": e.Res, "permissions": []string{}})
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Auditors"})
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": role}, 204)
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "group_id": group, "role_id": role}, 204)
	for _, tc := range []struct{ typ, subject, key, value string }{
		{"role.created", role, "resource_id", e.Res},
		{"group.created", group, "organization_id", e.Org},
		{"role.assigned", e.Alice, "role_id", role},
		{"group_role.assigned", group, "role_id", role},
	} {
		items := e.Must("GET", e.Base+"/events?type="+tc.typ+"&subject="+tc.subject, e.Owner, nil, 200).JSON["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["data"].(map[string]any)[tc.key] != tc.value {
			t.Fatalf("%s of %s = %v", tc.typ, tc.subject, items)
		}
	}

	// A failed sign-in is an event of its own.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "wrong password!"), 401)
	if got := eventTypes(e.Must("GET", e.Base+"/events?type=login.failed", e.Owner, nil, 200)); len(got) != 1 {
		t.Fatalf("login.failed = %v", got)
	}
	e.Login(e.AliceEmail)
	sessions := e.Must("GET", e.Base+"/events?type=session.*&limit=1", e.Owner, nil, 200)
	if got := eventTypes(sessions); len(got) != 1 || got[0] != "session.created" {
		t.Fatalf("session events = %v", got)
	}
	created := sessions.JSON["items"].([]any)[0].(map[string]any)
	if created["subject"].(map[string]any)["kind"] != "session" || created["data"].(map[string]any)["user_id"] != e.Alice || created["actor"].(map[string]any)["id"] != e.Alice {
		t.Fatalf("session.created = %v", created)
	}

	// /api/v1 needs iam:events:read; the service account is the actor of its writes.
	api := "/api/v1/environments/" + e.EnvID + "/events"
	e.Must("GET", api, e.scopedToken("iam:users:read"), nil, 403)
	token := e.scopedToken("iam:events:read", "iam:orgs:write")
	e.Must("GET", api, token, nil, 200)
	e.Must("POST", "/api/v1/environments/"+e.EnvID+"/organizations", token, fiber.Map{"name": "Globex"}, 201)
	orgs := e.Must("GET", api+"?type=organization.created&limit=1", token, nil, 200)
	if actor := orgs.JSON["items"].([]any)[0].(map[string]any)["actor"].(map[string]any); actor["kind"] != "service_account" {
		t.Fatalf("api actor = %v", actor)
	}

	// Retention: events older than the retention are pruned by the worker.
	e.DB.MustExec(`UPDATE events SET created_at = now() - interval '100 days' WHERE environment_id=$1 AND type='organization.created'`, e.EnvID)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "event_prune"); !found || err != nil {
		t.Fatalf("prune: %v %v", found, err)
	}
	if got := eventTypes(e.Must("GET", e.Base+"/events?type=organization.*", e.Owner, nil, 200)); len(got) != 0 {
		t.Fatalf("pruned events remain: %v", got)
	}
}
