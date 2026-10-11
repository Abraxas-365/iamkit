package e2e_test

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// emitAuditEvent posts an event to <base>/events (base ends in /audit-logs) with an optional Idempotency-Key.
func (e *Env) emitAuditEvent(base, token, key string, body fiber.Map) Response {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", base+"/events", strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(token, "ik_") && !strings.HasPrefix(token, "ik_svc_") {
		r.Header.Set("X-API-Key", token)
	} else {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	res, err := e.App.Test(r, 10000)
	if err != nil && strings.Contains(err.Error(), "body size exceeds") {
		// Fiber's global body limit (the same 64 KiB) answers 413 on a
		// real connection; App.Test reports it as an error instead.
		return Response{Status: 413}
	}
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var buf strings.Builder
	sc := bufio.NewReader(res.Body)
	for {
		line, err := sc.ReadString('\n')
		buf.WriteString(line)
		if err != nil {
			break
		}
	}
	out := Response{Status: res.StatusCode, Body: buf.String()}
	_ = json.Unmarshal([]byte(out.Body), &out.JSON)
	return out
}

func auditIDs(res Response) []string {
	items, _ := res.JSON["items"].([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(map[string]any)["id"].(string))
	}
	return out
}

// TestAuditLog: actions with schemas, event ingest rules, idempotency,
// reads with filters and cursors, exports, immutability, pruning and the
// /api/v1 permissions.
func TestAuditLog(t *testing.T) {
	e := newEnv(t)
	logs := e.Base + "/audit-logs"
	api := "/api/v1/environments/" + e.EnvID + "/audit-logs"
	now := time.Now().UTC()
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339Nano) }
	event := func(mutate func(fiber.Map)) fiber.Map {
		body := fiber.Map{"organization_id": e.Org, "action": "invoice.paid", "occurred_at": at(time.Minute),
			"actor":    fiber.Map{"type": "user", "id": "u-ana", "name": "=SUM(1)", "metadata": fiber.Map{"role": "admin"}},
			"targets":  []fiber.Map{{"type": "invoice", "id": "inv-1", "name": "=HYPERLINK(\"x\")"}},
			"context":  fiber.Map{"location": "PE", "user_agent": "curl/8"},
			"metadata": fiber.Map{"amount": 10, "currency": "USD"}}
		if mutate != nil {
			mutate(body)
		}
		return body
	}

	// Without a registered action nothing is accepted.
	r := e.emitAuditEvent(logs, e.Owner, "", event(nil))
	if r.Status != 422 || !strings.Contains(r.Body, "UNKNOWN_AUDIT_ACTION") {
		t.Fatalf("unregistered action = %d %s", r.Status, r.Body)
	}

	// Register actions; invalid ones are refused.
	e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "Invoice"}, 400)
	e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "invoice.paid", "schema": fiber.Map{"metadata": fiber.Map{"$ref": "https://example.com/s.json"}}}, 400)
	schema := fiber.Map{"metadata": fiber.Map{"type": "object", "required": []string{"amount"},
		"properties": fiber.Map{"amount": fiber.Map{"type": "number", "minimum": 0}}},
		"actor": fiber.Map{"type": "object", "required": []string{"role"}}}
	action := e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "invoice.paid", "description": "An invoice was paid",
		"target_types": []string{"invoice"}, "schema": schema}, 201).JSON
	actionID := action["id"].(string)
	if action["version"] != float64(1) {
		t.Fatalf("action = %v", action)
	}
	e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "invoice.paid"}, 409)
	e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "invoice.refunded", "target_types": []string{"invoice"}}, 201)
	if n := len(e.Must("GET", logs+"/actions", e.Owner, nil, 200).JSON["items"].([]any)); n != 2 {
		t.Fatalf("actions = %d", n)
	}
	e.Must("GET", logs+"/actions/"+actionID, e.Owner, nil, 200)
	e.Must("GET", logs+"/actions/not-a-uuid", e.Owner, nil, 404)

	// Valid event; the receipt carries id and created_at; version defaults to current.
	first := e.emitAuditEvent(logs, e.Owner, "", event(nil))
	if first.Status != 201 || first.JSON["id"] == nil || first.JSON["created_at"] == nil {
		t.Fatalf("first event = %d %s", first.Status, first.Body)
	}
	got := e.Must("GET", logs+"/events/"+first.JSON["id"].(string), e.Owner, nil, 200).JSON
	if got["action"] != "invoice.paid" || got["version"] != float64(1) || got["organization_id"] != e.Org ||
		got["actor"].(map[string]any)["id"] != "u-ana" || got["context"].(map[string]any)["location"] != "PE" ||
		got["metadata"].(map[string]any)["currency"] != "USD" || len(got["targets"].([]any)) != 1 {
		t.Fatalf("stored event = %v", got)
	}

	// Refusals.
	refused := map[string]struct {
		mutate func(fiber.Map)
		status int
		code   string
	}{
		"schema violation": {func(b fiber.Map) { b["metadata"] = fiber.Map{"amount": "ten"} }, 422, "AUDIT_SCHEMA_VIOLATION"},
		"missing metadata": {func(b fiber.Map) { delete(b, "metadata") }, 422, "AUDIT_SCHEMA_VIOLATION"},
		"actor schema":     {func(b fiber.Map) { b["actor"] = fiber.Map{"type": "user", "id": "x"} }, 422, "AUDIT_SCHEMA_VIOLATION"},
		"unknown action":   {func(b fiber.Map) { b["action"] = "invoice.voided" }, 422, "UNKNOWN_AUDIT_ACTION"},
		"bad target type":  {func(b fiber.Map) { b["targets"] = []fiber.Map{{"type": "order", "id": "o1"}} }, 422, "AUDIT_TARGET_TYPE"},
		"unknown org":      {func(b fiber.Map) { b["organization_id"] = "00000000-0000-4000-8000-000000000001" }, 422, "UNKNOWN_ORGANIZATION"},
		"stale version":    {func(b fiber.Map) { b["version"] = 7 }, 422, "AUDIT_ACTION_VERSION"},
		"future":           {func(b fiber.Map) { b["occurred_at"] = now.Add(time.Hour).Format(time.RFC3339) }, 400, "VALIDATION"},
		"too old":          {func(b fiber.Map) { b["occurred_at"] = now.Add(-5 * 366 * 24 * time.Hour).Format(time.RFC3339) }, 400, "VALIDATION"},
		"nested metadata":  {func(b fiber.Map) { b["metadata"] = fiber.Map{"amount": 1, "x": fiber.Map{"y": 1}} }, 400, "VALIDATION"},
		"no actor id":      {func(b fiber.Map) { b["actor"] = fiber.Map{"type": "user", "metadata": fiber.Map{"role": "a"}} }, 400, "VALIDATION"},
	}
	for name, tc := range refused {
		res := e.emitAuditEvent(logs, e.Owner, "", event(tc.mutate))
		if res.Status != tc.status || !strings.Contains(res.Body, tc.code) {
			t.Errorf("%s = %d %s", name, res.Status, res.Body)
		}
	}
	big := event(func(b fiber.Map) { b["context"] = fiber.Map{"location": strings.Repeat("x", 70<<10)} })
	if res := e.emitAuditEvent(logs, e.Owner, "", big); res.Status != 413 {
		t.Errorf("oversized body = %d", res.Status)
	}
	var count int
	if err := e.DB.Get(&count, `SELECT count(*) FROM audit_log_events WHERE environment_id=$1`, e.EnvID); err != nil || count != 1 {
		t.Fatalf("stored events = %d (%v)", count, err)
	}

	// IAMKit's own log never receives the app events.
	var leaked int
	if err := e.DB.Get(&leaked, `SELECT count(*) FROM events WHERE environment_id=$1 AND type LIKE 'audit_log%' AND type NOT LIKE 'audit_log_action.%'`, e.EnvID); err != nil || leaked != 0 {
		t.Fatalf("app events in the IAMKit log: %d %v", leaked, err)
	}
	if got := eventTypes(e.Must("GET", e.Base+"/events?type=audit_log_action.*", e.Owner, nil, 200)); len(got) != 2 {
		t.Fatalf("action mutations in the event log = %v", got)
	}

	// Idempotency: replay → the original receipt, no second row; another body → 409.
	body := event(func(b fiber.Map) { b["metadata"] = fiber.Map{"amount": 20}; b["occurred_at"] = at(2 * time.Minute) })
	created := e.emitAuditEvent(logs, e.Owner, "pay-20", body)
	if created.Status != 201 {
		t.Fatalf("keyed event = %d %s", created.Status, created.Body)
	}
	replay := e.emitAuditEvent(logs, e.Owner, "pay-20", body)
	if replay.Status != 201 || replay.JSON["id"] != created.JSON["id"] || replay.JSON["created_at"] != created.JSON["created_at"] {
		t.Fatalf("replay = %d %s (first %s)", replay.Status, replay.Body, created.Body)
	}
	changed := event(func(b fiber.Map) { b["metadata"] = fiber.Map{"amount": 21}; b["occurred_at"] = at(2 * time.Minute) })
	if res := e.emitAuditEvent(logs, e.Owner, "pay-20", changed); res.Status != 409 || !strings.Contains(res.Body, "IDEMPOTENCY_KEY_REUSED") {
		t.Fatalf("reused key = %d %s", res.Status, res.Body)
	}
	if res := e.emitAuditEvent(logs, e.Owner, strings.Repeat("k", 256), body); res.Status != 400 {
		t.Fatalf("long key = %d", res.Status)
	}
	if err := e.DB.Get(&count, `SELECT count(*) FROM audit_log_events WHERE environment_id=$1`, e.EnvID); err != nil || count != 2 {
		t.Fatalf("events after replay = %d (%v)", count, err)
	}
	// Concurrent first uses of one key create one event.
	racing := event(func(b fiber.Map) { b["metadata"] = fiber.Map{"amount": 30}; b["occurred_at"] = at(3 * time.Minute) })
	results := make(chan Response, 4)
	for range 4 {
		go func() { results <- e.emitAuditEvent(logs, e.Owner, "race", racing) }()
	}
	ids := map[any]bool{}
	for range 4 {
		res := <-results
		if res.Status != 201 {
			t.Fatalf("racing = %d %s", res.Status, res.Body)
		}
		ids[res.JSON["id"]] = true
	}
	if len(ids) != 1 {
		t.Fatalf("racing keys made %d events", len(ids))
	}

	// A schema edit bumps the version; a description edit does not. Old events keep theirs.
	e.Must("PATCH", logs+"/actions/"+actionID, e.Owner, fiber.Map{"description": "Paid"}, 200)
	if v := e.Must("GET", logs+"/actions/"+actionID, e.Owner, nil, 200).JSON["version"]; v != float64(1) {
		t.Fatalf("version after description = %v", v)
	}
	schema["metadata"] = fiber.Map{"type": "object", "required": []string{"amount", "currency"}}
	if v := e.Must("PATCH", logs+"/actions/"+actionID, e.Owner, fiber.Map{"schema": schema}, 200).JSON["version"]; v != float64(2) {
		t.Fatalf("version after schema = %v", v)
	}
	e.Must("PATCH", logs+"/actions/"+actionID, e.Owner, fiber.Map{"schema": fiber.Map{"targets": fiber.Map{"order": fiber.Map{}}}}, 400)
	one := 1
	if res := e.emitAuditEvent(logs, e.Owner, "", event(func(b fiber.Map) { b["version"] = one })); res.Status != 422 || !strings.Contains(res.Body, "AUDIT_ACTION_VERSION") {
		t.Fatalf("old version = %d %s", res.Status, res.Body)
	}
	if res := e.emitAuditEvent(logs, e.Owner, "", event(func(b fiber.Map) { b["metadata"] = fiber.Map{"amount": 1} })); res.Status != 422 {
		t.Fatalf("new schema not applied = %d %s", res.Status, res.Body)
	}
	v2 := e.emitAuditEvent(logs, e.Owner, "", event(func(b fiber.Map) { b["version"] = 2; b["occurred_at"] = at(4 * time.Minute) }))
	if v2.Status != 201 {
		t.Fatalf("v2 event = %d %s", v2.Status, v2.Body)
	}
	if v := e.Must("GET", logs+"/events/"+v2.JSON["id"].(string), e.Owner, nil, 200).JSON["version"]; v != float64(2) {
		t.Fatalf("stored version = %v", v)
	}
	if v := e.Must("GET", logs+"/events/"+first.JSON["id"].(string), e.Owner, nil, 200).JSON["version"]; v != float64(1) {
		t.Fatalf("old event version = %v", v)
	}

	// A second organization, another actor and target type, for the filters.
	org2 := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.Must("PATCH", logs+"/actions/"+e.Must("GET", logs+"/actions", e.Owner, nil, 200).JSON["items"].([]any)[1].(map[string]any)["id"].(string), e.Owner, fiber.Map{"target_types": []string{"invoice", "customer"}}, 200)
	refund := e.emitAuditEvent(logs, e.Owner, "", fiber.Map{"organization_id": org2, "action": "invoice.refunded", "occurred_at": at(10 * time.Minute),
		"actor":   fiber.Map{"type": "service", "id": "billing"},
		"targets": []fiber.Map{{"type": "customer", "id": "c-9"}, {"type": "invoice", "id": "inv-9"}}})
	if refund.Status != 201 {
		t.Fatalf("refund = %d %s", refund.Status, refund.Body)
	}

	// Reads: newest first, filters, cursors.
	all := e.Must("GET", logs+"/events", e.Owner, nil, 200)
	if n := len(auditIDs(all)); n != 5 {
		t.Fatalf("events = %d: %s", n, all.Body)
	}
	if all.JSON["items"].([]any)[0].(map[string]any)["id"] != refund.JSON["id"] {
		t.Fatalf("not newest first: %s", all.Body)
	}
	count5 := func(query string, want int) Response {
		t.Helper()
		res := e.Must("GET", logs+"/events?"+query, e.Owner, nil, 200)
		if n := len(auditIDs(res)); n != want {
			t.Fatalf("%s: %d events, want %d: %s", query, n, want, res.Body)
		}
		return res
	}
	count5("organization_id="+org2, 1)
	count5("organization_id="+e.Org, 4)
	count5("action=invoice.refunded", 1)
	count5("action=invoice.refunded&action=invoice.paid", 5)
	count5("action=invoice.refunded,invoice.paid", 5)
	count5("actor_id=u-ana", 4)
	count5("actor_type=service", 1)
	count5("actor_id=billing&actor_type=service", 1)
	count5("actor_id=billing&actor_type=user", 0)
	count5("target_id=inv-1", 4)
	count5("target_type=customer", 1)
	count5("target_type=customer&target_id=inv-9", 0) // both on the same target
	count5("target_type=invoice&target_id=inv-9", 1)
	count5("occurred_after="+now.Add(-150*time.Second).Format(time.RFC3339), 2)
	count5("occurred_before="+now.Add(-5*time.Minute).Format(time.RFC3339), 1)
	e.Must("GET", logs+"/events?organization_id=nope", e.Owner, nil, 400)
	e.Must("GET", logs+"/events?occurred_after=yesterday", e.Owner, nil, 400)
	e.Must("GET", logs+"/events?after=1&before=2", e.Owner, nil, 400)
	e.Must("GET", logs+"/events?action=Bad", e.Owner, nil, 400)

	page1 := e.Must("GET", logs+"/events?limit=2", e.Owner, nil, 200)
	next := int64(page1.JSON["next"].(float64))
	page2 := e.Must("GET", fmt.Sprintf("%s/events?limit=2&before=%d", logs, next), e.Owner, nil, 200)
	page3 := e.Must("GET", fmt.Sprintf("%s/events?limit=2&before=%d", logs, int64(page2.JSON["next"].(float64))), e.Owner, nil, 200)
	chained := append(append(auditIDs(page1), auditIDs(page2)...), auditIDs(page3)...)
	if fmt.Sprint(chained) != fmt.Sprint(auditIDs(all)) || page3.JSON["next"] != float64(0) {
		t.Fatalf("cursor pages %v != %v (last next %v)", chained, auditIDs(all), page3.JSON["next"])
	}
	feed := e.Must("GET", logs+"/events?after=0&limit=2", e.Owner, nil, 200)
	ascending := auditIDs(feed)
	if len(ascending) != 2 || ascending[0] != auditIDs(all)[4] {
		t.Fatalf("feed = %s", feed.Body)
	}
	tail := e.Must("GET", fmt.Sprintf("%s/events?after=%d", logs, int64(all.JSON["items"].([]any)[0].(map[string]any)["seq"].(float64))), e.Owner, nil, 200)
	if len(auditIDs(tail)) != 0 {
		t.Fatalf("tail = %s", tail.Body)
	}
	e.Must("GET", logs+"/events/"+first.JSON["id"].(string)[:30], e.Owner, nil, 404)
	e.Must("GET", logs+"/events/00000000-0000-4000-8000-000000000001", e.Owner, nil, 404)

	// Exports: NDJSON and CSV, oldest first, formula-safe, filtered.
	nd := e.Do("GET", logs+"/events/export?organization_id="+e.Org, e.Owner, nil)
	if nd.Status != 200 {
		t.Fatalf("ndjson = %d %s", nd.Status, nd.Body)
	}
	var lines []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(nd.Body), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("ndjson line %q: %v", line, err)
		}
		lines = append(lines, ev)
	}
	if len(lines) != 4 || lines[0]["id"] != first.JSON["id"] || lines[0]["seq"].(float64) > lines[1]["seq"].(float64) {
		t.Fatalf("ndjson = %s", nd.Body)
	}
	cs := e.Do("GET", logs+"/events/export?format=csv", e.Owner, nil)
	if cs.Status != 200 {
		t.Fatalf("csv = %d %s", cs.Status, cs.Body)
	}
	rows, err := csv.NewReader(strings.NewReader(cs.Body)).ReadAll()
	if err != nil || len(rows) != 6 {
		t.Fatalf("csv rows = %d %v\n%s", len(rows), err, cs.Body)
	}
	if strings.Join(rows[0], ",") != "id,occurred_at,organization_id,action,version,actor_type,actor_id,actor_name,targets,location,user_agent,metadata" {
		t.Fatalf("csv header = %v", rows[0])
	}
	if rows[1][0] != first.JSON["id"] || rows[1][3] != "invoice.paid" || rows[1][6] != "u-ana" || rows[1][9] != "PE" {
		t.Fatalf("csv row = %v", rows[1])
	}
	if rows[1][7] != "'=SUM(1)" {
		t.Fatalf("actor name cell not guarded: %q", rows[1][7])
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Fatalf("formula cell %q", cell)
			}
		}
	}
	e.Must("GET", logs+"/events/export?format=xml", e.Owner, nil, 400)
	e.Must("GET", logs+"/events/export?before=5", e.Owner, nil, 400)

	// Immutable: no update or delete route, and the database refuses it too.
	id := first.JSON["id"].(string)
	for _, method := range []string{"PUT", "PATCH", "DELETE"} {
		if res := e.Do(method, logs+"/events/"+id, e.Owner, fiber.Map{"action": "x.y"}); res.Status != 404 && res.Status != 405 {
			t.Fatalf("%s event = %d", method, res.Status)
		}
	}
	if _, err := e.DB.Exec(`UPDATE audit_log_events SET action='x.y' WHERE id=$1`, id); err == nil {
		t.Fatal("event updated")
	}
	if _, err := e.DB.Exec(`DELETE FROM audit_log_events WHERE id=$1`, id); err == nil {
		t.Fatal("event deleted outside the prune job")
	}

	// Deleting an action keeps its events.
	e.Must("DELETE", logs+"/actions/"+actionID, e.Owner, nil, 204)
	e.Must("GET", logs+"/actions/"+actionID, e.Owner, nil, 404)
	e.Must("DELETE", logs+"/actions/"+actionID, e.Owner, nil, 404)
	if e.Must("GET", logs+"/events/"+id, e.Owner, nil, 200).JSON["action"] != "invoice.paid" {
		t.Fatal("event lost its action name")
	}
	if res := e.emitAuditEvent(logs, e.Owner, "", event(nil)); res.Status != 422 || !strings.Contains(res.Body, "UNKNOWN_AUDIT_ACTION") {
		t.Fatalf("deleted action = %d %s", res.Status, res.Body)
	}
	// An idempotent replay still answers after the action is gone.
	if res := e.emitAuditEvent(logs, e.Owner, "pay-20", body); res.Status != 201 || res.JSON["id"] != created.JSON["id"] {
		t.Fatalf("replay after delete = %d %s", res.Status, res.Body)
	}
	e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "invoice.paid", "target_types": []string{"invoice"}}, 201)

	// /api/v1: read, write (emit) and manage (actions) are separate permissions.
	reader := e.scopedToken("iam:audit-logs:read")
	writer := e.scopedToken("iam:audit-logs:write")
	manager := e.scopedToken("iam:audit-logs:manage")
	e.Must("GET", api+"/events", reader, nil, 200)
	e.Must("GET", api+"/events/export?format=csv", reader, nil, 200)
	e.Must("GET", api+"/actions", reader, nil, 200)
	e.Must("GET", api+"/events", e.scopedToken("iam:users:read"), nil, 403)
	e.Must("GET", api+"/events", writer, nil, 403)
	e.Must("GET", api+"/actions", manager, nil, 403)
	if res := e.emitAuditEvent(api, reader, "", event(nil)); res.Status != 403 {
		t.Fatalf("emit with read = %d %s", res.Status, res.Body)
	}
	if res := e.emitAuditEvent(api, manager, "", event(nil)); res.Status != 403 {
		t.Fatalf("emit with manage = %d", res.Status)
	}
	if res := e.emitAuditEvent(api, writer, "", event(nil)); res.Status != 201 {
		t.Fatalf("emit with write = %d %s", res.Status, res.Body)
	}
	e.Must("POST", api+"/actions", reader, fiber.Map{"name": "order.placed"}, 403)
	e.Must("POST", api+"/actions", writer, fiber.Map{"name": "order.placed"}, 403)
	placed := e.Must("POST", api+"/actions", manager, fiber.Map{"name": "order.placed"}, 201).JSON["id"].(string)
	e.Must("PATCH", api+"/actions/"+placed, reader, fiber.Map{"description": "x"}, 403)
	e.Must("PATCH", api+"/actions/"+placed, manager, fiber.Map{"description": "x"}, 200)
	e.Must("DELETE", api+"/actions/"+placed, writer, nil, 403)
	e.Must("DELETE", api+"/actions/"+placed, manager, nil, 204)
	// The service account is the actor of the action's audit entry.
	if got := eventTypes(e.Must("GET", e.Base+"/events?type=audit_log_action.*&limit=1", e.Owner, nil, 200)); len(got) != 1 {
		t.Fatalf("api action events = %v", got)
	}
	// Retention: the prune job removes events past it, only those.
	// The trigger refuses every UPDATE, so age two rows with it off.
	tx := e.DB.MustBegin()
	tx.MustExec(`ALTER TABLE audit_log_events DISABLE TRIGGER refuse_audit_log_change`)
	tx.MustExec(`UPDATE audit_log_events SET created_at = now() - interval '400 days' WHERE id=$1 OR id=$2`, first.JSON["id"], refund.JSON["id"])
	tx.MustExec(`ALTER TABLE audit_log_events ENABLE TRIGGER refuse_audit_log_change`)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if found, err := e.Server.Workers.RunOnce(context.Background(), "audit_log_prune"); !found || err != nil {
		t.Fatalf("prune: %v %v", found, err)
	}
	e.Must("GET", logs+"/events/"+first.JSON["id"].(string), e.Owner, nil, 404)
	e.Must("GET", logs+"/events/"+refund.JSON["id"].(string), e.Owner, nil, 404)
	e.Must("GET", logs+"/events/"+created.JSON["id"].(string), e.Owner, nil, 200)
}

// TestAuditLogUsageLimit: audit_events_per_minute refuses ingest with 429
// once the window is full, and accepted events count in the usage report.
func TestAuditLogUsageLimit(t *testing.T) {
	e := newEnv(t)
	logs := e.Base + "/audit-logs"
	e.Must("POST", logs+"/actions", e.Owner, fiber.Map{"name": "login.succeeded"}, 201)
	e.Must("PUT", e.Base+"/limits", e.Owner, fiber.Map{"audit_events_per_minute": 2}, 200)
	emit := func(n int) Response {
		return e.emitAuditEvent(logs, e.Owner, "", fiber.Map{"organization_id": e.Org, "action": "login.succeeded",
			"occurred_at": time.Now().UTC().Add(-time.Duration(n) * time.Second).Format(time.RFC3339Nano),
			"actor":       fiber.Map{"type": "user", "id": "u"}})
	}
	e.Must("GET", logs+"/events", e.Owner, nil, 200)
	for n := 1; n <= 2; n++ {
		if res := emit(n); res.Status != 201 {
			t.Fatalf("event %d = %d %s", n, res.Status, res.Body)
		}
	}
	res := emit(3)
	if res.Status != 429 || !strings.Contains(res.Body, "QUOTA_EXCEEDED") {
		t.Fatalf("third event = %d %s", res.Status, res.Body)
	}
	if n := len(auditIDs(e.Must("GET", logs+"/events", e.Owner, nil, 200))); n != 2 {
		t.Fatalf("stored events = %d", n)
	}
	// Reading is not metered; lifting the limit admits again.
	e.Must("PUT", e.Base+"/limits", e.Owner, fiber.Map{}, 200)
	if res := emit(4); res.Status != 201 {
		t.Fatalf("after lifting = %d %s", res.Status, res.Body)
	}
	if err := e.Server.FlushUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	var counted int64
	if err := e.DB.Get(&counted, `SELECT COALESCE(sum(count),0) FROM usage_daily WHERE environment_id=$1 AND metric='audit_events'`, e.EnvID); err != nil || counted != 3 {
		t.Fatalf("audit_events usage = %d (%v)", counted, err)
	}
}
