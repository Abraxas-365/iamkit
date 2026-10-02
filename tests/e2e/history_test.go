package e2e_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestChangeHistory: updates carry data.changes {field: [old, new]} (no
// secrets, metadata per key), each entity serves its history, /api/v1
// needs iam:events:read, and the log exports as NDJSON.
func TestChangeHistory(t *testing.T) {
	e := newEnv(t)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"name": "Alice Liddell", "metadata": map[string]any{"plan": "pro"}}, 204)

	history := e.Must("GET", e.Base+"/users/"+e.Alice+"/history", e.Owner, nil, 200)
	items := history.JSON["items"].([]any)
	var changes map[string]any
	for _, it := range items {
		ev := it.(map[string]any)
		if ev["subject"].(map[string]any)["id"] != e.Alice {
			t.Fatalf("foreign event in history: %v", ev)
		}
		if data, _ := ev["data"].(map[string]any); ev["type"] == "user.updated" && data["changes"] != nil {
			changes = data["changes"].(map[string]any)
		}
		if strings.Contains(fmt.Sprint(ev["data"]), "password_hash") {
			t.Fatalf("secret in history: %v", ev)
		}
	}
	if fmt.Sprint(changes["name"]) != "[Alice Alice Liddell]" {
		t.Fatalf("changes = %v (history %s)", changes, history.Body)
	}
	if fmt.Sprint(changes["metadata.plan"]) != "[<nil> pro]" {
		t.Fatalf("metadata changes = %v", changes)
	}
	if got := eventTypes(history); got[len(got)-1] != "user.created" {
		t.Fatalf("history types = %v", got)
	}

	// Applications and roles too.
	e.Must("PATCH", e.Base+"/applications/"+e.Client, e.Owner, fiber.Map{"name": "web app"}, 204)
	app := e.Must("GET", e.Base+"/applications/"+e.Client+"/history?type=application.updated", e.Owner, nil, 200)
	if got := app.JSON["items"].([]any); len(got) != 1 || fmt.Sprint(got[0].(map[string]any)["data"].(map[string]any)["changes"]) != "map[name:[web web app]]" {
		t.Fatalf("application history = %s", app.Body)
	}
	e.Must("GET", e.Base+"/users/"+e.Alice+"/history?after=0", e.Owner, nil, 400)

	// /api/v1 reads history with the entity's read permission and iam:events:read.
	api := "/api/v1/environments/" + e.EnvID
	e.Must("GET", api+"/users/"+e.Alice+"/history", e.scopedToken("iam:users:read"), nil, 403)
	e.Must("GET", api+"/applications/"+e.Client+"/history", e.scopedToken("iam:events:read"), nil, 403)
	e.Must("GET", api+"/users/"+e.Alice+"/history", e.scopedToken("iam:events:read", "iam:users:read"), nil, 200)
	e.Must("GET", api+"/applications/"+e.Client+"/history", e.scopedToken("iam:events:read", "iam:apps:read"), nil, 200)

	// Export: NDJSON, oldest first, every event.
	export := e.Do("GET", e.Base+"/events/export?type=user.*", e.Owner, nil)
	if export.Status != 200 {
		t.Fatalf("export = %d %s", export.Status, export.Body)
	}
	var ids []float64
	scanner := bufio.NewScanner(strings.NewReader(export.Body))
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("export line %q: %v", scanner.Text(), err)
		}
		if !strings.HasPrefix(ev["type"].(string), "user.") {
			t.Fatalf("export ignored the filter: %v", ev)
		}
		ids = append(ids, ev["id"].(float64))
	}
	if len(ids) != 2 || ids[0] > ids[1] {
		t.Fatalf("export ids = %v", ids)
	}
	e.Must("GET", e.Base+"/events/export?before=5", e.Owner, nil, 400)
	e.Must("GET", api+"/events/export", e.scopedToken("iam:events:read"), nil, 200)
}
