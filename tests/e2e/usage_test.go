package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/gofiber/fiber/v2"
)

// TestUsageLimits: deployment caps with environment limits that only
// tighten them, refused creates (422) and API requests (429), daily usage
// from the event rollup and the flushed in-memory counters.
func TestUsageLimits(t *testing.T) {
	deployment, err := usage.ParseDeployment("organizations_max=2,requests_per_minute=1000")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, bootstrap.WithLimits(deployment))
	limits := e.Base + "/limits"

	got := e.Must("GET", limits, e.Owner, nil, 200).JSON
	if got["effective"].(map[string]any)["organizations_max"] != float64(2) || len(got["environment"].(map[string]any)) != 0 {
		t.Fatalf("limits = %v", got)
	}

	// newEnv made one organization; the second fits, the third is refused.
	e.Must("POST", e.Base+"/organizations", e.Owner, fiber.Map{"name": "Two"}, 201)
	refused := e.Must("POST", e.Base+"/organizations", e.Owner, fiber.Map{"name": "Three"}, 422).JSON
	if !quota(refused) {
		t.Fatalf("refusal = %v", refused)
	}

	// Only owners change limits; unknown names and negatives are refused.
	admin := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "admin@example.com", "role": "admin"}, 201).JSON["secret"].(string)
	e.Must("PUT", limits, admin, fiber.Map{"users_max": 5}, 403)
	e.Must("PUT", limits, e.Owner, fiber.Map{"nope": 5}, 400)
	e.Must("PUT", limits, e.Owner, fiber.Map{"users_max": -1}, 400)

	// An environment limit above the deployment cap does not loosen it.
	set := e.Must("PUT", limits, e.Owner, fiber.Map{"organizations_max": 10, "users_max": 2, "requests_per_minute": 3, "sms_per_day": nil}, 200).JSON
	effective := set["effective"].(map[string]any)
	if effective["organizations_max"] != float64(2) || effective["users_max"] != float64(2) || effective["requests_per_minute"] != float64(3) || set["updated_at"] == nil {
		t.Fatalf("set = %v", set)
	}
	if _, ok := effective["sms_per_day"]; ok {
		t.Fatalf("null limited sms: %v", set)
	}
	if n := len(eventTypes(e.Must("GET", e.Base+"/events?type=limits.updated", e.Owner, nil, 200))); n != 1 {
		t.Fatalf("limits.updated events = %d", n)
	}

	// Users: alice exists, one more fits, signups and SCIM-like creates stop.
	e.User("Bob", "bob@example.com")
	if r := e.Do("POST", e.Base+"/users", e.Owner, fiber.Map{"name": "Carol", "email": "carol@example.com", "password": e.Pass}); r.Status != 422 || !quota(r.JSON) {
		t.Fatalf("third user = %d %s", r.Status, r.Body)
	}

	// requests_per_minute bounds /api/v1 per environment.
	token := e.scopedToken("iam:users:read", "iam:usage:read")
	api := "/api/v1/environments/" + e.EnvID
	for range 3 {
		e.Must("GET", api+"/users", token, nil, 200)
	}
	if r := e.Do("GET", api+"/users", token, nil); r.Status != 429 || !quota(r.JSON) {
		t.Fatalf("fourth request = %d %s", r.Status, r.Body)
	}
	e.Must("PUT", limits, e.Owner, fiber.Map{"users_max": 2}, 200)

	// Sign-ins roll up from the event log; tokens are flushed counters.
	e.Login(e.AliceEmail)
	e.DB.MustExec(`UPDATE events SET created_at = created_at - interval '2 minutes' WHERE environment_id=$1`, e.EnvID)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "usage_rollup"); !found || err != nil {
		t.Fatalf("rollup = %v %v", found, err)
	}
	if err := e.Server.FlushUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	report := e.Must("GET", e.Base+"/usage?days=7", e.Owner, nil, 200).JSON
	days := report["days"].([]any)
	if len(days) != 7 || days[6].(map[string]any)["day"] != time.Now().UTC().Format(time.DateOnly) {
		t.Fatalf("days = %v", days)
	}
	totals := report["totals"].(map[string]any)
	if totals["logins"] != float64(1) || totals["users_created"] != float64(2) || totals["tokens"].(float64) < 2 || totals["api_requests"].(float64) < 3 {
		t.Fatalf("totals = %v", totals)
	}
	now := report["now"].([]any)
	if users := now[0].(map[string]any); users["name"] != "users_max" || users["count"] != float64(2) || users["max"] != float64(2) {
		t.Fatalf("now = %v", now)
	}
	// A second rollup counts nothing twice.
	if _, err := e.Server.Workers.RunOnce(context.Background(), "usage_rollup"); err != nil {
		t.Fatal(err)
	}
	again := e.Must("GET", e.Base+"/usage?days=7", e.Owner, nil, 200).JSON["totals"].(map[string]any)
	if again["logins"] != float64(1) {
		t.Fatalf("rolled up twice: %v", again)
	}
	e.Must("GET", e.Base+"/usage?days=0", e.Owner, nil, 400)

	// /api/v1 reads usage with iam:usage:read only.
	e.Must("PUT", limits, e.Owner, fiber.Map{}, 200)
	e.Must("GET", api+"/usage", token, nil, 200)
	e.Must("GET", api+"/usage", e.scopedToken("iam:users:read"), nil, 403)
}

// quota reports a QUOTA_EXCEEDED error body.
func quota(body map[string]any) bool {
	e, _ := body["error"].(map[string]any)
	return e["code"] == "QUOTA_EXCEEDED"
}
