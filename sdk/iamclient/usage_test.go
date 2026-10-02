package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUsageEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/usage") {
			w.Write([]byte(`{"days":[{"day":"2026-10-01","metrics":{"logins":3}}],"totals":{"logins":3},"now":[{"name":"users_max","count":2,"max":null}]}`))
			return
		}
		w.Write([]byte(`{"deployment":{"users_max":100},"environment":{"users_max":50},"effective":{"users_max":50}}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	limits, err := env.Limits(ctx)
	if err != nil || limits.Effective[LimitUsers] != 50 || limits.Deployment[LimitUsers] != 100 {
		t.Fatalf("limits = %+v %v", limits, err)
	}
	if _, err := env.SetLimits(ctx, map[string]int64{LimitUsers: 50}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.SetLimits(ctx, nil); err != nil {
		t.Fatal(err)
	}
	usage, err := env.Usage(ctx, 7)
	if err != nil || len(usage.Days) != 1 || usage.Totals["logins"] != 3 || usage.Now[0].Max != nil {
		t.Fatalf("usage = %+v %v", usage, err)
	}
	if _, err := env.Usage(ctx, 0); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /management/v1/environments/env-1/limits",
		"PUT /management/v1/environments/env-1/limits",
		"PUT /management/v1/environments/env-1/limits",
		"GET /management/v1/environments/env-1/usage?days=7",
		"GET /management/v1/environments/env-1/usage",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
	if bodies[1] != `{"users_max":50}` || bodies[2] != `{}` {
		t.Fatalf("bodies = %q", bodies)
	}
}
