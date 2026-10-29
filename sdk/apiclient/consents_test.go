package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserConnectedApps(t *testing.T) {
	var calls []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"items":[{"client":{"id":"c1","name":"Claude"},"resource":"https://mcp.example/mcp","scopes":["notes:read"],"active_sessions":1}]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer remote.Close()
	env := New(remote.URL, "tok").Environment("env")
	ctx := context.Background()
	apps, err := env.UserConnectedApps(ctx, "u1", "")
	if err != nil || len(apps) != 1 || apps[0].Client.ID != "c1" || apps[0].ActiveSessions != 1 {
		t.Fatalf("apps = %+v %v", apps, err)
	}
	if err := env.DisconnectUserApp(ctx, "u1", "c1", "o1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.UserConnectedApps(ctx, "../u", ""); err == nil {
		t.Fatal("unsafe id accepted")
	}
	want := []string{
		"GET /api/v1/environments/env/users/u1/connected-apps",
		"DELETE /api/v1/environments/env/users/u1/connected-apps/c1?organization_id=o1",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
}
