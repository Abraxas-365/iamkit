package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectedAppEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
		if r.Method == "GET" {
			w.Write([]byte(`{"items":[{"client":{"id":"c1","client_id":"https://claude.ai/m.json","source":"cimd","name":"Claude","host":"claude.ai","verified_name":"Claude"},"protected_resource_id":"p1","resource":"https://mcp.example/mcp","resource_name":"Notes","organization_id":"o1","scopes":["notes:read"],"consented_at":"2026-01-02T03:04:05Z","active_sessions":2,"last_used_at":null}]}`))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	apps, err := c.ListConnectedApps(ctx, "tok", "env", "https://a.example", "")
	if err != nil || len(apps) != 1 || apps[0].Client.ID != "c1" || apps[0].Client.VerifiedName != "Claude" || apps[0].ActiveSessions != 2 || apps[0].ConsentedAt == nil || apps[0].LastUsedAt != nil {
		t.Fatalf("apps = %+v %v", apps, err)
	}
	if err := c.DisconnectApp(ctx, "tok", "env", "https://a.example", "c1", "o1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /identity/v1/me/connected-apps?environment_id=env&audience=https%3A%2F%2Fa.example Bearer tok",
		"DELETE /identity/v1/me/connected-apps/c1?environment_id=env&audience=https%3A%2F%2Fa.example&organization_id=o1 Bearer tok",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
}
