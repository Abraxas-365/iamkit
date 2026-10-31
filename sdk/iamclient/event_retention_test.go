package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventRetention(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"security_retention_seconds":2592000,"default_retention_seconds":null,"ceilings":{"security":31536000,"default":7776000},"effective":{"security":2592000,"default":7776000}}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	got, err := env.EventRetention(ctx)
	if err != nil || *got.SecuritySeconds != 2592000 || got.DefaultSeconds != nil || got.Ceilings.Default != 7776000 || got.Effective.Security != 2592000 {
		t.Fatalf("retention = %+v %v", got, err)
	}
	days := int64(30 * 86400)
	if _, err := env.SetEventRetention(ctx, EventRetentionInput{SecuritySeconds: &days}); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /management/v1/environments/env-1/event-retention", "PUT /management/v1/environments/env-1/event-retention"}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
	if bodies[1] != `{"security_retention_seconds":2592000,"default_retention_seconds":null}` {
		t.Fatalf("body = %q", bodies[1])
	}
}
