package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFeatureEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/features") {
			w.Write([]byte(`{"items":[{"name":"beta_languages","scope":"environment","default":true,"deployment":null,"environment":false,"enabled":false}]}`))
			return
		}
		w.Write([]byte(`{"name":"beta_languages","scope":"environment","default":true,"deployment":false,"environment":null,"enabled":false}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	list, err := env.Features(ctx)
	if err != nil || len(list) != 1 || list[0].Environment == nil || *list[0].Environment || list[0].Deployment != nil {
		t.Fatalf("features = %+v %v", list, err)
	}
	got, err := env.Feature(ctx, "beta_languages")
	if err != nil || got.Deployment == nil || got.Enabled {
		t.Fatalf("feature = %+v %v", got, err)
	}
	if _, err := env.SetFeature(ctx, "beta_languages", true); err != nil {
		t.Fatal(err)
	}
	if _, err := env.ResetFeature(ctx, "beta_languages"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Feature(ctx, "../x"); err == nil {
		t.Fatal("unsafe name accepted")
	}
	want := []string{
		"GET /management/v1/environments/env-1/features",
		"GET /management/v1/environments/env-1/features/beta_languages",
		"PUT /management/v1/environments/env-1/features/beta_languages",
		"DELETE /management/v1/environments/env-1/features/beta_languages",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
	if bodies[2] != `{"enabled":true}` {
		t.Fatalf("body = %s", bodies[2])
	}
}
