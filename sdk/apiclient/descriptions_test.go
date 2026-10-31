package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermissionDescriptions(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == "PUT" {
			w.WriteHeader(204)
			return
		}
		w.Write([]byte(`{"items":[{"permission":"orders:read","locale":"","display_name":"Read orders","description":""}]}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "tok").Environment("e1")
	ctx := context.Background()
	got, err := env.PermissionDescriptions(ctx, "r1")
	if err != nil || len(got) != 1 || got[0].DisplayName != "Read orders" {
		t.Fatalf("get = %+v %v", got, err)
	}
	if err := env.SetPermissionDescriptions(ctx, "r1", got); err != nil {
		t.Fatal(err)
	}
	if _, err := env.PermissionDescriptions(ctx, "../x"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/api/v1/environments/e1/resources/r1/permission-descriptions"
	if len(calls) != 2 || calls[0] != "GET "+base || calls[1] != "PUT "+base {
		t.Fatalf("calls = %v", calls)
	}
}
