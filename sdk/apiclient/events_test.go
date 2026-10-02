package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHistoryAndExport(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/v1/environments/env/roles/r1/history":
			w.Write([]byte(`{"items":[{"id":4,"type":"role.updated"}],"next":0}`))
		case "/api/v1/environments/env/events/export":
			w.Write([]byte("{\"id\":1}\n{\"id\":2}\n"))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"nope"}}`))
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "tok").Environment("env")
	page, err := env.History(context.Background(), "roles", "r1", EventFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Type != "role.updated" {
		t.Fatalf("history = %+v %v", page, err)
	}
	n := 0
	if err := env.ExportEvents(context.Background(), EventFilter{}, func(Event) error { n++; return nil }); err != nil || n != 2 {
		t.Fatalf("export = %d %v", n, err)
	}
	if _, err := env.History(context.Background(), "nope", "x", EventFilter{}); err == nil {
		t.Fatal("404 not reported")
	}
}
