package iamclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvents(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/management/v1/environments/env/events" || q["type"][0] != "user.*" || q["type"][1] != "login.failed" ||
			q.Get("after") != "0" || q.Get("limit") != "10" || q.Has("before") || q.Has("subject") {
			t.Errorf("unexpected request %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[{"id":7,"type":"user.created","actor":{"kind":"system"},"subject":{"kind":"user","id":"u"},"data":{"origin":"api"}}],"next":7}`))
	}))
	defer remote.Close()
	after := int64(0)
	page, err := New(remote.URL, "ik_mgmt_test").Environment("env").Events(context.Background(),
		EventFilter{Types: []string{"user.*", "login.failed"}, After: &after, Limit: 10})
	if err != nil || page.Next != 7 || len(page.Items) != 1 || page.Items[0].Subject.ID != "u" ||
		page.Items[0].Actor.Kind != "system" || string(page.Items[0].Data) != `{"origin":"api"}` {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
}

func TestHistoryAndExport(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/management/v1/environments/env/users/u1/history":
			if r.URL.Query().Get("before") != "9" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"items":[{"id":8,"type":"user.updated","data":{"changes":{"name":["A","B"]}}}],"next":0}`))
		case "/management/v1/environments/env/events/export":
			if r.URL.Query().Get("type") != "user.*" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			w.Write([]byte("{\"id\":1,\"type\":\"user.created\"}\n{\"id\":2,\"type\":\"user.updated\"}\n"))
		default:
			t.Errorf("unexpected %s", r.URL)
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "ik_mgmt_test").Environment("env")
	page, err := env.History(context.Background(), "users", "u1", EventFilter{Before: 9})
	if err != nil || len(page.Items) != 1 || string(page.Items[0].Data) != `{"changes":{"name":["A","B"]}}` {
		t.Fatalf("history = %+v %v", page, err)
	}
	var ids []int64
	err = env.ExportEvents(context.Background(), EventFilter{Types: []string{"user.*"}}, func(e Event) error {
		ids = append(ids, e.ID)
		return nil
	})
	if err != nil || len(ids) != 2 || ids[1] != 2 {
		t.Fatalf("export = %v %v", ids, err)
	}
	if _, err := env.History(context.Background(), "users", "../x", EventFilter{}); err == nil {
		t.Fatal("unsafe id accepted")
	}
}
