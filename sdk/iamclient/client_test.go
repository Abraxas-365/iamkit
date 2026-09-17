package iamclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagementClient(t *testing.T) {
	var calls int
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/management/v1/projects" || r.Header.Get("Authorization") != "Bearer ik_mgmt_test" {
			t.Error("unexpected request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"project"}`))
	}))
	defer remote.Close()
	c := Client{BaseURL: remote.URL, Key: "ik_mgmt_test"}
	var out map[string]string
	if err := c.Do(context.Background(), "POST", "/projects", map[string]string{"name": "Demo"}, &out); err != nil || out["id"] != "project" {
		t.Fatal(out, err)
	}
	c.Key = "application-token"
	if err := c.Do(context.Background(), "GET", "/projects", nil, nil); err == nil {
		t.Fatal("application token accepted")
	}
	if calls != 1 {
		t.Fatal("unexpected network request")
	}
}
