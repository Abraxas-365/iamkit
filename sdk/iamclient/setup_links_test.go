package iamclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupLinkEndpoints(t *testing.T) {
	var calls []string
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "POST":
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"l1","url":"https://iam.example/org-admin/env-1/setup#ik_setup_x","expires_at":"2030-01-01T00:00:00Z","intents":["sso"]}`))
		case "DELETE":
			w.WriteHeader(204)
		default:
			w.Write([]byte(`{"items":[{"id":"l1","intents":["sso"],"expires_at":"2030-01-01T00:00:00Z","revoked_at":null,"created_by":"u","created_at":"2029-01-01T00:00:00Z","last_used_at":null}],"page":{"total":1,"limit":50,"offset":0}}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	link, err := env.CreateSetupLink(ctx, "org-1", SetupLinkInput{Intents: []string{SetupIntentSSO}, ExpiresIn: "24h"})
	if err != nil || link.ID != "l1" || link.URL == "" {
		t.Fatalf("link = %+v %v", link, err)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(body), &sent); err != nil || sent["expires_in"] != "24h" {
		t.Fatalf("body = %s", body)
	}
	list, err := env.SetupLinks(ctx, "org-1")
	if err != nil || len(list) != 1 || list[0].RevokedAt != nil {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := env.RevokeSetupLink(ctx, "org-1", "l1"); err != nil {
		t.Fatal(err)
	}
	base := "/management/v1/environments/env-1/organizations/org-1/setup-links"
	want := []string{"POST " + base, "GET " + base, "DELETE " + base + "/l1"}
	for i, w := range want {
		if calls[i] != w {
			t.Fatalf("calls = %v", calls)
		}
	}
}
