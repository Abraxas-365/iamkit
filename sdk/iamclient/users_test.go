package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserStateEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		calls = append(calls, call)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			w.WriteHeader(204)
			return
		}
		w.Write([]byte(`{"items":[{"id":"u1","email":"a@b.com","name":"A","active":true,"state":"initial","last_signed_in_at":null}],"page":{"total":1,"limit":20,"offset":0}}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	users, err := env.UsersInState(ctx, UserInitial)
	if err != nil || len(users) != 1 || users[0].State != UserInitial || users[0].LastSignedInAt != nil {
		t.Fatalf("users = %+v %v", users, err)
	}
	if err := env.DeactivateUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if err := env.ReactivateUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	base := "/management/v1/environments/env-1/"
	expected := []string{"GET " + base + "users?state=initial", "POST " + base + "users/u1/deactivate", "POST " + base + "users/u1/reactivate"}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}

func TestUserByExternalID(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("external_id")
		if gotQuery == "crm-42" {
			w.Write([]byte(`{"items":[{"id":"u1","email":"a@b.com","name":"A","external_id":"crm-42","active":true}],"page":{"total":1,"limit":20,"offset":0}}`))
			return
		}
		w.Write([]byte(`{"items":[],"page":{"total":0,"limit":20,"offset":0}}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	found, ok, err := env.UserByExternalID(context.Background(), "crm-42")
	if err != nil || !ok || found.ID != "u1" || found.ExternalID != "crm-42" || gotQuery != "crm-42" {
		t.Fatalf("found = %+v %v %v query=%q", found, ok, err, gotQuery)
	}
	if _, ok, err = env.UserByExternalID(context.Background(), "nope"); err != nil || ok {
		t.Fatalf("unknown = %v %v", ok, err)
	}
}

func TestImportUsers(t *testing.T) {
	var path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"index":0,"id":"u1"},{"index":1,"error":{"code":"CONFLICT","message":"email is taken"}}],"created":1,"failed":1}`))
	}))
	defer srv.Close()
	out, err := New(srv.URL, "ik_mgmt_test").Environment("env-1").ImportUsers(context.Background(), []CreateUser{
		{Email: "a@example.com", Name: "A", PasswordHash: "$2a$10$x", EmailVerified: true, Metadata: map[string]any{"plan": "pro"}},
		{Email: "b@example.com", Name: "B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/management/v1/environments/env-1/users/import" {
		t.Fatalf("path = %s", path)
	}
	for _, want := range []string{`"users":[`, `"password_hash":"$2a$10$x"`, `"email_verified":true`, `"metadata":{"plan":"pro"}`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s lacks %s", body, want)
		}
	}
	if out.Created != 1 || out.Failed != 1 || out.Results[0].ID != "u1" || out.Results[1].Error.Code != "CONFLICT" {
		t.Fatalf("out = %+v", out)
	}
}
