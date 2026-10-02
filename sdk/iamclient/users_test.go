package iamclient

import (
	"context"
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
