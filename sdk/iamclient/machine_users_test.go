package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMachineUserEndpoints(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		calls = append(calls, call)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/keys"):
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"k1","user_id":"m1","public_key":{"kty":"RSA"},"expires_at":"2027-09-29T00:00:00Z","created_at":"2026-09-29T00:00:00Z","private_key":"-----BEGIN PRIVATE KEY-----"}`))
		case strings.HasSuffix(r.URL.Path, "/keys"):
			w.Write([]byte(`{"items":[{"id":"k1","public_key":{"kty":"RSA"}}],"page":{"total":1,"limit":20,"offset":0}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/access-tokens"):
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"t1","user_id":"m1","name":"ci","expires_at":"2026-10-29T00:00:00Z","created_at":"2026-09-29T00:00:00Z","token":"ik_pat_x"}`))
		case r.Method == "POST":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"m1"}`))
		case strings.HasSuffix(r.URL.Path, "/access-tokens"):
			w.Write([]byte(`{"items":[{"id":"t1","name":"ci"}],"page":{"total":1,"limit":20,"offset":0}}`))
		default:
			w.Write([]byte(`{"items":[{"id":"m1","kind":"machine","name":"bot"}],"page":{"total":1,"limit":20,"offset":0}}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	created, err := env.CreateMachineUser(ctx, "bot", "")
	if err != nil || created.ID != "m1" || bodies[0]["kind"] != "machine" {
		t.Fatalf("create = %+v %v %v", created, err, bodies[0])
	}
	users, err := env.MachineUsers(ctx)
	if err != nil || len(users) != 1 || users[0].Kind != "machine" {
		t.Fatalf("machine users = %+v %v", users, err)
	}
	issued, err := env.CreateAccessToken(ctx, "m1", CreateAccessToken{Name: "ci", OrganizationID: "o1", ApplicationID: "a1", ResourceID: "r1", ExpiresIn: "720h"})
	if err != nil || issued.Token != "ik_pat_x" || issued.ID != "t1" {
		t.Fatalf("issued = %+v %v", issued, err)
	}
	tokens, err := env.AccessTokens(ctx, "m1")
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens = %+v %v", tokens, err)
	}
	if err := env.RevokeAccessToken(ctx, "m1", "t1"); err != nil {
		t.Fatal(err)
	}
	key, err := env.AddUserKey(ctx, "m1", AddUserKey{ExpiresIn: "720h"})
	if err != nil || key.ID != "k1" || key.PrivateKey == "" || bodies[len(bodies)-1]["public_key"] != nil {
		t.Fatalf("key = %+v %v %v", key, err, bodies[len(bodies)-1])
	}
	keys, err := env.UserKeys(ctx, "m1")
	if err != nil || len(keys) != 1 || string(keys[0].PublicKey) != `{"kty":"RSA"}` {
		t.Fatalf("keys = %+v %v", keys, err)
	}
	if err := env.RemoveUserKey(ctx, "m1", "k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.AccessTokens(ctx, "../x"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/management/v1/environments/env-1/"
	expected := []string{"POST " + base + "users", "GET " + base + "users?kind=machine", "POST " + base + "users/m1/access-tokens", "GET " + base + "users/m1/access-tokens", "DELETE " + base + "users/m1/access-tokens/t1",
		"POST " + base + "users/m1/keys", "GET " + base + "users/m1/keys", "DELETE " + base + "users/m1/keys/k1"}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}
