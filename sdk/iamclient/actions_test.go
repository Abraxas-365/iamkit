package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActionEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/action-calls"):
			w.Write([]byte(`{"items":[{"id":7,"target_id":"t1","condition":"function:pre_sign_in","outcome":"denied","status":200,"duration_ms":4}]}`))
		case strings.HasSuffix(r.URL.Path, "/test"):
			w.Write([]byte(`{"outcome":"ok","duration_ms":3,"response":{"claims":{"tier":"gold"}}}`))
		case strings.Contains(r.URL.Path, "/action-executions/"):
			w.Write([]byte(`{"condition":"function:pre_sign_in","targets":["t1"]}`))
		default:
			w.Write([]byte(`{"id":"t1","secret":"whsec_c2VjcmV0"}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	name, endpoint := "Risk", "https://risk.example/iam"
	secret, err := env.CreateActionTarget(ctx, ActionTargetInput{Name: &name, URL: &endpoint})
	if err != nil || secret.Secret != "whsec_c2VjcmV0" {
		t.Fatalf("create = %+v %v", secret, err)
	}
	if _, err := env.SetActionExecution(ctx, "function:pre_sign_in", []string{"t1"}); err != nil {
		t.Fatal(err)
	}
	test, err := env.TestActionTarget(ctx, "t1", "function:pre_access_token", nil)
	if err != nil || test.Outcome != "ok" || !strings.Contains(string(test.Response), "gold") {
		t.Fatalf("test = %+v %v", test, err)
	}
	got, err := env.ActionCalls(ctx, ActionCallFilter{Outcome: "denied", Limit: 10})
	if err != nil || len(got) != 1 || *got[0].Status != 200 {
		t.Fatalf("calls = %+v %v", got, err)
	}
	if err := env.DeleteActionExecution(ctx, "request:user.create"); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteActionExecution(ctx, "../x"); err == nil {
		t.Fatal("unsafe condition accepted")
	}
	want := []string{
		"POST /management/v1/environments/env-1/action-targets",
		"PUT /management/v1/environments/env-1/action-executions/function:pre_sign_in",
		"POST /management/v1/environments/env-1/action-targets/t1/test",
		"GET /management/v1/environments/env-1/action-calls?limit=10&outcome=denied",
		"DELETE /management/v1/environments/env-1/action-executions/request:user.create",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
	if bodies[0] != `{"name":"Risk","url":"https://risk.example/iam"}` || bodies[1] != `{"targets":["t1"]}` || bodies[2] != `{"condition":"function:pre_access_token"}` {
		t.Fatalf("bodies = %v", bodies)
	}
}
