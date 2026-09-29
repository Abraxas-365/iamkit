package iamclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestPasswordPolicyEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE" || strings.HasSuffix(r.URL.Path, "/unlock"):
			w.WriteHeader(204)
		case r.URL.Path == "/management/v1/environments/env-1/users":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":{"code":"PASSWORD_POLICY","message":"password must contain a digit","type":"VALIDATION","http_status":400,"details":{"rule":"digit","min_length":12}}}`))
		default:
			w.Write([]byte(`{"min_length":14,"require_digit":true,"max_age_days":90,"lockout_threshold":5,"lockout_minutes":15,"breach_check":true,"custom":true,"updated_at":"2026-09-01T00:00:00Z"}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	policy, err := env.PasswordPolicy(ctx)
	if err != nil || policy.MinLength != 14 || !policy.RequireDigit || policy.LockoutThreshold != 5 || !policy.Custom {
		t.Fatalf("policy = %+v %v", policy, err)
	}
	policy.MaxAgeDays = 30
	if _, err := env.SetPasswordPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := env.DeletePasswordPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.UnlockUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	_, err = env.CreateUser(ctx, CreateUser{Email: "a@b.com", Password: "no digits here"})
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || apiErr.Code != apierror.CodePasswordPolicy || apiErr.Rule() != apierror.RuleDigit || apiErr.Details["min_length"] != float64(12) {
		t.Fatalf("error = %#v", err)
	}

	base := "/management/v1/environments/env-1/"
	expected := []string{"GET " + base + "password-policy", "PUT " + base + "password-policy", "DELETE " + base + "password-policy", "POST " + base + "users/u1/unlock", "POST " + base + "users"}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	// Read-only fields are not sent back.
	if want := `{"min_length":14,"require_upper":false,"require_lower":false,"require_digit":true,"require_symbol":false,"max_age_days":30,"lockout_threshold":5,"lockout_minutes":15,"breach_check":true}`; bodies[1] != want {
		t.Fatalf("body = %s", bodies[1])
	}
}
