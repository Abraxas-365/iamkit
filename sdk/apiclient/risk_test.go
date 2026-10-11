package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		call := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		calls = append(calls, call)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE" || strings.HasSuffix(r.URL.Path, "/captcha/test"):
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/risk-restrictions"), strings.HasSuffix(r.URL.Path, "/devices"):
			w.Write([]byte(`{"items":[{"id":"r1"}]}`))
		case strings.HasSuffix(r.URL.Path, "/sign-in-attempts"):
			w.Write([]byte(`{"items":[{"id":"a1"}],"next":"a0"}`))
		case strings.Contains(r.URL.Path, "/sign-in-attempts/"):
			w.Write([]byte(`{"id":"a1"}`))
		case strings.HasSuffix(r.URL.Path, "/risk/status"):
			w.Write([]byte(`{"geoip":{"source":"none"},"captcha":true,"risk_signals":false}`))
		default:
			w.Write([]byte(`{"provider":"hcaptcha","saved":true}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "jwt").Environment("env-1")
	ctx := context.Background()

	if c, err := env.Captcha(ctx); err != nil || c.Provider != CaptchaHCaptcha {
		t.Fatalf("captcha = %+v %v", c, err)
	}
	if _, err := env.SaveCaptcha(ctx, CaptchaInput{Provider: CaptchaHCaptcha, SiteKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if err := env.TestCaptcha(ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteCaptcha(ctx); err != nil {
		t.Fatal(err)
	}
	if p, err := env.RiskPolicy(ctx); err != nil || !p.Saved {
		t.Fatalf("policy = %+v %v", p, err)
	}
	if _, err := env.SaveRiskPolicy(ctx, RiskPolicyInput{}); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteRiskPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if rs, err := env.RiskRestrictions(ctx, RiskRestrictionFilter{Kind: RestrictionCountry}); err != nil || len(rs) != 1 {
		t.Fatalf("restrictions = %+v %v", rs, err)
	}
	if _, err := env.CreateRiskRestriction(ctx, NewRiskRestriction{Kind: RestrictionCountry, Value: "KP", Action: RestrictionDeny}); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteRiskRestriction(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if page, err := env.SignInAttempts(ctx, SignInAttemptFilter{Outcome: AttemptFailure}); err != nil || page.Next != "a0" {
		t.Fatalf("attempts = %+v %v", page, err)
	}
	if _, err := env.SignInAttempt(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if d, err := env.UserDevices(ctx, "u1"); err != nil || len(d) != 1 {
		t.Fatalf("devices = %+v %v", d, err)
	}
	if st, err := env.RiskStatus(ctx); err != nil || !st.Captcha {
		t.Fatalf("status = %+v %v", st, err)
	}
	if _, err := env.SignInAttempt(ctx, "../x"); err == nil {
		t.Fatal("unsafe id accepted")
	}
	base := "/api/v1/environments/env-1/"
	want := []string{
		"GET " + base + "captcha", "PUT " + base + "captcha", "POST " + base + "captcha/test", "DELETE " + base + "captcha",
		"GET " + base + "risk-policy", "PUT " + base + "risk-policy", "DELETE " + base + "risk-policy",
		"GET " + base + "risk-restrictions?kind=country", "POST " + base + "risk-restrictions", "DELETE " + base + "risk-restrictions/r1",
		"GET " + base + "sign-in-attempts?outcome=failure", "GET " + base + "sign-in-attempts/a1",
		"GET " + base + "users/u1/devices", "GET " + base + "risk/status",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls =\n%s", strings.Join(calls, "\n"))
	}
}
