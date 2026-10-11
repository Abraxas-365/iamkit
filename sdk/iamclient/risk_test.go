package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		calls = append(calls, call)
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case r.Method == "DELETE" || strings.HasSuffix(p, "/captcha/test"):
			w.WriteHeader(204)
		case strings.HasSuffix(p, "/captcha"):
			w.Write([]byte(`{"environment_id":"env-1","provider":"turnstile","site_key":"1x00000000000000000000AA","has_secret":true,"hosted":true,"headless":false,"hostnames":["app.example.com"]}`))
		case strings.HasSuffix(p, "/risk-policy"):
			w.Write([]byte(`{"environment_id":"env-1","actions":{"new_device":"challenge"},"thresholds":{"ip_failures_per_hour":20,"ip_distinct_logins_per_hour":10,"user_failures_per_hour":10,"stale_after_days":60,"travel_speed_kmh":1000},"notify_user":true,"block_if_unverifiable":false,"saved":true}`))
		case strings.HasSuffix(p, "/risk-restrictions") && r.Method == "POST":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"r1","kind":"country","value":"KP","action":"deny","note":""}`))
		case strings.HasSuffix(p, "/risk-restrictions"):
			w.Write([]byte(`{"items":[{"id":"r1","kind":"ip","value":"10.0.0.0/8","action":"allow"}]}`))
		case strings.HasSuffix(p, "/sign-in-attempts"):
			w.Write([]byte(`{"items":[{"id":"a2","outcome":"blocked","detections":["ip_velocity"],"device":true,"action":"block"}],"next":"a1"}`))
		case strings.Contains(p, "/sign-in-attempts/"):
			w.Write([]byte(`{"id":"a1","outcome":"success","detections":[],"action":"none","captcha":"passed"}`))
		case strings.HasSuffix(p, "/devices"):
			w.Write([]byte(`{"items":[{"first_seen_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-02T00:00:00Z","last_ip":"1.2.3.4","last_country":"PE"}]}`))
		case strings.HasSuffix(p, "/risk/status"):
			w.Write([]byte(`{"geoip":{"source":"mmdb","database":"GeoLite2-City","countries":true,"travel":true},"captcha":true,"risk_signals":true}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	no := false

	cfg, err := env.Captcha(ctx)
	if err != nil || cfg.Provider != CaptchaTurnstile || !cfg.HasSecret || cfg.Headless || len(cfg.Hostnames) != 1 {
		t.Fatalf("captcha = %+v %v", cfg, err)
	}
	secret := "test-secret"
	if _, err := env.SaveCaptcha(ctx, CaptchaInput{Provider: CaptchaTurnstile, SiteKey: "1x00000000000000000000AA", Secret: &secret, Headless: &no}); err != nil {
		t.Fatal(err)
	}
	if err := env.TestCaptcha(ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteCaptcha(ctx); err != nil {
		t.Fatal(err)
	}

	pol, err := env.RiskPolicy(ctx)
	if err != nil || !pol.Saved || pol.Actions[RiskNewDevice] != RiskActionChallenge || pol.Thresholds.StaleAfterDays != 60 {
		t.Fatalf("policy = %+v %v", pol, err)
	}
	if _, err := env.SaveRiskPolicy(ctx, RiskPolicyInput{Actions: map[string]string{RiskIPVelocity: RiskActionBlock}}); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteRiskPolicy(ctx); err != nil {
		t.Fatal(err)
	}

	rs, err := env.RiskRestrictions(ctx, RiskRestrictionFilter{Kind: RestrictionIP, Action: RestrictionAllow})
	if err != nil || len(rs) != 1 || rs[0].Value != "10.0.0.0/8" {
		t.Fatalf("restrictions = %+v %v", rs, err)
	}
	r, err := env.CreateRiskRestriction(ctx, NewRiskRestriction{Kind: RestrictionCountry, Value: "KP", Action: RestrictionDeny})
	if err != nil || r.ID != "r1" {
		t.Fatalf("restriction = %+v %v", r, err)
	}
	if err := env.DeleteRiskRestriction(ctx, "r1"); err != nil {
		t.Fatal(err)
	}

	page, err := env.SignInAttempts(ctx, SignInAttemptFilter{Outcome: AttemptBlocked, IP: "1.2.3.4", Limit: 10, Before: "a9"})
	if err != nil || len(page.Items) != 1 || page.Next != "a1" || !page.Items[0].Device {
		t.Fatalf("attempts = %+v %v", page, err)
	}
	att, err := env.SignInAttempt(ctx, "a1")
	if err != nil || att.Captcha != "passed" {
		t.Fatalf("attempt = %+v %v", att, err)
	}
	devices, err := env.UserDevices(ctx, "u1")
	if err != nil || len(devices) != 1 || devices[0].LastCountry != "PE" {
		t.Fatalf("devices = %+v %v", devices, err)
	}
	st, err := env.RiskStatus(ctx)
	if err != nil || st.GeoIP.Source != "mmdb" || !st.GeoIP.Travel || !st.Captcha {
		t.Fatalf("status = %+v %v", st, err)
	}
	for _, bad := range []func() error{
		func() error { _, err := env.SignInAttempt(ctx, "../x"); return err },
		func() error { _, err := env.UserDevices(ctx, "a/b"); return err },
		func() error { return env.DeleteRiskRestriction(ctx, "") },
	} {
		if bad() == nil {
			t.Fatal("unsafe segment accepted")
		}
	}

	base := "/management/v1/environments/env-1/"
	want := []string{
		"GET " + base + "captcha",
		"PUT " + base + "captcha",
		"POST " + base + "captcha/test",
		"DELETE " + base + "captcha",
		"GET " + base + "risk-policy",
		"PUT " + base + "risk-policy",
		"DELETE " + base + "risk-policy",
		"GET " + base + "risk-restrictions?action=allow&kind=ip",
		"POST " + base + "risk-restrictions",
		"DELETE " + base + "risk-restrictions/r1",
		"GET " + base + "sign-in-attempts?before=a9&ip=1.2.3.4&limit=10&outcome=blocked",
		"GET " + base + "sign-in-attempts/a1",
		"GET " + base + "users/u1/devices",
		"GET " + base + "risk/status",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls =\n%s", strings.Join(calls, "\n"))
	}
	if bodies[1] != `{"provider":"turnstile","site_key":"1x00000000000000000000AA","secret":"test-secret","headless":false}` {
		t.Fatalf("captcha body = %s", bodies[1])
	}
	if bodies[5] != `{"actions":{"ip_velocity":"block"},"block_if_unverifiable":false}` {
		t.Fatalf("policy body = %s", bodies[5])
	}
}
