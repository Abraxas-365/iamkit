package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestCaptchaSet(t *testing.T) {
	t.Setenv(envCaptchaSecret, "test-secret")
	_, _, seen, err := runCLI(t, ok(200, `{"provider":"turnstile"}`),
		"captcha", "set", "--provider", "Turnstile", "--site-key", "1x00000000000000000000AA", "--headless=false", "--hostname", "a.example.com,b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"provider": "turnstile", "site_key": "1x00000000000000000000AA", "secret": "test-secret", "headless": false, "hostnames": []any{"a.example.com", "b.example.com"}}
	if len(seen) != 1 || seen[0].Method != "PUT" || seen[0].Path != base+"/captcha" || !reflect.DeepEqual(seen[0].Body, want) {
		t.Fatalf("seen = %+v", seen)
	}

	// Without a secret the stored one is kept, and unset flags are not sent.
	t.Setenv(envCaptchaSecret, "")
	_, _, seen, err = runCLI(t, ok(200, `{}`), "captcha", "set", "--provider", "hcaptcha", "--site-key", "k")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen[0].Body, map[string]any{"provider": "hcaptcha", "site_key": "k"}) {
		t.Fatalf("body = %v", seen[0].Body)
	}

	for _, bad := range [][]string{{"--provider", "recaptcha", "--site-key", "k"}, {"--provider", "turnstile"}} {
		_, _, seen, err := runCLI(t, ok(200, `{}`), append([]string{"captcha", "set"}, bad...)...)
		if err == nil || len(seen) != 0 {
			t.Fatalf("%v: err = %v, requests = %d", bad, err, len(seen))
		}
	}
}

func TestCaptchaGetTestDelete(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"provider":"turnstile","has_secret":true}`), "captcha", "get")
	if err != nil || !strings.Contains(out, `"has_secret"`) || seen[0].Method != "GET" || seen[0].Path != base+"/captcha" {
		t.Fatalf("get: %v %s %+v", err, out, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "captcha", "test")
	if err != nil || seen[0].Method != "POST" || seen[0].Path != base+"/captcha/test" {
		t.Fatalf("test: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "captcha", "delete")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/captcha" {
		t.Fatalf("delete: %v %+v", err, seen)
	}
}

func TestRiskPolicySetMergesCurrent(t *testing.T) {
	current := `{"environment_id":"e","actions":{"ip_velocity":"block","new_device":"off"},"thresholds":{"ip_failures_per_hour":20,"stale_after_days":60},"notify_user":false,"block_if_unverifiable":true,"saved":true}`
	handler := func(r seenRequest) (int, string) { return 200, current }
	_, _, seen, err := runCLI(t, handler, "risk", "policy", "set", "--new-device", "challenge", "--stale-after-days", "90")
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0].Method != "GET" || seen[1].Method != "PUT" || seen[1].Path != base+"/risk-policy" {
		t.Fatalf("seen = %+v", seen)
	}
	want := map[string]any{
		"actions":               map[string]any{"ip_velocity": "block", "new_device": "challenge"},
		"thresholds":            map[string]any{"ip_failures_per_hour": float64(20), "stale_after_days": float64(90)},
		"notify_user":           false,
		"block_if_unverifiable": true,
	}
	if !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("body = %v", seen[1].Body)
	}
}

func TestRiskPolicySetValidates(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--new-device", "block"},
		{"--ip-velocity", "notify"},
		{"--user-failures-per-hour", "-1"},
	} {
		_, _, seen, err := runCLI(t, ok(200, `{}`), append([]string{"risk", "policy", "set"}, args...)...)
		if err == nil || len(seen) != 0 {
			t.Fatalf("%v: err = %v, requests = %d", args, err, len(seen))
		}
	}
}

func TestRiskPolicyGetDelete(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"actions":{},"thresholds":{},"saved":false}`), "risk", "policy", "get")
	if err != nil || seen[0].Path != base+"/risk-policy" {
		t.Fatalf("%v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "risk", "policy", "delete")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/risk-policy" {
		t.Fatalf("%v %+v", err, seen)
	}
}

func TestRiskRestrictions(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"items":[]}`), "risk", "restrictions", "list", "--kind", "country", "--action", "deny")
	if err != nil || seen[0].Path != base+"/risk-restrictions" || seen[0].Query != "action=deny&kind=country" {
		t.Fatalf("list: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(201, `{"id":"r1"}`), "risk", "restrictions", "add", "--kind", "ip", "--value", "203.0.113.0/24", "--action", "deny", "--note", "scanner")
	want := map[string]any{"kind": "ip", "value": "203.0.113.0/24", "action": "deny", "note": "scanner"}
	if err != nil || seen[0].Method != "POST" || !reflect.DeepEqual(seen[0].Body, want) {
		t.Fatalf("add: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "risk", "restrictions", "remove", "r1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/risk-restrictions/r1" {
		t.Fatalf("remove: %v %+v", err, seen)
	}
	for _, bad := range [][]string{
		{"list", "--kind", "asn"},
		{"add", "--kind", "asn", "--value", "1", "--action", "deny"},
		{"add", "--kind", "ip", "--value", "1.2.3.4", "--action", "maybe"},
	} {
		_, _, seen, err := runCLI(t, ok(200, `{}`), append([]string{"risk", "restrictions"}, bad...)...)
		if err == nil || len(seen) != 0 {
			t.Fatalf("%v: err = %v, requests = %d", bad, err, len(seen))
		}
	}
}

func TestRiskAttempts(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"items":[],"next":"a1"}`), "risk", "attempts", "list",
		"--user", "u1", "--ip", "1.2.3.4", "--outcome", "blocked", "--detection", "ip_velocity", "--country", "PE", "--before", "a9", "--limit", "10")
	want := "before=a9&country=PE&detection=ip_velocity&ip=1.2.3.4&limit=10&outcome=blocked&user_id=u1"
	if err != nil || seen[0].Path != base+"/sign-in-attempts" || seen[0].Query != want {
		t.Fatalf("list: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"id":"a1"}`), "risk", "attempts", "get", "a1")
	if err != nil || seen[0].Path != base+"/sign-in-attempts/a1" {
		t.Fatalf("get: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{}`), "risk", "attempts", "list", "--outcome", "meh")
	if err == nil || len(seen) != 0 {
		t.Fatalf("bad outcome accepted: %v", err)
	}
}

func TestRiskStatusAndDevices(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"geoip":{"source":"none"},"captcha":true,"risk_signals":false}`), "risk", "status")
	if err != nil || seen[0].Path != base+"/risk/status" {
		t.Fatalf("status: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"items":[]}`), "users", "devices", "u1")
	if err != nil || seen[0].Path != base+"/users/u1/devices" {
		t.Fatalf("devices: %v %+v", err, seen)
	}
}
