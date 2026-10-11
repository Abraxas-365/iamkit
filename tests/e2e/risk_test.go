package e2e_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/server"
	"github.com/gofiber/fiber/v2"
)

// riskEnv is an environment behind a trusted proxy that tells the client's
// address (X-Forwarded-For) and country (CF-IPCountry).
func riskEnv(t *testing.T, opts ...bootstrap.Option) *Env {
	t.Helper()
	return newEnvWith(t, func(s *server.Server) {
		s.TrustedProxies = []string{"0.0.0.0/8"}
		s.GeoIPHeader = "CF-IPCountry"
	}, append(opts, bootstrap.WithGeoIP("", "CF-IPCountry"))...)
}

// from sends a request as a client at ip in country ("" = none).
func (e *Env) from(ip, country, method, path string, body any) Response {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, reader)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", ip)
	if country != "" {
		r.Header.Set("CF-IPCountry", country)
	}
	res, err := e.App.Test(r, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := Response{Status: res.StatusCode, Body: string(raw)}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

func (e *Env) attempts(query string) []map[string]any {
	e.t.Helper()
	return items(e.Must("GET", e.Base+"/sign-in-attempts"+query, e.Owner, nil, 200))
}

func (e *Env) riskPolicy(body fiber.Map) {
	e.t.Helper()
	e.Must("PUT", e.Base+"/risk-policy", e.Owner, body, 200)
}

const riskOK = "203.0.113.7"

// TestRiskDefaults: with no policy or restriction nothing changes for the
// user (a plain sign-in, no challenge), only the attempt log fills.
func TestRiskDefaults(t *testing.T) {
	e := riskEnv(t)
	policy := e.Must("GET", e.Base+"/risk-policy", e.Owner, nil, 200).JSON
	if policy["saved"] != false || policy["actions"].(map[string]any)["new_device"] != "off" {
		t.Fatalf("default policy = %s", policy)
	}
	status := e.Must("GET", e.Base+"/risk/status", e.Owner, nil, 200).JSON
	if status["risk_signals"] != true || status["geoip"].(map[string]any)["countries"] != true || status["geoip"].(map[string]any)["travel"] != false {
		t.Fatalf("status = %v", status)
	}
	if got := e.from(riskOK, "PE", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, "wrong password here")); got.Status != 401 {
		t.Fatalf("wrong password: %d %s", got.Status, got.Body)
	}
	if got := e.from(riskOK, "PE", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, e.Pass)); got.Status != 200 || got.JSON["access_token"] == nil || got.JSON["mfa_required"] != nil {
		t.Fatalf("login: %d %s", got.Status, got.Body)
	}
	log := e.attempts("")
	if len(log) != 2 || log[0]["outcome"] != "success" || log[1]["outcome"] != "failure" || log[0]["ip"] != riskOK || log[0]["country"] != "PE" || log[0]["user_id"] != e.Alice || log[0]["action"] != "none" {
		t.Fatalf("attempts = %v", log)
	}
	for _, a := range log {
		if _, leaked := a["device_hash"]; leaked || a["device"] != false {
			t.Fatalf("attempt shows a device: %v", a)
		}
	}
	one := e.Must("GET", e.Base+"/sign-in-attempts/"+log[0]["id"].(string), e.Owner, nil, 200).JSON
	if one["id"] != log[0]["id"] {
		t.Fatalf("attempt = %v", one)
	}
	e.Must("GET", e.Base+"/sign-in-attempts/00000000-0000-4000-8000-000000000000", e.Owner, nil, 404)
	if got := items(e.Must("GET", e.Base+"/sign-in-attempts?outcome=failure", e.Owner, nil, 200)); len(got) != 1 {
		t.Fatalf("outcome filter = %v", got)
	}
	e.Must("GET", e.Base+"/sign-in-attempts?outcome=bogus", e.Owner, nil, 400)
	if devices := items(e.Must("GET", e.Base+"/users/"+e.Alice+"/devices", e.Owner, nil, 200)); len(devices) != 0 {
		t.Fatalf("devices without a device id = %v", devices)
	}
	// The kill switch stops recording too.
	e.Must("PUT", e.Base+"/features/risk_signals", e.Owner, fiber.Map{"enabled": false}, 200)
	e.Login(e.AliceEmail)
	if n := len(e.attempts("")); n != 2 {
		t.Fatalf("recorded with risk_signals off: %d", n)
	}
}

// TestRiskRestrictions: deny rules (address, country, email domain) refuse
// every method with the same answer; an allow rule skips detections; sign-ups
// are screened too; validation and removal.
func TestRiskRestrictions(t *testing.T) {
	e := riskEnv(t)
	add := func(kind, value, action string, want int) Response {
		e.t.Helper()
		return e.Must("POST", e.Base+"/risk-restrictions", e.Owner, fiber.Map{"kind": kind, "value": value, "action": action, "note": "test"}, want)
	}
	add("ip", "not-an-ip", "deny", 400)
	add("country", "PERU", "deny", 400)
	add("email_domain", "no spaces.example", "deny", 400)
	add("ip", "198.51.100.0/24", "bogus", 400)
	blockedIP := add("ip", "198.51.100.0/24", "deny", 201).JSON
	add("ip", "198.51.100.0/24", "deny", 409)
	add("country", "ru", "deny", 201)
	add("email_domain", "@Blocked.Example", "deny", 201)
	if got := items(e.Must("GET", e.Base+"/risk-restrictions?kind=country", e.Owner, nil, 200)); len(got) != 1 || got[0]["value"] != "RU" {
		t.Fatalf("country rules = %v", got)
	}
	e.Must("GET", e.Base+"/risk-restrictions?kind=bogus", e.Owner, nil, 400)

	body := e.LoginBody(e.AliceEmail, e.Pass)
	for _, c := range []struct{ ip, country string }{{"198.51.100.20", "PE"}, {riskOK, "RU"}, {riskOK, "ru"}} {
		got := e.from(c.ip, c.country, "POST", "/identity/v1/login", body)
		if got.Status != 403 || errorOf(got)["code"] != "SIGN_IN_BLOCKED" {
			t.Fatalf("%v: %d %s", c, got.Status, got.Body)
		}
	}
	// The same answer for an account that does not exist, and for a wrong password.
	unknown := e.from("198.51.100.20", "", "POST", "/identity/v1/login", e.LoginBody("nobody@example.com", e.Pass))
	wrong := e.from("198.51.100.20", "", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, "wrong password here"))
	if unknown.Status != 403 || wrong.Status != 403 || unknown.Body != wrong.Body {
		t.Fatalf("unknown %d %s, wrong %d %s", unknown.Status, unknown.Body, wrong.Status, wrong.Body)
	}
	// Email codes are screened before a code is sent.
	sent := len(e.Mail.Sent)
	if got := e.from("198.51.100.20", "", "POST", "/identity/v1/challenges", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "login"}); got.Status != 403 || errorOf(got)["code"] != "SIGN_IN_BLOCKED" {
		t.Fatalf("challenge: %d %s", got.Status, got.Body)
	}
	if len(e.Mail.Sent) != sent {
		t.Fatal("a blocked sign-in sent mail")
	}
	// The hosted page says so too.
	client := e.hostedClient()
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 303 {
		t.Fatalf("hosted (not blocked here): %d %s", p.Status, p.Body)
	}
	// Browsers reach the server as 0.0.0.0 here: deny that address.
	here := add("ip", "0.0.0.0", "deny", 201).JSON
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 || !strings.Contains(p.Body, "not allowed") {
		t.Fatalf("hosted blocked: %d %s", p.Status, p.Body)
	}
	e.Must("DELETE", e.Base+"/risk-restrictions/"+here["id"].(string), e.Owner, nil, 204)

	blocked := e.attempts("?outcome=blocked")
	if len(blocked) < 4 || blocked[0]["reason"] == "" {
		t.Fatalf("blocked attempts = %v", blocked)
	}
	if got := e.attempts("?outcome=blocked&country=RU"); len(got) != 2 {
		t.Fatalf("country filter = %v", got)
	}

	// Sign-ups: a denied email domain is refused before any code goes out.
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true, "allow_signup": true, "signup_organization_id": e.Org}, 200)
	signup := fiber.Map{"environment_id": e.EnvID, "email": "eve@blocked.example", "name": "Eve", "password": "a long enough password"}
	if got := e.from(riskOK, "", "POST", "/identity/v1/signup", signup); got.Status != 403 || errorOf(got)["code"] != "SIGN_IN_BLOCKED" {
		t.Fatalf("signup: %d %s", got.Status, got.Body)
	}
	signup["email"] = "eve@sub.blocked.example"
	e.from(riskOK, "", "POST", "/identity/v1/signup", signup)
	if got := e.from(riskOK, "", "POST", "/identity/v1/signup", fiber.Map{"environment_id": e.EnvID, "email": "fay@fine.example", "name": "Fay", "password": "a long enough password"}); got.Status != 202 {
		t.Fatalf("allowed signup: %d %s", got.Status, got.Body)
	}

	// An allow rule beats the detections (and a deny for another kind does not apply to it).
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"user_brute_force": "block"}, "thresholds": fiber.Map{"user_failures_per_hour": 1}})
	e.from(riskOK, "", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, "wrong password here"))
	if got := e.from(riskOK, "", "POST", "/identity/v1/login", body); got.Status != 403 || errorOf(got)["code"] != "SIGN_IN_BLOCKED" {
		t.Fatalf("brute force block: %d %s", got.Status, got.Body)
	}
	e.Must("POST", e.Base+"/risk-restrictions", e.Owner, fiber.Map{"kind": "ip", "value": riskOK, "action": "allow"}, 201)
	if got := e.from(riskOK, "", "POST", "/identity/v1/login", body); got.Status != 200 {
		t.Fatalf("allowed address: %d %s", got.Status, got.Body)
	}

	// Removing a rule lifts it.
	e.Must("DELETE", e.Base+"/risk-policy", e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/risk-restrictions/"+blockedIP["id"].(string), e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/risk-restrictions/"+blockedIP["id"].(string), e.Owner, nil, 404)
	if got := e.from("198.51.100.20", "", "POST", "/identity/v1/login", body); got.Status != 200 {
		t.Fatalf("after delete: %d %s", got.Status, got.Body)
	}
}

// TestRiskCountryNeedsGeoIP: without GeoIP, country rules and impossible
// travel are refused rather than silently ignored.
func TestRiskCountryNeedsGeoIP(t *testing.T) {
	e := newEnv(t)
	if r := e.Must("POST", e.Base+"/risk-restrictions", e.Owner, fiber.Map{"kind": "country", "value": "RU", "action": "deny"}, 422); errorOf(r)["code"] != "GEOIP_REQUIRED" {
		t.Fatalf("country: %s", r.Body)
	}
	e.Must("POST", e.Base+"/risk-restrictions", e.Owner, fiber.Map{"kind": "email_domain", "value": "evil.example", "action": "deny"}, 201)
	if r := e.Must("PUT", e.Base+"/risk-policy", e.Owner, fiber.Map{"actions": fiber.Map{"impossible_travel": "block"}}, 422); errorOf(r)["code"] != "GEOIP_REQUIRED" {
		t.Fatalf("travel: %s", r.Body)
	}
	if got := e.Must("GET", e.Base+"/risk/status", e.Owner, nil, 200).JSON["geoip"].(map[string]any)["source"]; got != "none" {
		t.Fatalf("geoip source = %v", got)
	}
}

// TestRiskPolicyManagement: validation, defaults for unspecified detections,
// saved policies and reset.
func TestRiskPolicyManagement(t *testing.T) {
	e := riskEnv(t)
	for _, bad := range []fiber.Map{
		{"actions": fiber.Map{"bogus": "log"}},
		{"actions": fiber.Map{"new_device": "block"}},
		{"actions": fiber.Map{"ip_velocity": "notify"}},
		{"actions": fiber.Map{"ip_velocity": "log"}, "thresholds": fiber.Map{"ip_failures_per_hour": -1}},
		{"thresholds": fiber.Map{"stale_after_days": 3}},
	} {
		e.Must("PUT", e.Base+"/risk-policy", e.Owner, bad, 400)
	}
	saved := e.Must("PUT", e.Base+"/risk-policy", e.Owner, fiber.Map{"actions": fiber.Map{"new_device": "notify", "stale_account": "log"}, "block_if_unverifiable": true}, 200).JSON
	actions := saved["actions"].(map[string]any)
	if saved["saved"] != true || actions["new_device"] != "notify" || actions["stale_account"] != "log" || actions["ip_velocity"] != "off" || saved["block_if_unverifiable"] != true || saved["notify_user"] != true {
		t.Fatalf("saved = %v", saved)
	}
	th := saved["thresholds"].(map[string]any)
	if th["ip_failures_per_hour"] != float64(20) || th["user_failures_per_hour"] != float64(10) || th["stale_after_days"] != float64(60) || th["travel_speed_kmh"] != float64(1000) {
		t.Fatalf("threshold defaults = %v", th)
	}
	e.Must("DELETE", e.Base+"/risk-policy", e.Owner, nil, 204)
	if got := e.Must("GET", e.Base+"/risk-policy", e.Owner, nil, 200).JSON; got["saved"] != false || got["actions"].(map[string]any)["new_device"] != "off" {
		t.Fatalf("after reset = %v", got)
	}
	// The events say who changed what.
	types := map[string]bool{}
	for _, ev := range items(e.Must("GET", e.Base+"/events?limit=200", e.Owner, nil, 200)) {
		types[ev["type"].(string)] = true
	}
	for _, want := range []string{"risk_policy.updated", "risk_policy.deleted"} {
		if !types[want] {
			t.Errorf("no %s event (have %v)", want, types)
		}
	}
}

// TestRiskChallengeHeadless: repeated failures turn the next correct
// password into an emailed-code step (reason risk_challenge); the code
// completes it with amr otp but not mfa; an unverified inbox cannot be
// challenged (signs in, or is blocked with block_if_unverifiable).
func TestRiskChallengeHeadless(t *testing.T) {
	e := riskEnv(t)
	e.verifyEmail(e.Alice)
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"user_brute_force": "challenge"}, "thresholds": fiber.Map{"user_failures_per_hour": 2}})
	body := e.LoginBody(e.AliceEmail, e.Pass)
	for range 2 {
		e.from(riskOK, "", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, "wrong password here"))
	}
	asked := e.from(riskOK, "", "POST", "/identity/v1/login", body)
	token, _ := asked.JSON["mfa_token"].(string)
	if asked.Status != 200 || asked.JSON["mfa_required"] != true || asked.JSON["reason"] != "risk_challenge" || !strings.HasPrefix(token, "ik_mfa_") || asked.JSON["access_token"] != nil ||
		!equal(strs(asked.JSON["factors"]), []string{"email"}) || asked.JSON["enrollment_required"] != false {
		t.Fatalf("challenge = %d %s", asked.Status, asked.Body)
	}
	if a := e.attempts("?outcome=challenged"); len(a) != 1 || a[0]["action"] != "challenge" || !contains(strs(a[0]["detections"]), "user_brute_force") {
		t.Fatalf("challenged attempts = %v", a)
	}
	// The code is sent on request (and the only factor is email).
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "sms"}, 422)
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "email"}, 202)
	if m, ok := e.Mail.Last("mfa"); !ok || m.Email != e.AliceEmail {
		t.Fatalf("code mail = %+v", m)
	}
	code := e.lastMFACode(t)
	if r := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": "000000"}, 401); r.JSON["access_token"] != nil {
		t.Fatalf("wrong code: %s", r.Body)
	}
	done := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 200).JSON
	access, _ := done["access_token"].(string)
	if access == "" {
		t.Fatalf("verify = %v", done)
	}
	if a := strs(claims(t, access)["amr"]); !contains(a, "otp") || contains(a, "mfa") || !contains(a, "pwd") {
		t.Fatalf("amr = %v", a)
	}
	var detections []string
	if err := e.DB.Select(&detections, `SELECT unnest(risk_detections) FROM sessions WHERE user_id = $1`, e.Alice); err != nil || !contains(detections, "user_brute_force") {
		t.Fatalf("session detections = %v %v", detections, err)
	}
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 401)
	if a := e.attempts("?outcome=success"); len(a) == 0 {
		t.Fatal("completed challenge not recorded as success")
	}

	// An organization that requires MFA asks for its factor (enrollment
	// here), which satisfies the challenge: no emailed code on top.
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": true}, 204)
	mfaAsked := e.from(riskOK, "", "POST", "/identity/v1/login", body)
	if mfaAsked.JSON["mfa_required"] != true || mfaAsked.JSON["reason"] != nil || mfaAsked.JSON["enrollment_required"] != true {
		t.Fatalf("mfa organization: %s", mfaAsked.Body)
	}
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": false}, 204)

	// An unverified address cannot receive the code: sign in, or block.
	e.User("Bob", "bob@example.com")
	bobBody := e.LoginBody("bob@example.com", e.Pass)
	e.Join(e.Org, e.userID("bob@example.com"))
	e.Grant(e.Org, e.userID("bob@example.com"), e.Res, "invoices:read")
	for range 2 {
		e.from(riskOK, "", "POST", "/identity/v1/login", e.LoginBody("bob@example.com", "wrong password here"))
	}
	if got := e.from(riskOK, "", "POST", "/identity/v1/login", bobBody); got.Status != 200 || got.JSON["access_token"] == nil {
		t.Fatalf("unverifiable, not blocked: %d %s", got.Status, got.Body)
	}
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"user_brute_force": "challenge"}, "thresholds": fiber.Map{"user_failures_per_hour": 2}, "block_if_unverifiable": true})
	if got := e.from(riskOK, "", "POST", "/identity/v1/login", bobBody); got.Status != 403 || errorOf(got)["code"] != "SIGN_IN_BLOCKED" {
		t.Fatalf("unverifiable, blocked: %d %s", got.Status, got.Body)
	}
}

func (e *Env) userID(email string) string {
	e.t.Helper()
	var id string
	if err := e.DB.Get(&id, `SELECT id FROM users WHERE environment_id = $1 AND email = $2`, e.EnvID, email); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// TestRiskNewDevice: a device id the user has not signed in from before is
// a new_device detection (only with a device id); a notify action emails the
// user (once per interval); known devices are listed.
func TestRiskNewDevice(t *testing.T) {
	e := riskEnv(t)
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"new_device": "notify"}})
	// Nobody is alerted at an address they never proved: Bob is flagged, not mailed.
	e.User("Bob", "bob@example.com")
	bob := e.userID("bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	bobLogin := e.LoginBody("bob@example.com", e.Pass)
	bobLogin["device_id"] = "bobs-device-0000000001"
	if got := e.from(riskOK, "PE", "POST", "/identity/v1/login", bobLogin); got.Status != 200 {
		t.Fatalf("bob: %d %s", got.Status, got.Body)
	}
	if _, ok := e.Mail.Last("security_alert"); ok || len(e.attempts("?detection=new_device")) != 1 {
		t.Fatalf("unverified address alerted or not flagged: %v", e.attempts(""))
	}
	e.verifyEmail(e.Alice)
	alerts := func() int {
		n := 0
		for _, m := range e.Mail.Sent {
			if m.Purpose == "security_alert" {
				n++
			}
		}
		return n
	}
	device := func(id string) fiber.Map {
		b := e.LoginBody(e.AliceEmail, e.Pass)
		if id != "" {
			b["device_id"] = id
		}
		return b
	}
	// No device id: not evaluated, no alert.
	e.from(riskOK, "PE", "POST", "/identity/v1/login", device(""))
	if alerts() != 0 {
		t.Fatalf("alert without a device id")
	}
	// An invalid id is dropped like none.
	e.from(riskOK, "PE", "POST", "/identity/v1/login", device("short"))
	if alerts() != 0 {
		t.Fatalf("alert for an invalid device id")
	}
	const laptop, phone = "laptop-device-0000001", "phone-device-00000002"
	if got := e.from(riskOK, "PE", "POST", "/identity/v1/login", device(laptop)); got.Status != 200 || got.JSON["access_token"] == nil {
		t.Fatalf("new device login: %d %s", got.Status, got.Body)
	}
	if alerts() != 1 {
		t.Fatalf("alerts after a new device = %d", alerts())
	}
	m, _ := e.Mail.Last("security_alert")
	if m.Detection != "new_device" || m.Email != e.AliceEmail {
		t.Fatalf("alert = %+v", m)
	}
	first := e.attempts("?detection=new_device")
	first = e.attempts("?detection=new_device&user_id=" + e.Alice)
	if len(first) != 1 || first[0]["outcome"] != "success" || first[0]["action"] != "notify" || first[0]["device"] != true {
		t.Fatalf("new_device attempts = %v", first)
	}
	// Known now: no detection, no alert.
	e.from(riskOK, "PE", "POST", "/identity/v1/login", device(laptop))
	if len(e.attempts("?detection=new_device&user_id="+e.Alice)) != 1 || alerts() != 1 {
		t.Fatalf("known device flagged")
	}
	// A second new device is flagged, but the alert is throttled.
	e.from(riskOK, "PE", "POST", "/identity/v1/login", device(phone))
	if len(e.attempts("?detection=new_device&user_id="+e.Alice)) != 2 || alerts() != 1 {
		t.Fatalf("second device: %d alerts", alerts())
	}
	devices := items(e.Must("GET", e.Base+"/users/"+e.Alice+"/devices", e.Owner, nil, 200))
	if len(devices) != 2 || devices[0]["last_ip"] != riskOK || devices[0]["last_country"] != "PE" {
		t.Fatalf("devices = %v", devices)
	}
	for _, d := range devices {
		if _, leaked := d["device_hash"]; leaked || d["device_id"] != nil {
			t.Fatalf("device leaks an identifier: %v", d)
		}
	}
	// notify_user off: flagged, no mail.
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"new_device": "notify"}, "notify_user": false})
	e.from(riskOK, "PE", "POST", "/identity/v1/login", device("tablet-device-00000003"))
	if alerts() != 1 {
		t.Fatalf("alert with notify_user off")
	}
}

// TestRiskChallengeHosted: the hosted pages ask for the emailed code with
// the risk wording, accept it (amr otp, not mfa) and refuse a wrong one.
func TestRiskChallengeHosted(t *testing.T) {
	e := riskEnv(t)
	e.verifyEmail(e.Alice)
	client := e.hostedClient()
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"user_brute_force": "challenge"}, "thresholds": fiber.Map{"user_failures_per_hour": 2}})
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	for range 2 {
		if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"wrong password here"}}); p.Status != 401 {
			t.Fatalf("wrong password: %d %s", p.Status, p.Body)
		}
	}
	ask := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if ask.Status != 200 || !strings.Contains(ask.Body, `action="/hosted/login/mfa"`) || !strings.Contains(ask.Body, `name="risk" value="true"`) || strings.Contains(ask.Body, "data:image/png") {
		t.Fatalf("challenge page: %d %s", ask.Status, ask.Body)
	}
	if strings.Contains(ask.Body, "/hosted/login/mfa/webauthn") {
		t.Fatalf("a risk challenge offers a security key: %s", ask.Body)
	}
	// The code went out when the challenge was asked; asking again waits.
	code := e.lastMFACode(t)
	if r := b.post("/hosted/login/mfa/send", url.Values{"ticket": {tk}, "factors": {"email"}, "risk": {"true"}, "factor": {"email"}}); r.Status != 429 || !strings.Contains(r.Body, `name="risk" value="true"`) {
		t.Fatalf("resend too soon: %d %s", r.Status, r.Body)
	}
	e.cooled()
	if r := b.post("/hosted/login/mfa/send", url.Values{"ticket": {tk}, "factors": {"email"}, "risk": {"true"}, "factor": {"email"}}); r.Status != 200 || !strings.Contains(r.Body, `name="risk" value="true"`) {
		t.Fatalf("send: %d %s", r.Status, r.Body)
	}
	code = e.lastMFACode(t)
	if r := b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "factors": {"email"}, "risk": {"true"}, "code": {"000000"}}); r.Status != 401 || !strings.Contains(r.Body, `name="risk" value="true"`) {
		t.Fatalf("wrong code: %d %s", r.Status, r.Body)
	}
	tokens := b.exchange(client, b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "factors": {"email"}, "risk": {"true"}, "code": {code}}))
	for _, kind := range []string{"access_token", "id_token"} {
		if a := strs(claims(t, tokens[kind].(string))["amr"]); !contains(a, "otp") || contains(a, "mfa") {
			t.Fatalf("%s amr = %v", kind, a)
		}
	}
	// A blocking detection stops the hosted sign-in with the generic answer.
	e.riskPolicy(fiber.Map{"actions": fiber.Map{"user_brute_force": "block"}, "thresholds": fiber.Map{"user_failures_per_hour": 2}})
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 {
		t.Fatalf("blocked hosted sign-in: %d %s", p.Status, p.Body)
	}
}

// TestRiskActionChallenge: the pre_sign_in action sees the risk context and
// may ask for a challenge; the completed challenge is not asked again.
func TestRiskActionChallenge(t *testing.T) {
	receiver := &actionReceiver{answers: map[string]string{}}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := riskEnv(t, bootstrap.WithActionTransport(http.DefaultTransport))
	e.verifyEmail(e.Alice)
	created := e.Must("POST", e.Base+"/action-targets", e.Owner, fiber.Map{"name": "Risk", "url": srv.URL}, 201).JSON
	target := created["id"].(string)
	receiver.secret = created["secret"].(string)
	e.Must("PUT", e.Base+"/action-executions/function.pre_sign_in", e.Owner, fiber.Map{"targets": []string{target}}, 200)

	// No risk policy: the action still sees the context, and nothing is asked.
	e.from(riskOK, "PE", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, e.Pass))
	in := receiver.last("function:pre_sign_in")
	risk, _ := in["risk"].(map[string]any)
	if risk == nil || risk["ip"] != riskOK || risk["country"] != "PE" || risk["action"] != "none" || risk["surface"] != "headless" || len(risk["detections"].([]any)) != 0 || risk["challenged"] != nil {
		t.Fatalf("risk input = %v", in["risk"])
	}

	// The target asks for a challenge.
	receiver.answer("function:pre_sign_in", `{"challenge":true}`)
	asked := e.from(riskOK, "PE", "POST", "/identity/v1/login", e.LoginBody(e.AliceEmail, e.Pass))
	token, _ := asked.JSON["mfa_token"].(string)
	if asked.Status != 200 || asked.JSON["reason"] != "risk_challenge" || token == "" {
		t.Fatalf("action challenge: %d %s", asked.Status, asked.Body)
	}
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "email"}, 202)
	done := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": e.lastMFACode(t)}, 200).JSON
	if done["access_token"] == nil {
		t.Fatalf("challenged action loops: %v", done)
	}
	in = receiver.last("function:pre_sign_in")
	if risk, _ := in["risk"].(map[string]any); risk == nil || risk["challenged"] != true {
		t.Fatalf("rerun input = %v", in["risk"])
	}

	// An unverified inbox cannot be challenged: the sign-in goes on.
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"name": "Cy", "email": "cy@example.com", "password": e.Pass}, 201)
	e.Join(e.Org, e.userID("cy@example.com"))
	e.Grant(e.Org, e.userID("cy@example.com"), e.Res, "invoices:read")
	if got := e.from(riskOK, "", "POST", "/identity/v1/login", e.LoginBody("cy@example.com", e.Pass)); got.Status != 200 || got.JSON["access_token"] == nil {
		t.Fatalf("unverified inbox: %d %s", got.Status, got.Body)
	}
}
