package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
)

// smsInbox is an SMS webhook receiver on loopback.
type smsInbox struct {
	mu   sync.Mutex
	sent []map[string]string
	fail bool
}

func (s *smsInbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		w.WriteHeader(503)
		return
	}
	var m map[string]string
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &m)
	m["authorization"] = r.Header.Get("Authorization")
	m["signature"] = r.Header.Get("webhook-signature")
	s.sent = append(s.sent, m)
	w.WriteHeader(202)
}

func (s *smsInbox) last(t *testing.T) map[string]string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) == 0 {
		t.Fatal("no SMS sent")
	}
	return s.sent[len(s.sent)-1]
}

func (s *smsInbox) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

// mfaCodes counts emails of purpose mfa.
func (e *Env) mfaCodes() int {
	e.Mail.mu.Lock()
	defer e.Mail.mu.Unlock()
	n := 0
	for _, m := range e.Mail.Sent {
		if m.Purpose == "mfa" {
			n++
		}
	}
	return n
}

func (e *Env) lastMFACode(t *testing.T) string {
	t.Helper()
	m, ok := e.Mail.Last("mfa")
	if !ok || len(m.Code) != 6 {
		t.Fatalf("no mfa email: %+v", m)
	}
	return m.Code
}

// cooled lifts the per-factor resend cooldown (config.FactorCodeCooldown).
func (e *Env) cooled() {
	e.t.Helper()
	if _, err := e.DB.Exec(`UPDATE user_factors SET code_sent_at = now() - interval '1 minute' WHERE code_sent_at IS NOT NULL`); err != nil {
		e.t.Fatal(err)
	}
}

// TestCodeFactors covers email and SMS second factors: allowed_factors on
// the environment and organization, the SMS provider API, self-service
// enrollment, headless login with a sent code, amr, the same-inbox rule
// and that email webhooks never see purpose mfa unless email is allowed.
func TestCodeFactors(t *testing.T) {
	inbox := &smsInbox{}
	srv := httptest.NewServer(inbox)
	defer srv.Close()
	// The SMS receiver is on loopback; environment endpoints are guarded.
	e := newEnv(t, bootstrap.WithMail(authmodule.Mail{SMSClient: http.DefaultTransport}))
	self := func(method, path, token string, body fiber.Map, want int) Response {
		t.Helper()
		if body == nil {
			return e.Must(method, path+"?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), token, nil, want)
		}
		body["environment_id"], body["audience"] = e.EnvID, e.Audience
		return e.Must(method, path, token, body, want)
	}
	policy := e.Base + "/sign-in-policy"

	// Default: TOTP and security keys only; code factors are refused.
	if p := e.Must("GET", policy, e.Owner, nil, 200); !equal(strs(p.JSON["allowed_factors"]), []string{"totp", "webauthn"}) {
		t.Fatalf("default policy = %s", p.Body)
	}
	access := e.Login(e.AliceEmail)
	if r := self("POST", "/identity/v1/me/factors/email", access, fiber.Map{}, 422); !strings.Contains(r.Body, "FACTOR_NOT_ALLOWED") {
		t.Fatalf("email refused = %s", r.Body)
	}
	if e.mfaCodes() != 0 {
		t.Fatal("an mfa email was sent while the email factor is not allowed")
	}
	full := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true}
	factors := func(kinds ...string) fiber.Map {
		m := fiber.Map{"allowed_factors": append([]string{}, kinds...)}
		for k, v := range full {
			m[k] = v
		}
		return m
	}
	e.Must("PUT", policy, e.Owner, factors("totp", "fax"), 400)
	e.Must("PUT", policy, e.Owner, factors([]string{}...), 400)
	if p := e.Must("GET", policy, e.Owner, nil, 200); !equal(strs(p.JSON["allowed_factors"]), []string{"totp", "webauthn"}) {
		t.Fatalf("refused update changed the policy: %s", p.Body)
	}
	e.Must("PUT", policy, e.Owner, factors("totp", "email", "sms"), 200)
	// Saving the policy without allowed_factors keeps them.
	if p := e.Must("PUT", policy, e.Owner, full, 200); !equal(strs(p.JSON["allowed_factors"]), []string{"totp", "email", "sms"}) {
		t.Fatalf("factors lost: %s", p.Body)
	}

	// Email factor: a code to the account address confirms it.
	sent := self("POST", "/identity/v1/me/factors/email", access, fiber.Map{}, 202)
	if sent.JSON["factor"] != "email" || sent.JSON["destination"] != "a•••@example.com" {
		t.Fatalf("email start = %s", sent.Body)
	}
	self("POST", "/identity/v1/me/factors/email/confirm", access, fiber.Map{"code": "000000"}, 422)
	confirmed := self("POST", "/identity/v1/me/factors/email/confirm", access, fiber.Map{"code": e.lastMFACode(t)}, 200)
	recovery := strs(confirmed.JSON["recovery_codes"])
	if len(recovery) != 10 || e.audited("mfa.enrolled", e.Alice) != 1 {
		t.Fatalf("email confirm = %s", confirmed.Body)
	}

	// Headless login: challenge sends a code; verify yields amr otp+mfa.
	pending := e.mfaLogin(e.AliceEmail)
	if f := strs(pending.JSON["factors"]); !contains(f, "email") || !contains(f, "recovery") {
		t.Fatalf("pending = %s", pending.Body)
	}
	token := pending.JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "sms"}, 422)
	if r := e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "email"}, 429); !strings.Contains(r.Body, "CODE_COOLDOWN") {
		t.Fatalf("cooldown = %s", r.Body)
	}
	e.cooled()
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "email"}, 202)
	code := e.lastMFACode(t)
	pair := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("email mfa amr = %v", a)
	}
	// A code is single use.
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 401)

	// Same inbox: an email-code sign-in cannot use the email factor; with no
	// other factor the user must enroll another one.
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"otp_enabled": true}, 204)
	challenge := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "login"}, 202).JSON
	login, _ := e.Mail.Last("login")
	emailLogin := e.Must("POST", "/identity/v1/challenges/verify", "", fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res,
		"challenge_id": challenge["challenge_id"], "purpose": "login", "code": login.Code}, 200)
	if emailLogin.JSON["mfa_required"] != true || contains(strs(emailLogin.JSON["factors"]), "email") || emailLogin.JSON["enrollment_required"] != true {
		t.Fatalf("email-code login = %s", emailLogin.Body)
	}

	// SMS provider: validated, secrets never returned, status and test.
	sms := e.Base + "/sms"
	e.Must("GET", sms, e.Owner, nil, 404)
	e.Must("PUT", sms, e.Owner, fiber.Map{"provider": "webhook", "webhook_url": srv.URL}, 400) // token required
	e.Must("PUT", sms, e.Owner, fiber.Map{"provider": "twilio", "account_sid": "AC123", "auth_token": "x", "from_number": "+15550001111"}, 400)
	cfg := e.Must("PUT", sms, e.Owner, fiber.Map{"provider": "webhook", "webhook_url": srv.URL, "webhook_token": "sms-secret"}, 200)
	if cfg.JSON["has_secret"] != true || strings.Contains(cfg.Body, "sms-secret") {
		t.Fatalf("sms config = %s", cfg.Body)
	}
	var stored string
	if err := e.DB.Get(&stored, `SELECT secret_sealed FROM sms_configs WHERE environment_id=$1`, e.EnvID); err != nil || stored == "" || strings.Contains(stored, "sms-secret") {
		t.Fatalf("sealed secret: %q %v", stored, err)
	}
	e.Must("POST", sms+"/test", e.Owner, fiber.Map{"phone": "555"}, 400)
	if a := e.Must("POST", sms+"/test", e.Owner, fiber.Map{"phone": "+15551234567"}, 200).JSON; a["delivered"] != true || a["purpose"] != "test" {
		t.Fatalf("test sms = %v", a)
	}
	if m := inbox.last(t); m["phone"] != "+15551234567" || m["purpose"] != "test" || m["code"] != "" || m["authorization"] != "Bearer sms-secret" || !strings.HasPrefix(m["signature"], "v1,") {
		t.Fatalf("test payload = %v", m)
	}
	if st := e.Must("GET", sms+"/status", e.Owner, nil, 200).JSON; st["configured"] != true || st["provider"] != "webhook" || st["last_attempt"] == nil {
		t.Fatalf("sms status = %v", st)
	}

	// SMS factor: the phone is confirmed by the first code.
	self("POST", "/identity/v1/me/factors/sms", access, fiber.Map{"phone": "5551234567"}, 400)
	sent = self("POST", "/identity/v1/me/factors/sms", access, fiber.Map{"phone": "+1 555 765 4321"}, 202)
	text := inbox.last(t)
	if sent.JSON["factor"] != "sms" || text["phone"] != "+15557654321" || text["purpose"] != "phone_verification" || len(text["code"]) != 6 || !strings.Contains(text["body"], text["code"]) {
		t.Fatalf("sms start = %s / %v", sent.Body, text)
	}
	if strings.Contains(sent.JSON["destination"].(string), "7654321") {
		t.Fatalf("destination not masked: %s", sent.Body)
	}
	self("POST", "/identity/v1/me/factors/sms/confirm", access, fiber.Map{"code": text["code"]}, 200)
	var phone string
	var verified bool
	if err := e.DB.QueryRow(`SELECT coalesce(phone,''), phone_verified FROM users WHERE id=$1`, e.Alice).Scan(&phone, &verified); err != nil || phone != "+15557654321" || !verified {
		t.Fatalf("user phone %q %v %v", phone, verified, err)
	}
	if u := e.Must("GET", e.Base+"/users/"+e.Alice, e.Owner, nil, 200).JSON; u["phone"] != "+15557654321" || u["phone_verified"] != true {
		t.Fatalf("user = %v", u)
	}
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"phone": "12"}, 400)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"phone": "+1 555 765 4321"}, 204) // same number: still verified
	if u := e.Must("GET", e.Base+"/users/"+e.Alice, e.Owner, nil, 200).JSON; u["phone_verified"] != true {
		t.Fatalf("same number unverified: %v", u)
	}

	// Login with SMS: amr sms+mfa.
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	e.cooled()
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "sms"}, 202)
	if m := inbox.last(t); m["purpose"] != "mfa" {
		t.Fatalf("login sms = %v", m)
	}
	pair = e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": inbox.last(t)["code"]}, 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"pwd", "sms", "mfa"}) {
		t.Fatalf("sms mfa amr = %v", a)
	}

	// A failed text is reported and recorded; the provider can be removed.
	inbox.mu.Lock()
	inbox.fail = true
	inbox.mu.Unlock()
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	before := inbox.count()
	e.cooled()
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": token, "factor": "sms"}, 502)
	if st := e.Must("GET", sms+"/status", e.Owner, nil, 200).JSON; st["last_failure"] == nil || inbox.count() != before {
		t.Fatalf("failure not recorded: %v", st)
	}
	inbox.mu.Lock()
	inbox.fail = false
	inbox.mu.Unlock()

	// Organization narrows: without sms members cannot use it.
	org := e.Base + "/organizations/" + e.Org
	e.Must("PATCH", org, e.Owner, fiber.Map{"allowed_factors": []string{"nope"}}, 400)
	e.Must("PATCH", org, e.Owner, fiber.Map{"allowed_factors": []string{"totp", "email"}}, 204)
	if o := e.Must("GET", org, e.Owner, nil, 200); !equal(strs(o.JSON["allowed_factors"]), []string{"totp", "email"}) {
		t.Fatalf("org = %s", o.Body)
	}
	pending = e.mfaLogin(e.AliceEmail)
	if f := strs(pending.JSON["factors"]); contains(f, "sms") || !contains(f, "email") {
		t.Fatalf("org-narrowed factors = %v", f)
	}
	e.Must("POST", "/identity/v1/mfa/challenge", "", fiber.Map{"mfa_token": pending.JSON["mfa_token"], "factor": "sms"}, 422)

	// Environment removes email and the org keeps only it: nothing usable,
	// so the user enrolls a factor both allow (totp).
	e.Must("PUT", policy, e.Owner, factors("totp", "sms"), 200)
	pending = e.mfaLogin(e.AliceEmail)
	if pending.JSON["enrollment_required"] != true || !equal(strs(pending.JSON["factors"]), []string{"totp"}) {
		t.Fatalf("no usable factor = %s", pending.Body)
	}
	// The organization keeps only a kind the environment refuses: no factor
	// can be added, so the login is refused instead of parking one nothing
	// finishes.
	e.Must("PATCH", org, e.Owner, fiber.Map{"allowed_factors": []string{"email"}}, 204)
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 403); r.JSON["error"].(map[string]any)["code"] != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("disjoint factors = %s", r.Body)
	}

	// Removing the SMS factor needs a code; operator reset clears the phone factor.
	e.Must("PATCH", org, e.Owner, fiber.Map{"allowed_factors": []string{"totp", "email", "sms", "webauthn"}}, 204)
	e.cooled()
	self("POST", "/identity/v1/me/factors/sms/challenge", access, fiber.Map{}, 202)
	self("DELETE", "/identity/v1/me/factors/sms", access, fiber.Map{"code": "000000"}, 422)
	self("DELETE", "/identity/v1/me/factors/sms", access, fiber.Map{"code": inbox.last(t)["code"]}, 204)
	summary := e.Must("GET", e.Base+"/users/"+e.Alice+"/factors", e.Owner, nil, 200)
	for _, f := range summary.JSON["factors"].([]any) {
		if f.(map[string]any)["kind"] == "sms" {
			t.Fatalf("sms factor left: %s", summary.Body)
		}
	}
	// An operator-set number is no longer verified.
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"phone": "+34600000000"}, 204)
	if u := e.Must("GET", e.Base+"/users/"+e.Alice, e.Owner, nil, 200).JSON; u["phone"] != "+34600000000" || u["phone_verified"] != false {
		t.Fatalf("operator phone = %v", u)
	}

	e.Must("DELETE", sms, e.Owner, nil, 204)
	e.Must("GET", sms, e.Owner, nil, 404)
	var audits int
	if err := e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action IN ('sms.update','sms.test','sms.delete')`, e.EnvID); err != nil || audits != 3 {
		t.Fatalf("sms audits = %d (%v)", audits, err)
	}
}
