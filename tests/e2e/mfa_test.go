package e2e_test

import (
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfatotp"
	"github.com/gofiber/fiber/v2"
)

// totp returns the code of the step offset from now. Only offsets 0 and +1
// are used, in increasing order, so a step boundary passing mid-test never
// pushes a code out of the ±1 window.
func totp(t *testing.T, secret string, offset int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return mfatotp.Code(key, time.Now().Unix()/30+offset)
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func (e *Env) audited(action, target string) int {
	e.t.Helper()
	var n int
	if err := e.DB.Get(&n, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action=$2 AND target_id=$3`, e.EnvID, action, target); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// mfaLogin logs in with the password and expects the second-factor step.
func (e *Env) mfaLogin(email string) Response {
	e.t.Helper()
	r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(email, e.Pass), 200)
	token, _ := r.JSON["mfa_token"].(string)
	if r.JSON["mfa_required"] != true || !strings.HasPrefix(token, "ik_mfa_") || r.JSON["access_token"] != nil {
		e.t.Fatalf("want mfa_required: %s", r.Body)
	}
	return r
}

// TestMFAJourney covers TOTP self-service, the headless second-factor
// step, amr claims, replay and attempt limits, recovery codes, operator
// reset and the organization policy with enrollment during login.
func TestMFAJourney(t *testing.T) {
	e := newEnv(t)
	access := e.Login(e.AliceEmail)
	if a := claims(t, access)["amr"]; !equal(strs(a), []string{"pwd"}) {
		t.Fatalf("password amr = %v", a)
	}
	self := func(method, path, token string, body fiber.Map, want int) Response {
		t.Helper()
		if body == nil {
			return e.Must(method, path+"?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), token, nil, want)
		}
		body["environment_id"], body["audience"] = e.EnvID, e.Audience
		return e.Must(method, path, token, body, want)
	}
	if list := self("GET", "/identity/v1/me/factors", access, nil, 200); len(list.JSON["factors"].([]any)) != 0 {
		t.Fatalf("factors = %s", list.Body)
	}
	e.Must("GET", "/identity/v1/me/factors", "", nil, 401)

	// Enroll: the secret stays unconfirmed (and login unchanged) until a code proves it.
	start := self("POST", "/identity/v1/me/factors/totp", access, fiber.Map{}, 201)
	secret, _ := start.JSON["secret"].(string)
	if secret == "" || !strings.HasPrefix(start.JSON["otpauth_uri"].(string), "otpauth://totp/") {
		t.Fatalf("start = %s", start.Body)
	}
	e.Login(e.AliceEmail)
	self("POST", "/identity/v1/me/factors/totp/confirm", access, fiber.Map{"code": "000000"}, 422)
	confirmed := self("POST", "/identity/v1/me/factors/totp/confirm", access, fiber.Map{"code": totp(t, secret, 0)}, 200)
	recovery := strs(confirmed.JSON["recovery_codes"])
	if len(recovery) != 10 || e.audited("mfa.enrolled", e.Alice) != 1 {
		t.Fatalf("confirm = %s", confirmed.Body)
	}
	self("POST", "/identity/v1/me/factors/totp", access, fiber.Map{}, 409)
	var sealed string
	if err := e.DB.Get(&sealed, `SELECT secret_sealed FROM user_factors WHERE user_id=$1`, e.Alice); err != nil || strings.Contains(sealed, secret) {
		t.Fatalf("secret at rest: %v", err)
	}

	// Login now needs the second factor; the code yields tokens with amr.
	pending := e.mfaLogin(e.AliceEmail)
	if !contains(strs(pending.JSON["factors"]), "totp") || pending.JSON["enrollment_required"] != false {
		t.Fatalf("pending = %s", pending.Body)
	}
	token := pending.JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": "000000"}, 401)
	code := totp(t, secret, 1)
	pair := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("mfa amr = %v", a)
	}
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 401) // token spent
	refresh := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": pair.JSON["refresh_token"]}
	rotated := e.Must("POST", "/identity/v1/refresh", "", refresh, 200)
	if a := strs(claims(t, rotated.JSON["access_token"].(string))["amr"]); !contains(a, "mfa") {
		t.Fatalf("refresh lost amr: %v", a)
	}
	if before, after := claims(t, pair.JSON["access_token"].(string))["auth_time"], claims(t, rotated.JSON["access_token"].(string))["auth_time"]; before == nil || before != after {
		t.Fatalf("auth_time %v -> %v", before, after)
	}

	// A code works once (replay guard), a recovery code too.
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": code}, 401)
	pair = e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": strings.ToUpper(recovery[0])}, 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"pwd", "mfa"}) {
		t.Fatalf("recovery amr = %v", a)
	}
	if e.audited("mfa.recovery_used", e.Alice) != 1 {
		t.Fatal("recovery use not audited")
	}
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": recovery[0]}, 401)

	// Five wrong codes burn the token, even for a right code afterwards.
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	for range 5 {
		e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": "123123"}, 401)
	}
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": recovery[1]}, 401)

	// Self-service: regenerate needs possession; old codes die.
	self("POST", "/identity/v1/me/factors/recovery-codes", access, fiber.Map{"code": "nope-nope-nope"}, 422)
	fresh := strs(self("POST", "/identity/v1/me/factors/recovery-codes", access, fiber.Map{"code": recovery[1]}, 200).JSON["recovery_codes"])
	if len(fresh) != 10 || e.audited("mfa.recovery_regenerated", e.Alice) != 1 {
		t.Fatal("regenerate")
	}
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": recovery[2]}, 401)

	// Operator view never exposes secrets; reset removes everything.
	summary := e.Must("GET", e.Base+"/users/"+e.Alice+"/factors", e.Owner, nil, 200)
	factors := summary.JSON["factors"].([]any)
	if len(factors) != 1 || summary.JSON["recovery_codes_remaining"] != float64(10) || strings.Contains(summary.Body, "secret") {
		t.Fatalf("operator summary = %s", summary.Body)
	}
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/factors", e.Owner, nil, 204)
	if e.audited("mfa.reset", e.Alice) != 1 {
		t.Fatal("reset not audited")
	}
	e.Login(e.AliceEmail)

	// Organization policy: users without a factor enroll while logging in.
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": true}, 204)
	if org := e.Must("GET", e.Base+"/organizations/"+e.Org, e.Owner, nil, 200); org.JSON["mfa_required"] != true || org.JSON["mfa_for_federated"] != false {
		t.Fatalf("org = %s", org.Body)
	}
	pending = e.mfaLogin(e.AliceEmail)
	if pending.JSON["enrollment_required"] != true {
		t.Fatalf("want enrollment: %s", pending.Body)
	}
	token = pending.JSON["mfa_token"].(string)
	enroll := e.Must("POST", "/identity/v1/mfa/enroll", "", fiber.Map{"mfa_token": token}, 200)
	secret, _ = enroll.JSON["secret"].(string)
	if secret == "" || enroll.JSON["otpauth_uri"] == nil {
		t.Fatalf("enroll = %s", enroll.Body)
	}
	pair = e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": totp(t, secret, 0)}, 200)
	recovery = strs(pair.JSON["recovery_codes"])
	if len(recovery) != 10 || pair.JSON["access_token"] == nil || !contains(strs(claims(t, pair.JSON["access_token"].(string))["amr"]), "otp") {
		t.Fatalf("enrolled login = %s", pair.Body)
	}
	access = pair.JSON["access_token"].(string)

	// Removing the factor needs a code; the policy then requires enrolling again.
	self("DELETE", "/identity/v1/me/factors/totp", access, fiber.Map{"code": "000000"}, 422)
	self("DELETE", "/identity/v1/me/factors/totp", access, fiber.Map{"code": recovery[0]}, 204)
	if e.audited("mfa.removed", e.Alice) != 1 {
		t.Fatal("remove not audited")
	}
	if e.mfaLogin(e.AliceEmail).JSON["enrollment_required"] != true {
		t.Fatal("policy must ask for enrollment again")
	}

	// Permanent deletion erases factors.
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/permanent", e.Owner, nil, 204)
	var left int
	if err := e.DB.Get(&left, `SELECT (SELECT count(*) FROM user_factors)+(SELECT count(*) FROM recovery_codes)+(SELECT count(*) FROM mfa_logins)`); err != nil || left != 0 {
		t.Fatalf("erasure left %d rows (%v)", left, err)
	}
}

// TestHostedMFA covers the hosted pages: enrollment with a QR code when the
// organization requires MFA, recovery codes shown once, the code page for
// enrolled users and amr in OAuth tokens.
func TestHostedMFA(t *testing.T) {
	e := newEnv(t)
	client := e.hostedClient()
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": true}, 204)

	b := e.browser()
	tk := b.authorize(client).field("ticket")
	enroll := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if enroll.Status != 200 || !strings.Contains(enroll.Body, `src="data:image/png;base64,`) || !strings.Contains(enroll.Header.Get("Content-Security-Policy"), "img-src https: data:") {
		t.Fatalf("enroll page: %d %s", enroll.Status, enroll.Body)
	}
	secret := between(enroll.Body, "<p><code>", "</code></p>")
	if secret == "" {
		t.Fatalf("no secret on the page: %s", enroll.Body)
	}
	if r := b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "enrolling": {"true"}, "code": {"000000"}}); r.Status != 401 || !strings.Contains(r.Body, "data:image/png") {
		t.Fatalf("wrong enrollment code: %d %s", r.Status, r.Body)
	}
	codes := b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "enrolling": {"true"}, "code": {totp(t, secret, 0)}})
	if codes.Status != 200 || strings.Count(codes.Body, "<li><code>") != 10 {
		t.Fatalf("recovery page: %d %s", codes.Status, codes.Body)
	}
	tokens := b.exchange(client, b.post("/hosted/login/mfa/continue", url.Values{"ticket": {tk}}))
	for _, kind := range []string{"access_token", "id_token"} {
		if a := strs(claims(t, tokens[kind].(string))["amr"]); !equal(a, []string{"pwd", "otp", "mfa"}) {
			t.Fatalf("%s amr = %v", kind, a)
		}
	}

	// Enrolled: the code page comes before tokens.
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	ask := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if ask.Status != 200 || !strings.Contains(ask.Body, `action="/hosted/login/mfa"`) || strings.Contains(ask.Body, "data:image/png") {
		t.Fatalf("mfa page: %d %s", ask.Status, ask.Body)
	}
	if r := b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "code": {"000000"}}); r.Status != 401 || !strings.Contains(r.Body, "4 attempts left.") {
		t.Fatalf("wrong code: %d %s", r.Status, r.Body)
	}
	tokens = b.exchange(client, b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "code": {totp(t, secret, 1)}}))
	if a := strs(claims(t, tokens["id_token"].(string))["amr"]); !contains(a, "otp") {
		t.Fatalf("id_token amr = %v", a)
	}
	// An OAuth access token carries auth_time (fosite encodes it as a
	// float) and is fresh enough to manage factors: a wrong code reaches
	// the service (422), not the re-authentication gate (403).
	access := tokens["access_token"].(string)
	aud := claims(t, access)["aud"]
	if list, ok := aud.([]any); ok && len(list) > 0 {
		aud = list[0]
	}
	self := fiber.Map{"environment_id": e.EnvID, "audience": aud, "code": "000000"}
	if r := e.Must("POST", "/identity/v1/me/factors/recovery-codes", access, self, 422); !strings.Contains(r.Body, "INVALID_CODE") {
		t.Fatalf("oauth token self-service = %s", r.Body)
	}

	// Parallel guesses share one attempt budget: at most 5 are checked; the
	// rest (and anything after) find the login gone and restart sign-in.
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	var cookies []*http.Cookie
	for _, c := range b.cookies {
		cookies = append(cookies, c)
	}
	statuses := make(chan int, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/hosted/login/mfa", strings.NewReader(url.Values{"ticket": {tk}, "code": {"000000"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range cookies {
				req.AddCookie(c)
			}
			res, err := e.App.Test(req, 10000)
			if err != nil {
				statuses <- 0
				return
			}
			res.Body.Close()
			statuses <- res.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	var attempts int
	if err := e.DB.Get(&attempts, `SELECT COALESCE(max(mfa_attempts),0) FROM hosted_logins`); err != nil || attempts > 5 {
		t.Fatalf("attempts = %d (%v)", attempts, err)
	}
	for s := range statuses {
		if s != 401 {
			t.Fatalf("parallel wrong code status %d", s)
		}
	}
	if r := b.post("/hosted/login/mfa", url.Values{"ticket": {tk}, "code": {"000000"}}); r.Status != 401 || !strings.Contains(r.Body, `action="/hosted/login/identify"`) {
		t.Fatalf("after attempts: %d %s", r.Status, r.Body)
	}
}

// TestMFAFederatedAndImpersonation: SSO trusts the identity provider unless
// the organization opts in; impersonated sessions cannot manage factors.
func TestMFAFederatedAndImpersonation(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(idp.Client().Transport)
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})
	provider := map[string]any{"sub": "alice-sub", "email": e.AliceEmail, "email_verified": true}
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": true}, 204)

	r := e.sso(idp, conn, e.Org, provider)
	if r.Status != 200 || r.JSON["access_token"] == nil {
		t.Fatalf("federated login under mfa_required: %d %v", r.Status, r.JSON)
	}
	if a := strs(claims(t, r.JSON["access_token"].(string))["amr"]); !equal(a, []string{"fed"}) {
		t.Fatalf("federated amr = %v", a)
	}
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_for_federated": true}, 204)
	r = e.sso(idp, conn, e.Org, provider)
	if r.Status != 200 || r.JSON["mfa_required"] != true || r.JSON["enrollment_required"] != true || r.JSON["access_token"] != nil {
		t.Fatalf("federated login with mfa_for_federated: %d %v", r.Status, r.JSON)
	}
	token := r.JSON["mfa_token"].(string)
	secret := e.Must("POST", "/identity/v1/mfa/enroll", "", fiber.Map{"mfa_token": token}, 200).JSON["secret"].(string)
	pair := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": totp(t, secret, 0)}, 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"fed", "otp", "mfa"}) {
		t.Fatalf("federated mfa amr = %v", a)
	}

	// Impersonation tokens cannot see or change the user's factors.
	imp := e.Must("POST", e.Base+"/impersonations", e.Owner, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "reason": "support ticket 42"}, 200)
	token = imp.JSON["access_token"].(string)
	e.Must("GET", "/identity/v1/me/factors?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), token, nil, 403)
	e.Must("POST", "/identity/v1/me/factors/totp", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 403)
}

// TestMFALockoutAndFreshAuth: wrong codes lock the factor across fresh
// pending logins (a new mfa_token buys no new guesses); factor changes need
// a recent sign-in, which refreshing does not renew.
func TestMFALockoutAndFreshAuth(t *testing.T) {
	e := newEnv(t)
	access := e.Login(e.AliceEmail)
	body := fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}
	secret := e.Must("POST", "/identity/v1/me/factors/totp", access, body, 201).JSON["secret"].(string)
	body["code"] = totp(t, secret, 0)
	e.Must("POST", "/identity/v1/me/factors/totp/confirm", access, body, 200)

	// Two pending logins, five wrong codes each: the factor locks.
	for range 2 {
		token := e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
		for range 5 {
			e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": "123123"}, 401)
		}
	}
	token := e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	locked := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": totp(t, secret, 1)}, 429)
	if !strings.Contains(locked.Body, "MFA_LOCKED") || e.audited("mfa.locked", e.Alice) != 1 {
		t.Fatalf("lockout = %s", locked.Body)
	}
	// It lifts after the lockout; the right code then resets the count.
	if _, err := e.DB.Exec(`UPDATE user_mfa_state SET locked_until=now()-interval '1 second' WHERE user_id=$1`, e.Alice); err != nil {
		t.Fatal(err)
	}
	pair := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "code": totp(t, secret, 1)}, 200)
	var failures int
	if err := e.DB.Get(&failures, `SELECT failed_attempts FROM user_mfa_state WHERE user_id=$1`, e.Alice); err != nil || failures != 0 {
		t.Fatalf("failures after success = %d (%v)", failures, err)
	}

	// A session that signed in long ago cannot change factors, even with a
	// freshly refreshed access token.
	if _, err := e.DB.Exec(`UPDATE sessions SET authenticated_at=now()-interval '1 hour' WHERE user_id=$1`, e.Alice); err != nil {
		t.Fatal(err)
	}
	refresh := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": pair.JSON["refresh_token"]}
	stale := e.Must("POST", "/identity/v1/refresh", "", refresh, 200).JSON["access_token"].(string)
	body["code"] = totp(t, secret, 2)
	if r := e.Must("POST", "/identity/v1/me/factors/recovery-codes", stale, body, 403); !strings.Contains(r.Body, "REAUTHENTICATION_REQUIRED") {
		t.Fatalf("stale session = %s", r.Body)
	}
	e.Must("GET", "/identity/v1/me/factors?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), stale, nil, 200)
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	j := strings.Index(s, close)
	if j < 0 {
		return ""
	}
	return s[:j]
}
