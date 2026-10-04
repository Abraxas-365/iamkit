package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func ssoCode(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Code
	}
	return ""
}

// TestOperatorSSORepository covers 014 through mgmtpg: single-use,
// browser-bound states, linking by active operator email, one identity per
// issuer per operator, disabled operators and the owner reset.
func TestOperatorSSORepository(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	repo := mgmtpg.New(db)
	workspace, ann, bob := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, q := range []string{
		`INSERT INTO workspaces(id,name) VALUES('` + workspace + `','W')`,
		`INSERT INTO operators(id,email) VALUES('` + ann + `','ann@acme.com'),('` + bob + `','bob@acme.com')`,
		`INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES('` + workspace + `','` + ann + `','admin'),('` + workspace + `','` + bob + `','viewer')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ws, annID := identity.MustParseWorkspaceID(workspace), identity.MustParseOperatorID(ann)

	// States: wrong binding refused without spending the state; right one
	// consumes it once; expired ones are refused and pruned.
	state := management.SSOState{Provider: "okta", Binding: []byte("bind"), Nonce: "n", Verifier: "v"}
	if err := repo.SaveSSOState(ctx, []byte("s1"), state, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeSSOState(ctx, []byte("s1"), []byte("other")); ssoCode(err) != management.CodeSSOExpired {
		t.Fatalf("other browser: %v", err)
	}
	got, err := repo.ConsumeSSOState(ctx, []byte("s1"), []byte("bind"))
	if err != nil || got.Provider != "okta" || got.Nonce != "n" || got.Verifier != "v" {
		t.Fatalf("consume: %+v %v", got, err)
	}
	if _, err = repo.ConsumeSSOState(ctx, []byte("s1"), []byte("bind")); ssoCode(err) != management.CodeSSOExpired {
		t.Fatalf("replay: %v", err)
	}
	if err = repo.SaveSSOState(ctx, []byte("old"), state, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ConsumeSSOState(ctx, []byte("old"), []byte("bind")); ssoCode(err) != management.CodeSSOExpired {
		t.Fatalf("expired: %v", err)
	}
	if err = repo.SaveSSOState(ctx, []byte("s2"), state, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM operator_sso_states WHERE secret_hash='old'`); n != 0 {
		t.Fatal("expired state not pruned")
	}

	// Linking.
	const iss = "https://acme.okta.com"
	if _, found, err := repo.LinkedOperator(ctx, iss, "ann-1"); found || err != nil {
		t.Fatalf("unlinked: %v %v", found, err)
	}
	if _, err = repo.LinkOperator(ctx, iss, "x", "okta", "nobody@acme.com"); ssoCode(err) != management.CodeSSONotAuthorized {
		t.Fatalf("unknown email: %v", err)
	}
	p, err := repo.LinkOperator(ctx, iss, "ann-1", "okta", "ann@acme.com")
	if err != nil || p.OperatorID != annID || p.WorkspaceID != ws || p.Role != "admin" {
		t.Fatalf("link: %+v %v", p, err)
	}
	if p, found, err := repo.LinkedOperator(ctx, iss, "ann-1"); !found || err != nil || p.OperatorID != annID || p.Role != "admin" {
		t.Fatalf("linked: %+v %v %v", p, found, err)
	}
	// A second subject of the same issuer (reassigned mailbox) is refused;
	// another issuer is fine.
	if _, err = repo.LinkOperator(ctx, iss, "ann-2", "okta", "ann@acme.com"); ssoCode(err) != management.CodeSSONotAuthorized {
		t.Fatalf("second subject: %v", err)
	}
	if _, err = repo.LinkOperator(ctx, "https://accounts.google.com", "g-ann", "google", "ann@acme.com"); err != nil {
		t.Fatalf("second issuer: %v", err)
	}
	if err = repo.TouchIdentity(ctx, iss, "ann-1"); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.Identities(ctx, ws, annID)
	if err != nil || len(ids) != 2 || ids[0].Issuer != iss || ids[0].Provider != "okta" || ids[0].LastLogin == nil {
		t.Fatalf("identities: %+v %v", ids, err)
	}
	if _, err = repo.Identities(ctx, identity.NewWorkspaceID(), annID); err == nil {
		t.Fatal("identities visible from another workspace")
	}

	// Disabled operators: linked identities refuse, email links refuse.
	if _, err = db.Exec(`UPDATE workspace_members SET active=false WHERE operator_id=$1`, bob); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.LinkOperator(ctx, iss, "bob-1", "okta", "bob@acme.com"); ssoCode(err) != management.CodeSSONotAuthorized {
		t.Fatalf("disabled link: %v", err)
	}
	if _, err = db.Exec(`INSERT INTO operator_identities(issuer,subject,operator_id,provider,email) VALUES($1,'bob-1',$2,'okta','bob@acme.com')`, iss, bob); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repo.LinkedOperator(ctx, iss, "bob-1"); !found || ssoCode(err) != management.CodeSSONotAuthorized {
		t.Fatalf("disabled linked: %v %v", found, err)
	}

	// Concurrent first sign-ins of one identity: exactly one links, the
	// other is refused (and matches by subject next time).
	carl := uuid.NewString()
	for _, q := range []string{
		`INSERT INTO operators(id,email) VALUES('` + carl + `','carl@acme.com')`,
		`INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES('` + workspace + `','` + carl + `','viewer')`,
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := repo.LinkOperator(ctx, iss, "carl-1", "okta", "carl@acme.com")
			errs <- err
		}()
	}
	var linked, refused int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			linked++
		case ssoCode(err) == management.CodeSSONotAuthorized:
			refused++
		default:
			t.Fatalf("race: %v", err)
		}
	}
	if linked != 1 || refused != 1 || count(t, db, `SELECT count(*) FROM operator_identities WHERE subject='carl-1'`) != 1 {
		t.Fatalf("race: linked %d refused %d", linked, refused)
	}
	if p, found, err := repo.LinkedOperator(ctx, iss, "carl-1"); !found || err != nil || p.OperatorID.String() != carl {
		t.Fatalf("after race: %+v %v %v", p, found, err)
	}

	// An operator of several workspaces always lands in the oldest one, by
	// password and by single sign-on alike.
	newer := uuid.NewString()
	for _, q := range []string{
		`INSERT INTO workspaces(id,name,created_at) VALUES('` + newer + `','Newer',now()+interval '1 day')`,
		`INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES('` + newer + `','` + carl + `','owner')`,
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for range 5 {
		if p, _, err := repo.LinkedOperator(ctx, iss, "carl-1"); err != nil || p.WorkspaceID != ws || p.Role != "viewer" {
			t.Fatalf("sso workspace: %+v %v", p, err)
		}
		if a, err := repo.PasswordByEmail(ctx, "carl@acme.com"); err != nil || a.Principal.WorkspaceID != ws {
			t.Fatalf("password workspace: %+v %v", a, err)
		}
	}
	// Disabled in the oldest workspace only: the active membership is used.
	if _, err = db.Exec(`UPDATE workspace_members SET active=false WHERE workspace_id=$1 AND operator_id=$2`, workspace, carl); err != nil {
		t.Fatal(err)
	}
	if p, _, err := repo.LinkedOperator(ctx, iss, "carl-1"); err != nil || p.WorkspaceID.String() != newer || p.Role != "owner" {
		t.Fatalf("active workspace: %+v %v", p, err)
	}

	// Owner reset removes the identities and revokes sessions.
	p.Method = management.MethodSSO
	if err = repo.CreateSession(ctx, identity.NewSessionID(), p, []byte("sess"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = repo.UnlinkIdentities(ctx, identity.NewWorkspaceID(), annID); err == nil {
		t.Fatal("reset across workspaces")
	}
	if err = repo.UnlinkIdentities(ctx, ws, annID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM operator_identities WHERE operator_id=$1`, ann); n != 0 {
		t.Fatalf("identities left: %d", n)
	}
	if _, err = repo.AuthenticateSession(ctx, []byte("sess")); err == nil {
		t.Fatal("session survived the reset")
	}
	if _, err = repo.LinkOperator(ctx, iss, "ann-2", "okta", "ann@acme.com"); err != nil {
		t.Fatalf("relink after reset: %v", err)
	}
}

// operatorSSO starts an operator single sign-on at the provider and
// follows the callback with claims, returning the callback response.
func operatorSSO(t *testing.T, h *Harness, p *fakeIdP, provider string, claims map[string]any) *http.Response {
	t.Helper()
	res, err := h.App.Test(httptest.NewRequest("GET", "/management/v1/sso/"+provider+"/start", nil), 10000)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != fiber.StatusFound {
		return res
	}
	authorization, _ := url.Parse(res.Header.Get("Location"))
	if authorization.Query().Get("redirect_uri") != "https://iam.example/management/v1/sso/callback" {
		t.Fatalf("redirect_uri: %s", authorization)
	}
	p.mu.Lock()
	p.nonce, p.claims = authorization.Query().Get("nonce"), claims
	p.mu.Unlock()
	req := httptest.NewRequest("GET", "/management/v1/sso/callback?code=provider-code&state="+url.QueryEscape(authorization.Query().Get("state")), nil)
	for _, c := range res.Cookies() {
		req.AddCookie(c)
	}
	out, err := h.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	return out
}

func sessionCookie(res *http.Response) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == "__Host-iamkit-operator" && c.Value != "" {
			return c
		}
	}
	return nil
}

// TestOperatorSSOJourney signs an invited operator in through a configured
// OIDC provider with password sign-in disabled, then the owner resets the
// operator's identity.
func TestOperatorSSOJourney(t *testing.T) {
	requireE2E(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := newFakeIdP(t, key, "console")
	sso := bootstrap.OperatorSSO{
		Settings: management.SSOSettings{Password: management.PasswordDisabled, Providers: []management.SSOProvider{
			{ID: "acme", Name: "Acme", Type: management.SSOTypeOIDC, Issuer: idp.URL, Client: "console", AllowedDomains: []string{"acme.com"}},
		}},
		Secrets:   map[string]string{"acme": "sealed-secret"},
		Transport: idp.Client().Transport,
	}
	h := newHarness(t, bootstrap.WithOperatorSSO(sso))

	options := h.Do("GET", "/management/v1/login-options", "", nil)
	providers, _ := options.JSON["providers"].([]any)
	if options.Status != 200 || options.JSON["password"] != false || len(providers) != 1 {
		t.Fatalf("login options: %s", options.Body)
	}
	login := httptest.NewRequest("POST", "/management/v1/login", strings.NewReader(`{"email":"owner@example.com","password":"whatever-password"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("X-IAMKit-Console", "1")
	if res, _ := h.App.Test(login, 10000); res.StatusCode != 403 {
		t.Fatalf("password login: %d", res.StatusCode)
	}

	claims := map[string]any{"sub": "u-ann", "email": "ann@acme.com", "email_verified": true}
	// Not an operator yet: refused, no session.
	res := operatorSSO(t, h, idp, "acme", claims)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/login?sso_error=not_authorized" || sessionCookie(res) != nil {
		t.Fatalf("uninvited: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	invited := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "admin"}, 201)
	annID := invited.JSON["operator_id"].(string)
	res = operatorSSO(t, h, idp, "acme", claims)
	cookie := sessionCookie(res)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/" || cookie == nil {
		t.Fatalf("invited: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	req := httptest.NewRequest("GET", "/management/v1/me", nil)
	req.AddCookie(cookie)
	me, _ := h.App.Test(req, 10000)
	var principal map[string]any
	json.NewDecoder(me.Body).Decode(&principal)
	me.Body.Close()
	if me.StatusCode != 200 || principal["operator_id"] != annID {
		t.Fatalf("me: %d %v", me.StatusCode, principal)
	}

	// Later sign-ins match the subject even if the provider email changed,
	// but the domain gate still applies.
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann", "email": "ann.new@acme.com"}); sessionCookie(res) == nil {
		t.Fatalf("linked: %s", res.Header.Get("Location"))
	}
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann", "email": "ann@evil.com"}); sessionCookie(res) != nil {
		t.Fatal("domain gate skipped for a linked identity")
	}
	// Another subject with Ann's email cannot take over her account.
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-mallory", "email": "ann@acme.com", "email_verified": true}); sessionCookie(res) != nil {
		t.Fatal("second subject linked")
	}
	// Unknown provider and a callback without its browser binding.
	if res = operatorSSO(t, h, idp, "other", claims); res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "sso_error=not_authorized") {
		t.Fatalf("unknown provider: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	callback, _ := h.App.Test(httptest.NewRequest("GET", "/management/v1/sso/callback?code=provider-code&state=ik_state_x", nil), 10000)
	if callback.StatusCode != 303 || callback.Header.Get("Location") != "/login?sso_error=expired" {
		t.Fatalf("unbound callback: %d %s", callback.StatusCode, callback.Header.Get("Location"))
	}

	// An operator disabled through the API cannot sign in with an already
	// linked identity, and does not fall back to linking by email.
	bob := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "bob@acme.com", "role": "viewer"}, 201)
	bobID := bob.JSON["operator_id"].(string)
	bobClaims := map[string]any{"sub": "u-bob", "email": "bob@acme.com", "email_verified": true}
	if res = operatorSSO(t, h, idp, "acme", bobClaims); sessionCookie(res) == nil {
		t.Fatalf("bob: %s", res.Header.Get("Location"))
	}
	h.Must("DELETE", "/management/v1/operators/"+bobID, h.Owner, nil, 204)
	if res = operatorSSO(t, h, idp, "acme", bobClaims); sessionCookie(res) != nil || res.Header.Get("Location") != "/login?sso_error=not_authorized" {
		t.Fatalf("disabled bob: %s", res.Header.Get("Location"))
	}
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-bob-2", "email": "bob@acme.com", "email_verified": true}); sessionCookie(res) != nil {
		t.Fatal("disabled operator linked a new identity")
	}

	// The owner sees and resets Ann's identity; her session ends.
	ids := h.Must("GET", "/management/v1/operators/"+annID+"/identities", h.Owner, nil, 200)
	if items := ids.JSON["items"].([]any); len(items) != 1 || items[0].(map[string]any)["issuer"] != idp.URL {
		t.Fatalf("identities: %s", ids.Body)
	}
	h.Must("DELETE", "/management/v1/operators/"+annID+"/identities", h.Owner, nil, 204)
	req = httptest.NewRequest("GET", "/management/v1/me", nil)
	req.AddCookie(cookie)
	if me, _ = h.App.Test(req, 10000); me.StatusCode != 401 {
		t.Fatalf("session after reset: %d", me.StatusCode)
	}
	// The new subject now links by verified email.
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann-2", "email": "ann@acme.com", "email_verified": true}); sessionCookie(res) == nil {
		t.Fatalf("relink: %s", res.Header.Get("Location"))
	}
}

// consolePassword signs in with a password as the console does and returns
// the response status, error code and session cookie.
func consolePassword(t *testing.T, h *Harness, email, password string) (int, string, *http.Cookie) {
	t.Helper()
	return consoleLogin(t, h, map[string]string{"email": email, "password": password})
}

// consoleLogin posts a console login body (e.g. with new_password).
func consoleLogin(t *testing.T, h *Harness, input map[string]string) (int, string, *http.Cookie) {
	t.Helper()
	body, _ := json.Marshal(input)
	req := httptest.NewRequest("POST", "/management/v1/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IAMKit-Console", "1")
	res, err := h.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out.Error.Code, sessionCookie(res)
}

// consoleRequest sends a console request with an operator session cookie.
func consoleRequest(t *testing.T, h *Harness, cookie *http.Cookie, method, path string, body any) (int, string) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IAMKit-Console", "1")
	req.AddCookie(cookie)
	res, err := h.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out.Error.Code
}

// TestOperatorBreakGlass: with SSO configured, passwords are emergency
// access that owners grant; everyone else must use the identity provider,
// so removing someone there is enough to lock them out.
func TestOperatorBreakGlass(t *testing.T) {
	requireE2E(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := newFakeIdP(t, key, "console")
	h := newHarness(t, bootstrap.WithOperatorSSO(bootstrap.OperatorSSO{
		Settings: management.SSOSettings{Password: management.PasswordBreakGlass, Providers: []management.SSOProvider{
			{ID: "acme", Name: "Acme", Type: management.SSOTypeOIDC, Issuer: idp.URL, Client: "console", AllowedDomains: []string{"acme.com"}},
		}},
		Secrets:   map[string]string{"acme": "sealed-secret"},
		Transport: idp.Client().Transport,
	}))
	options := h.Do("GET", "/management/v1/login-options", "", nil)
	if options.JSON["password"] != true || options.JSON["password_mode"] != "break_glass" {
		t.Fatalf("login options: %s", options.Body)
	}

	// The bootstrap owner has emergency access and can set a password.
	h.Must("POST", "/management/v1/password", h.Owner, map[string]any{"password": "owner emergency pw"}, 204)
	status, _, ownerCookie := consolePassword(t, h, "owner@example.com", "owner emergency pw")
	if status != 200 || ownerCookie == nil {
		t.Fatalf("owner emergency login: %d", status)
	}
	var ownerID string
	var operators []map[string]any
	if err := json.Unmarshal([]byte(h.Must("GET", "/management/v1/operators", h.Owner, nil, 200).Body), &operators); err != nil {
		t.Fatal(err)
	}
	for _, o := range operators {
		if o["email"] == "owner@example.com" {
			ownerID = o["id"].(string)
			if o["password_allowed"] != true {
				t.Fatalf("bootstrap owner without emergency access: %v", o)
			}
		}
	}

	// An invited operator can neither set nor use a password.
	ann := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "admin"}, 201)
	annID, annKey := ann.JSON["operator_id"].(string), ann.JSON["secret"].(string)
	if res := h.Do("POST", "/management/v1/password", annKey, map[string]any{"password": "ann password 123"}); res.Status != 403 || !strings.Contains(res.Body, `"code":"`+management.CodeSSORequired+`"`) {
		t.Fatalf("ann set password: %d %s", res.Status, res.Body)
	}
	res := operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann", "email": "ann@acme.com", "email_verified": true})
	annCookie := sessionCookie(res)
	if annCookie == nil {
		t.Fatalf("ann sso: %s", res.Header.Get("Location"))
	}

	// A password set while passwords were open (or by SQL) still fails, but
	// only with the right password is SSO_REQUIRED revealed.
	if _, err := h.DB.Exec(`UPDATE operators SET password_hash=(SELECT password_hash FROM operators WHERE email='owner@example.com') WHERE email='ann@acme.com'`); err != nil {
		t.Fatal(err)
	}
	if status, code, c := consolePassword(t, h, "ann@acme.com", "owner emergency pw"); status != 403 || code != management.CodeSSORequired || c != nil {
		t.Fatalf("ann password login: %d %s", status, code)
	}
	if status, code, _ := consolePassword(t, h, "ann@acme.com", "wrong password!!"); status != 401 || code == management.CodeSSORequired {
		t.Fatalf("ann wrong password: %d %s", status, code)
	}

	// Only owners grant emergency access; granting it lets Ann's password work.
	if status, _ := consoleRequest(t, h, annCookie, "PUT", "/management/v1/operators/"+annID+"/password-access", map[string]any{"allowed": true}); status != 403 {
		t.Fatalf("admin granted emergency access: %d", status)
	}
	if res := h.Do("PUT", "/management/v1/operators/"+annID+"/password-access", h.Owner, map[string]any{}); res.Status != 400 {
		t.Fatalf("missing allowed: %d", res.Status)
	}
	if res := h.Do("PUT", "/management/v1/operators/"+uuid.NewString()+"/password-access", h.Owner, map[string]any{"allowed": true}); res.Status != 404 {
		t.Fatalf("unknown operator: %d", res.Status)
	}
	h.Must("PUT", "/management/v1/operators/"+annID+"/password-access", h.Owner, map[string]any{"allowed": true}, 204)
	// Her fresh single sign-on session may replace the password without
	// knowing it, and stays signed in; a stale one must sign in again.
	if status, code := consoleRequest(t, h, annCookie, "POST", "/management/v1/password", map[string]any{"password": "ann chosen password"}); status != 204 {
		t.Fatalf("ann fresh sso set password: %d %s", status, code)
	}
	if _, err := h.DB.Exec(`UPDATE operator_sessions SET authenticated_at=now()-interval '10 minutes' WHERE operator_id=$1 AND revoked_at IS NULL`, annID); err != nil {
		t.Fatal(err)
	}
	if status, code := consoleRequest(t, h, annCookie, "POST", "/management/v1/password", map[string]any{"password": "another ann password"}); status != 403 || code != management.CodeReauthenticationRequired {
		t.Fatalf("ann stale sso set password: %d %s", status, code)
	}
	status, _, annPasswordCookie := consolePassword(t, h, "ann@acme.com", "ann chosen password")
	if status != 200 || annPasswordCookie == nil {
		t.Fatalf("ann emergency login: %d", status)
	}
	// Removing it ends her password sessions, not her single sign-on ones,
	// and her password stops working.
	h.Must("PUT", "/management/v1/operators/"+annID+"/password-access", h.Owner, map[string]any{"allowed": false}, 204)
	if status, _ := consoleRequest(t, h, annPasswordCookie, "GET", "/management/v1/me", nil); status != 401 {
		t.Fatalf("password session after revoke: %d", status)
	}
	if status, _ := consoleRequest(t, h, annCookie, "GET", "/management/v1/me", nil); status != 200 {
		t.Fatalf("sso session after revoke: %d", status)
	}
	if status, code, _ := consolePassword(t, h, "ann@acme.com", "ann chosen password"); status != 403 || code != management.CodeSSORequired {
		t.Fatalf("ann after revoke: %d %s", status, code)
	}
	// SSO still works for her.
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann", "email": "ann@acme.com", "email_verified": true}); sessionCookie(res) == nil {
		t.Fatalf("ann sso after revoke: %s", res.Header.Get("Location"))
	}

	// The owner's own access is per workspace membership and revocable too.
	h.Must("PUT", "/management/v1/operators/"+ownerID+"/password-access", h.Owner, map[string]any{"allowed": false}, 204)
	if status, code, _ := consolePassword(t, h, "owner@example.com", "owner emergency pw"); status != 403 || code != management.CodeSSORequired {
		t.Fatalf("owner after revoke: %d %s", status, code)
	}
}

// TestOperatorPasswordChange: a bootstrap password must be replaced at the
// first sign-in; later changes prove the current password and keep the
// session that made them, ending the others.
func TestOperatorPasswordChange(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	mgmt := bootstrap.ManagementWithPasswords(h.DB)
	owner, err := mgmt.Authenticate(t.Context(), h.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = mgmt.SetTemporaryPassword(t.Context(), owner, "bootstrap password"); err != nil {
		t.Fatal(err)
	}
	if status, code, c := consolePassword(t, h, "owner@example.com", "bootstrap password"); status != 403 || code != management.CodePasswordChangeRequired || c != nil {
		t.Fatalf("must change: %d %s", status, code)
	}
	if status, code, _ := consolePassword(t, h, "owner@example.com", "wrong password!!"); status != 401 || code == management.CodePasswordChangeRequired {
		t.Fatalf("wrong password: %d %s", status, code)
	}
	status, _, first := consoleLogin(t, h, map[string]string{"email": "owner@example.com", "password": "bootstrap password", "new_password": "owner chosen password"})
	if status != 200 || first == nil {
		t.Fatalf("change at login: %d", status)
	}
	if status, _, _ := consolePassword(t, h, "owner@example.com", "bootstrap password"); status != 401 {
		t.Fatalf("old password: %d", status)
	}
	status, _, second := consolePassword(t, h, "owner@example.com", "owner chosen password")
	if status != 200 || second == nil {
		t.Fatalf("login with new password: %d", status)
	}

	// The status tells the console what the form needs.
	var st management.PasswordStatus
	req := httptest.NewRequest("GET", "/management/v1/password", nil)
	req.Header.Set("X-IAMKit-Console", "1")
	req.AddCookie(second)
	res, err := h.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(res.Body).Decode(&st)
	res.Body.Close()
	if res.StatusCode != 200 || !st.Set || !st.Usable || st.Fresh || st.Mode != management.PasswordEnabled {
		t.Fatalf("status: %d %+v", res.StatusCode, st)
	}

	// A session needs the current password; the change keeps it signed in
	// and ends the other one.
	if status, code := consoleRequest(t, h, second, "POST", "/management/v1/password", map[string]any{"password": "a newer password!"}); status != 403 || code != management.CodeReauthenticationRequired {
		t.Fatalf("without current: %d %s", status, code)
	}
	if status, code := consoleRequest(t, h, second, "POST", "/management/v1/password", map[string]any{"current_password": "wrong password!!", "password": "a newer password!"}); status != 403 || code != management.CodeReauthenticationRequired {
		t.Fatalf("wrong current: %d %s", status, code)
	}
	if status, code := consoleRequest(t, h, second, "POST", "/management/v1/password", map[string]any{"current_password": "owner chosen password", "password": "a newer password!"}); status != 204 {
		t.Fatalf("change: %d %s", status, code)
	}
	if status, _ := consoleRequest(t, h, second, "GET", "/management/v1/me", nil); status != 200 {
		t.Fatalf("current session after change: %d", status)
	}
	if status, _ := consoleRequest(t, h, first, "GET", "/management/v1/me", nil); status != 401 {
		t.Fatalf("other session after change: %d", status)
	}
	// A management key needs no proof (console /setup).
	h.Must("POST", "/management/v1/password", h.Owner, map[string]any{"password": "set with the key"}, 204)
	if status, _ := consoleRequest(t, h, second, "GET", "/management/v1/me", nil); status != 401 {
		t.Fatalf("session after key change: %d", status)
	}
	if status, _, c := consolePassword(t, h, "owner@example.com", "set with the key"); status != 200 || c == nil {
		t.Fatalf("login after key change: %d", status)
	}
}

// TestOperatorRoleAndReactivation: owners change roles (never leaving the
// workspace without an owner; changes apply to live credentials at once),
// and inviting a disabled operator again reactivates them with fresh state.
func TestOperatorRoleAndReactivation(t *testing.T) {
	requireE2E(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := newFakeIdP(t, key, "console")
	h := newHarness(t, bootstrap.WithOperatorSSO(bootstrap.OperatorSSO{
		Settings: management.SSOSettings{Password: management.PasswordBreakGlass, Providers: []management.SSOProvider{
			{ID: "acme", Name: "Acme", Type: management.SSOTypeOIDC, Issuer: idp.URL, Client: "console", AllowedDomains: []string{"acme.com"}},
		}},
		Secrets:   map[string]string{"acme": "sealed-secret"},
		Transport: idp.Client().Transport,
	}))
	role := func(id string) string {
		var out string
		if err := h.DB.Get(&out, `SELECT role FROM workspace_members WHERE operator_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ownerID := h.Must("GET", "/management/v1/me", h.Owner, nil, 200).JSON["operator_id"].(string)
	ann := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "viewer"}, 201)
	annID, annKey := ann.JSON["operator_id"].(string), ann.JSON["secret"].(string)
	if ann.JSON["reactivated"] != false {
		t.Fatalf("new operator reported reactivated: %s", ann.Body)
	}

	// Validation, permissions, unknown operators.
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", h.Owner, map[string]any{"role": "root"}, 400)
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", annKey, map[string]any{"role": "admin"}, 403)
	h.Must("PUT", "/management/v1/operators/"+uuid.NewString()+"/role", h.Owner, map[string]any{"role": "admin"}, 404)
	h.Must("PUT", "/management/v1/operators/not-a-uuid/role", h.Owner, map[string]any{"role": "admin"}, 404)
	// The last owner cannot step down.
	if res := h.Must("PUT", "/management/v1/operators/"+ownerID+"/role", h.Owner, map[string]any{"role": "admin"}, 409); !strings.Contains(res.Body, management.CodeLastOwner) {
		t.Fatalf("last owner demotion: %s", res.Body)
	}
	// An invitation never changes an active member's role.
	if res := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "admin"}, 409); !strings.Contains(res.Body, management.CodeOperatorExists) {
		t.Fatalf("invite with another role: %s", res.Body)
	}
	// Same role re-invite keeps working (a new key) and is not a reactivation.
	if res := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "viewer"}, 201); res.JSON["reactivated"] != false {
		t.Fatalf("same-role re-invite: %s", res.Body)
	}

	// Promotion applies to Ann's existing key at once.
	h.Must("POST", "/management/v1/projects", annKey, map[string]any{"name": "nope"}, 403)
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", h.Owner, map[string]any{"role": "admin"}, 204)
	h.Must("POST", "/management/v1/projects", annKey, map[string]any{"name": "ann project"}, 201)
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", h.Owner, map[string]any{"role": "admin"}, 204) // no-op
	// Ann becomes an owner; then the bootstrap owner may demote itself, and
	// Ann (now the last owner) may not.
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", h.Owner, map[string]any{"role": "owner"}, 204)
	if got := h.Must("GET", "/management/v1/me", annKey, nil, 200).JSON["role"]; got != "owner" {
		t.Fatalf("ann role after promotion: %v", got)
	}
	h.Must("PUT", "/management/v1/operators/"+ownerID+"/role", h.Owner, map[string]any{"role": "viewer"}, 204)
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", annKey, map[string]any{"role": "admin"}, 409)
	h.Must("PUT", "/management/v1/operators/"+ownerID+"/role", h.Owner, map[string]any{"role": "owner"}, 403) // a viewer now
	h.Must("PUT", "/management/v1/operators/"+ownerID+"/role", annKey, map[string]any{"role": "owner"}, 204)
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", h.Owner, map[string]any{"role": "admin"}, 204)

	// Ann links SSO, gets emergency access and a password, then is disabled.
	res := operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann", "email": "ann@acme.com", "email_verified": true})
	annCookie := sessionCookie(res)
	if annCookie == nil {
		t.Fatalf("ann sso: %s", res.Header.Get("Location"))
	}
	h.Must("PUT", "/management/v1/operators/"+annID+"/password-access", h.Owner, map[string]any{"allowed": true}, 204)
	if status, code := consoleRequest(t, h, annCookie, "POST", "/management/v1/password", map[string]any{"password": "ann chosen password"}); status != 204 {
		t.Fatalf("ann set password: %d %s", status, code)
	}
	h.Must("DELETE", "/management/v1/operators/"+annID, h.Owner, nil, 204)
	if n := count(t, h.DB, `SELECT count(*) FROM operator_sessions WHERE operator_id=$1 AND revoked_at IS NULL`, annID); n != 0 {
		t.Fatalf("disable left %d live sessions", n)
	}
	h.Must("PUT", "/management/v1/operators/"+annID+"/role", h.Owner, map[string]any{"role": "viewer"}, 409)

	// Inviting her again reactivates her with the chosen role and nothing
	// of before: old key, sessions, SSO link, password and grant are gone.
	again := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "viewer"}, 201)
	if again.JSON["reactivated"] != true || again.JSON["operator_id"] != annID {
		t.Fatalf("reactivation: %s", again.Body)
	}
	if role(annID) != "viewer" {
		t.Fatalf("reactivated role: %s", role(annID))
	}
	h.Must("GET", "/management/v1/me", annKey, nil, 401)
	h.Must("GET", "/management/v1/me", again.JSON["secret"].(string), nil, 200)
	if status, _ := consoleRequest(t, h, annCookie, "GET", "/management/v1/me", nil); status != 401 {
		t.Fatalf("old session after reactivation: %d", status)
	}
	if status, code, _ := consolePassword(t, h, "ann@acme.com", "ann chosen password"); status != 401 {
		t.Fatalf("old password after reactivation: %d %s", status, code)
	}
	if n := count(t, h.DB, `SELECT count(*) FROM operator_identities WHERE operator_id=$1`, annID); n != 0 {
		t.Fatalf("identities after reactivation: %d", n)
	}
	if n := count(t, h.DB, `SELECT count(*) FROM workspace_members WHERE operator_id=$1 AND password_allowed`, annID); n != 0 {
		t.Fatal("emergency access survived reactivation")
	}
	// A new subject for the same email links afresh.
	if res = operatorSSO(t, h, idp, "acme", map[string]any{"sub": "u-ann-new", "email": "ann@acme.com", "email_verified": true}); sessionCookie(res) == nil {
		t.Fatalf("relink after reactivation: %s", res.Header.Get("Location"))
	}
}

// TestOperatorDemotionEndsOwnerPowers: a request authenticated as an owner
// that was demoted meanwhile cannot change roles or reactivate, and a former
// owner's impersonation sessions end with the demotion.
func TestOperatorDemotionEndsOwnerPowers(t *testing.T) {
	requireE2E(t)
	e := newEnv(t)
	ctx := context.Background()
	repo := mgmtpg.New(e.DB)
	owner := e.Must("GET", "/management/v1/me", e.Owner, nil, 200).JSON
	ownerID := identity.MustParseOperatorID(owner["operator_id"].(string))
	workspace := identity.MustParseWorkspaceID(owner["workspace_id"].(string))
	bob := e.Must("POST", "/management/v1/operators", e.Owner, map[string]any{"email": "bob@example.com", "role": "admin"}, 201).JSON
	bobID, bobKey := bob["operator_id"].(string), bob["secret"].(string)
	gone := e.Must("POST", "/management/v1/operators", e.Owner, map[string]any{"email": "gone@example.com", "role": "viewer"}, 201).JSON["operator_id"].(string)
	e.Must("DELETE", "/management/v1/operators/"+gone, e.Owner, nil, 204)
	e.Must("PUT", "/management/v1/operators/"+bobID+"/role", e.Owner, map[string]any{"role": "owner"}, 204)

	// Bob impersonates Alice, then the bootstrap owner demotes him.
	imp := e.Must("POST", e.Base+"/impersonations", bobKey, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "reason": "support ticket 42"}, 200)
	active := func() any {
		return e.Must("POST", "/identity/v1/introspect", imp.JSON["access_token"].(string), fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 200).JSON["active"]
	}
	if active() != true {
		t.Fatal("impersonation token inactive before demotion")
	}
	e.Must("PUT", "/management/v1/operators/"+bobID+"/role", e.Owner, map[string]any{"role": "admin"}, 204)
	if n := count(t, e.DB, `SELECT count(*) FROM sessions WHERE actor_id=$1 AND revoked_at IS NULL`, bobID); n != 0 {
		t.Fatalf("impersonation sessions after demotion: %d", n)
	}
	// Promoted back, the old impersonation does not revive.
	e.Must("PUT", "/management/v1/operators/"+bobID+"/role", e.Owner, map[string]any{"role": "owner"}, 204)
	if active() != false {
		t.Fatal("impersonation revived by promotion")
	}

	// A principal read before the owner was demoted (a request in flight).
	forbidden := func(err error) bool { return ssoCode(err) == "FORBIDDEN" }
	stale := management.Principal{WorkspaceID: workspace, OperatorID: ownerID, Role: management.RoleOwner}
	e.Must("PUT", "/management/v1/operators/"+ownerID.String()+"/role", bobKey, map[string]any{"role": "viewer"}, 204)
	if _, err := repo.SetOperatorRole(ctx, stale, identity.MustParseOperatorID(bobID), management.RoleViewer); !forbidden(err) {
		t.Fatalf("stale owner role change: %v", err)
	}
	if _, _, err := repo.Delegate(ctx, stale, "gone@example.com", "admin", identity.NewKeyID(), []byte("h"), time.Now().Add(time.Hour)); !forbidden(err) {
		t.Fatalf("stale owner reactivation: %v", err)
	}
}
