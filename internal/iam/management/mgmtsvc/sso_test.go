package mgmtsvc

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakeSecrets struct{ n int }

func (f *fakeSecrets) Generate(prefix string) (string, []byte, error) {
	f.n++
	raw := prefix + strings.Repeat("x", f.n)
	return raw, f.Hash(raw), nil
}
func (*fakeSecrets) Hash(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

type fakeIdP struct {
	claims management.SSOClaims
	// provider, nonce and verifier of the last Verify.
	provider, nonce, verifier string
}

func (*fakeIdP) Verifier() string { return "verifier" }
func (*fakeIdP) Authorize(_ context.Context, provider, state, nonce, verifier string) (string, error) {
	return "https://idp.example/authorize?provider=" + provider + "&state=" + state, nil
}
func (f *fakeIdP) Verify(_ context.Context, provider, code, nonce, verifier string) (management.SSOClaims, error) {
	f.provider, f.nonce, f.verifier = provider, nonce, verifier
	if code != "code" {
		return management.SSOClaims{}, errx.Unauthorized("bad code")
	}
	return f.claims, nil
}

type operatorRow struct {
	p      management.Principal
	email  string
	active bool
}

// fakeStore plays SSORepository and the session half of SessionRepository.
type fakeStore struct {
	management.SessionRepository
	states    map[string]management.SSOState
	operators []operatorRow
	// links maps issuer+" "+subject to an operator.
	links    map[string]identity.OperatorID
	touched  int
	sessions []management.Principal
}

func newStore() *fakeStore {
	return &fakeStore{states: map[string]management.SSOState{}, links: map[string]identity.OperatorID{}}
}

func (f *fakeStore) SaveSSOState(_ context.Context, hash []byte, s management.SSOState, _ time.Time) error {
	f.states[string(hash)] = s
	return nil
}
func (f *fakeStore) ConsumeSSOState(_ context.Context, stateHash, bindingHash []byte) (management.SSOState, error) {
	s, ok := f.states[string(stateHash)]
	if !ok || string(s.Binding) != string(bindingHash) {
		return management.SSOState{}, management.ErrSSOExpired()
	}
	delete(f.states, string(stateHash))
	return s, nil
}
func (f *fakeStore) operator(match func(operatorRow) bool) (operatorRow, bool) {
	for _, o := range f.operators {
		if match(o) {
			return o, true
		}
	}
	return operatorRow{}, false
}
func (f *fakeStore) LinkedOperator(_ context.Context, issuer, subject string) (management.Principal, bool, error) {
	id, ok := f.links[issuer+" "+subject]
	if !ok {
		return management.Principal{}, false, nil
	}
	o, _ := f.operator(func(o operatorRow) bool { return o.p.OperatorID == id })
	if !o.active {
		return management.Principal{}, true, management.ErrSSONotAuthorized("disabled")
	}
	return o.p, true, nil
}
func (f *fakeStore) LinkOperator(_ context.Context, issuer, subject, provider, email string) (management.Principal, error) {
	o, ok := f.operator(func(o operatorRow) bool { return o.email == email && o.active })
	if !ok {
		return management.Principal{}, management.ErrSSONotAuthorized("no operator")
	}
	for key, id := range f.links {
		if id == o.p.OperatorID && strings.HasPrefix(key, issuer+" ") {
			return management.Principal{}, management.ErrSSONotAuthorized("already linked")
		}
	}
	f.links[issuer+" "+subject] = o.p.OperatorID
	return o.p, nil
}
func (f *fakeStore) TouchIdentity(context.Context, string, string) error { f.touched++; return nil }
func (f *fakeStore) Identities(_ context.Context, _ identity.WorkspaceID, operator identity.OperatorID) ([]management.OperatorIdentity, error) {
	out := []management.OperatorIdentity{}
	for key, id := range f.links {
		if id == operator {
			out = append(out, management.OperatorIdentity{Issuer: strings.Fields(key)[0]})
		}
	}
	return out, nil
}
func (f *fakeStore) UnlinkIdentities(_ context.Context, _ identity.WorkspaceID, operator identity.OperatorID) error {
	for key, id := range f.links {
		if id == operator {
			delete(f.links, key)
		}
	}
	return nil
}
func (f *fakeStore) CreateSession(_ context.Context, _ identity.SessionID, p management.Principal, _ []byte, _ time.Time) error {
	f.sessions = append(f.sessions, p)
	return nil
}

func ptr(v bool) *bool { return &v }

type ssoFixture struct {
	sso   *SSO
	idp   *fakeIdP
	store *fakeStore
	ann   management.Principal
}

func newSSO(t *testing.T) ssoFixture {
	t.Helper()
	settings := management.SSOSettings{Password: management.PasswordEnabled, Providers: []management.SSOProvider{
		{ID: "okta", Name: "Okta", Type: management.SSOTypeOIDC, Issuer: "https://acme.okta.com", Client: "c", AllowedDomains: []string{"acme.com"}},
		{ID: "google", Name: "Google", Type: management.SSOTypeGoogle, Client: "c", AllowedDomains: []string{"acme.com"}},
	}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	store := newStore()
	ann := management.Principal{WorkspaceID: identity.NewWorkspaceID(), OperatorID: identity.NewOperatorID(), Role: "admin"}
	store.operators = []operatorRow{{p: ann, email: "ann@acme.com", active: true}}
	idp := &fakeIdP{claims: management.SSOClaims{Issuer: "https://acme.okta.com", Subject: "okta-ann", Email: "Ann@acme.com", EmailVerified: ptr(true)}}
	return ssoFixture{sso: NewSSO(settings, idp, store, store, &fakeSecrets{}), idp: idp, store: store, ann: ann}
}

// signIn starts a sign-in with the provider and completes it in the same
// browser.
func (f ssoFixture) signIn(t *testing.T, provider string) (string, management.Principal, error) {
	t.Helper()
	start, err := f.sso.Start(context.Background(), provider)
	if err != nil {
		t.Fatal(err)
	}
	state := start.URL[strings.Index(start.URL, "state=")+len("state="):]
	raw, p, err := f.sso.Callback(context.Background(), "code", state, start.Binding)
	if err == nil && (p.Method != management.MethodSSO || p.Session.IsZero() || p.AuthTime == nil) {
		t.Fatalf("sso session: %+v", p)
	}
	// Callers compare the operator; the session parts are checked above.
	p.Method, p.Session, p.AuthTime = "", identity.SessionID{}, nil
	return raw, p, err
}

func code(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestSSOLinksByVerifiedEmailThenBySubject(t *testing.T) {
	f := newSSO(t)
	raw, p, err := f.signIn(t, "okta")
	if err != nil || p != f.ann || !strings.HasPrefix(raw, "ik_sess_") || len(f.store.sessions) != 1 {
		t.Fatalf("first sign-in: %q %+v %v", raw, p, err)
	}
	if f.idp.provider != "okta" || f.idp.verifier != "verifier" || !strings.HasPrefix(f.idp.nonce, "ik_nonce_") {
		t.Fatalf("verify args: %+v", f.idp)
	}
	// Later sign-ins match the subject, whatever the email says now, within
	// the allowed domains.
	f.idp.claims.Email, f.idp.claims.EmailVerified = "renamed@acme.com", ptr(false)
	if _, p, err = f.signIn(t, "okta"); err != nil || p != f.ann || f.store.touched != 1 {
		t.Fatalf("linked sign-in: %+v %v", p, err)
	}
	f.idp.claims.Email = "renamed@elsewhere.com"
	if _, _, err = f.signIn(t, "okta"); code(err) != management.CodeSSONotAuthorized {
		t.Fatalf("linked sign-in outside allowed domains: %v", err)
	}
}

func TestSSORefusals(t *testing.T) {
	cases := map[string]func(f ssoFixture){
		"unverified email":  func(f ssoFixture) { f.idp.claims.EmailVerified = ptr(false) },
		"unknown email":     func(f ssoFixture) { f.idp.claims.Email = "bob@acme.com" },
		"disabled operator": func(f ssoFixture) { f.store.operators[0].active = false },
		"second subject of the issuer": func(f ssoFixture) {
			f.store.links["https://acme.okta.com old-ann"] = f.ann.OperatorID
		},
		"linked but disabled": func(f ssoFixture) {
			f.store.links["https://acme.okta.com okta-ann"] = f.ann.OperatorID
			f.store.operators[0].active = false
		},
	}
	for name, arrange := range cases {
		f := newSSO(t)
		arrange(f)
		if _, _, err := f.signIn(t, "okta"); code(err) != management.CodeSSONotAuthorized {
			t.Errorf("%s: %v", name, err)
		}
		if len(f.store.sessions) != 0 {
			t.Errorf("%s: session created", name)
		}
	}
}

func TestSSOGoogleRequiresWorkspaceDomain(t *testing.T) {
	f := newSSO(t)
	f.idp.claims = management.SSOClaims{Issuer: "https://accounts.google.com", Subject: "g-ann", Email: "ann@acme.com", EmailVerified: ptr(true)}
	if _, _, err := f.signIn(t, "google"); code(err) != management.CodeSSONotAuthorized {
		t.Fatalf("personal account: %v", err)
	}
	f.idp.claims.HostedDomain = "acme.com"
	if _, p, err := f.signIn(t, "google"); err != nil || p != f.ann {
		t.Fatalf("workspace account: %v", err)
	}
	// The domain gate holds on later sign-ins too.
	f.idp.claims.HostedDomain = ""
	if _, _, err := f.signIn(t, "google"); code(err) != management.CodeSSONotAuthorized {
		t.Fatalf("linked personal account: %v", err)
	}
}

func TestSSOStateIsSingleUseAndBrowserBound(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	if _, err := f.sso.Start(ctx, "unknown"); err == nil {
		t.Fatal("unknown provider started")
	}
	start, err := f.sso.Start(ctx, "okta")
	if err != nil {
		t.Fatal(err)
	}
	state := start.URL[strings.Index(start.URL, "state=")+len("state="):]
	if _, _, err = f.sso.Callback(ctx, "code", state, "ik_binding_other"); code(err) != management.CodeSSOExpired {
		t.Fatalf("other browser: %v", err)
	}
	start, _ = f.sso.Start(ctx, "okta")
	state = start.URL[strings.Index(start.URL, "state=")+len("state="):]
	if _, _, err = f.sso.Callback(ctx, "code", state, start.Binding); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.sso.Callback(ctx, "code", state, start.Binding); code(err) != management.CodeSSOExpired {
		t.Fatalf("replay: %v", err)
	}
	for _, args := range [][3]string{{"", state, start.Binding}, {"code", "", start.Binding}, {"code", state, ""}} {
		if _, _, err = f.sso.Callback(ctx, args[0], args[1], args[2]); code(err) != management.CodeSSOExpired {
			t.Fatalf("missing parameter %v: %v", args, err)
		}
	}
}

func TestSSOIdentitiesAccess(t *testing.T) {
	f := newSSO(t)
	ctx := context.Background()
	if _, _, err := f.signIn(t, "okta"); err != nil {
		t.Fatal(err)
	}
	owner := management.Principal{WorkspaceID: f.ann.WorkspaceID, OperatorID: identity.NewOperatorID(), Role: "owner"}
	other := management.Principal{WorkspaceID: f.ann.WorkspaceID, OperatorID: identity.NewOperatorID(), Role: "admin"}
	if ids, err := f.sso.Identities(ctx, f.ann, f.ann.OperatorID); err != nil || len(ids) != 1 {
		t.Fatalf("own identities: %v %v", ids, err)
	}
	if _, err := f.sso.Identities(ctx, other, f.ann.OperatorID); err == nil {
		t.Fatal("admin read another operator's identities")
	}
	if err := f.sso.UnlinkIdentities(ctx, f.ann, f.ann.OperatorID); err == nil {
		t.Fatal("non-owner reset identities")
	}
	if err := f.sso.UnlinkIdentities(ctx, owner, f.ann.OperatorID); err != nil || len(f.store.links) != 0 {
		t.Fatalf("owner reset: %v", err)
	}
	// After the reset, the next sign-in links again by verified email.
	f.idp.claims.Subject = "okta-ann-2"
	if _, p, err := f.signIn(t, "okta"); err != nil || p != f.ann {
		t.Fatalf("relink: %v", err)
	}
}

func TestPasswordLoginDisabled(t *testing.T) {
	s := New(nil, nil, &fakeSecrets{}, nil).WithPasswordMode(management.PasswordDisabled)
	ctx := context.Background()
	if _, _, err := s.Login(ctx, "ann@acme.com", "correct horse battery", ""); code(err) != management.CodePasswordLoginDisabled {
		t.Fatalf("login: %v", err)
	}
	if err := s.SetPassword(ctx, management.Principal{}, "", "correct horse battery"); code(err) != management.CodePasswordLoginDisabled {
		t.Fatalf("set password: %v", err)
	}
}

// plainPasswords "hashes" by prefixing, so tests can tell hashes apart.
type plainPasswords struct{}

func (plainPasswords) Hash(password string) (string, error) { return "h:" + password, nil }
func (plainPasswords) Compare(hash, password string) bool   { return hash == "h:"+password }

// passwordStore plays the password half of SessionRepository.
type passwordStore struct {
	management.SessionRepository
	accounts map[string]management.PasswordAccount
	created  int
	session  management.Principal // the last created session
	set      string
	must     bool
	kept     identity.SessionID // the session SetPassword left alive
}

func (f *passwordStore) PasswordByEmail(_ context.Context, email string) (management.PasswordAccount, error) {
	a, ok := f.accounts[email]
	if !ok {
		return a, errx.Unauthorized("invalid credentials")
	}
	return a, nil
}
func (f *passwordStore) OperatorPassword(_ context.Context, _ identity.WorkspaceID, operator identity.OperatorID) (management.PasswordAccount, error) {
	for _, a := range f.accounts {
		if a.Principal.OperatorID == operator {
			return management.PasswordAccount{Hash: a.Hash, Allowed: a.Allowed, MustChange: a.MustChange}, nil
		}
	}
	return management.PasswordAccount{}, errx.Unauthorized("management credential required")
}
func (f *passwordStore) CreateSession(_ context.Context, _ identity.SessionID, p management.Principal, _ []byte, _ time.Time) error {
	f.created++
	f.session = p
	return nil
}
func (f *passwordStore) SetPassword(_ context.Context, operator identity.OperatorID, hash string, mustChange bool, keep identity.SessionID) error {
	f.set, f.must, f.kept = hash, mustChange, keep
	for email, a := range f.accounts {
		if a.Principal.OperatorID == operator {
			a.Hash, a.MustChange = hash, mustChange
			f.accounts[email] = a
		}
	}
	return nil
}

func TestPasswordModes(t *testing.T) {
	ctx := context.Background()
	owner := management.Principal{WorkspaceID: identity.NewWorkspaceID(), OperatorID: identity.NewOperatorID(), Role: "owner"}
	ann := management.Principal{WorkspaceID: owner.WorkspaceID, OperatorID: identity.NewOperatorID(), Role: "admin"}
	newService := func(mode management.PasswordMode) (*Service, *passwordStore) {
		store := &passwordStore{accounts: map[string]management.PasswordAccount{
			"owner@acme.com": {Principal: owner, Hash: "h:owner password", Allowed: true},
			"ann@acme.com":   {Principal: ann, Hash: "h:ann password!!", Allowed: false},
		}}
		return New(nil, store, &fakeSecrets{}, plainPasswords{}).WithPasswordMode(mode), store
	}

	// Enabled (and the zero mode): every operator with a password.
	for _, mode := range []management.PasswordMode{management.PasswordEnabled, ""} {
		s, store := newService(mode)
		if _, p, err := s.Login(ctx, "ann@acme.com", "ann password!!", ""); err != nil || p.OperatorID != ann.OperatorID || p.Method != management.MethodPassword {
			t.Fatalf("%q: ann login: %v", mode, err)
		}
		if err := s.SetPassword(ctx, store.session, "ann password!!", "a new password!"); err != nil || store.set != "h:a new password!" {
			t.Fatalf("%q: ann set password: %v", mode, err)
		}
	}

	// Break-glass: only operators with emergency access.
	s, store := newService(management.PasswordBreakGlass)
	if _, p, err := s.Login(ctx, "owner@acme.com", "owner password", ""); err != nil || p.OperatorID != owner.OperatorID {
		t.Fatalf("emergency login: %v", err)
	}
	if _, _, err := s.Login(ctx, "ann@acme.com", "ann password!!", ""); code(err) != management.CodeSSORequired {
		t.Fatalf("ann login: %v", err)
	}
	// A wrong password never reveals that the operator must use SSO.
	for _, email := range []string{"ann@acme.com", "owner@acme.com", "nobody@acme.com"} {
		if _, _, err := s.Login(ctx, email, "wrong password!", ""); code(err) != string(errx.TypeAuthorization) {
			t.Fatalf("%s wrong password: %v", email, err)
		}
	}
	if store.created != 1 {
		t.Fatalf("sessions created: %d", store.created)
	}
	if err := s.SetPassword(ctx, ann, "ann password!!", "a new password!"); code(err) != management.CodeSSORequired || store.set != "" {
		t.Fatalf("ann set password: %v", err)
	}
	if err := s.SetPassword(ctx, owner, "owner password", "a new password!"); err != nil || store.set != "h:a new password!" {
		t.Fatalf("owner set password: %v", err)
	}

	// Disabled: nobody, not even with emergency access.
	s, _ = newService(management.PasswordDisabled)
	if _, _, err := s.Login(ctx, "owner@acme.com", "owner password", ""); code(err) != management.CodePasswordLoginDisabled {
		t.Fatalf("disabled owner login: %v", err)
	}
}

func TestSetPasswordProof(t *testing.T) {
	ctx := context.Background()
	workspace := identity.NewWorkspaceID()
	withPassword := management.Principal{WorkspaceID: workspace, OperatorID: identity.NewOperatorID(), Role: "admin"}
	without := management.Principal{WorkspaceID: workspace, OperatorID: identity.NewOperatorID(), Role: "admin"}
	store := &passwordStore{accounts: map[string]management.PasswordAccount{
		"pat@acme.com": {Principal: withPassword, Hash: "h:pat password!!"},
		"sam@acme.com": {Principal: without},
	}}
	s := New(nil, store, &fakeSecrets{}, plainPasswords{})
	session := func(p management.Principal, method string, age time.Duration) management.Principal {
		at := time.Now().Add(-age)
		p.Method, p.Session, p.AuthTime = method, identity.NewSessionID(), &at
		return p
	}

	// A password session proves the current password, however recent.
	pat := session(withPassword, management.MethodPassword, 0)
	for current, want := range map[string]string{"": management.CodeReauthenticationRequired, "wrong password!!": management.CodeReauthenticationRequired} {
		if err := s.SetPassword(ctx, pat, current, "pat new password"); code(err) != want {
			t.Fatalf("pat with %q: %v", current, err)
		}
	}
	if err := s.SetPassword(ctx, pat, "pat password!!", "pat new password"); err != nil || store.kept != pat.Session || store.must {
		t.Fatalf("pat change: %v (kept %v)", err, store.kept)
	}

	// Without a password, a recent sign-in is the proof.
	if err := s.SetPassword(ctx, session(without, management.MethodSSO, 10*time.Minute), "", "sam first password"); code(err) != management.CodeReauthenticationRequired {
		t.Fatalf("stale sso: %v", err)
	}
	fresh := session(without, management.MethodSSO, time.Minute)
	if st, err := s.PasswordStatus(ctx, fresh); err != nil || st.Set || !st.Fresh || !st.Usable {
		t.Fatalf("status: %+v %v", st, err)
	}
	if err := s.SetPassword(ctx, fresh, "", "sam first password"); err != nil || store.kept != fresh.Session {
		t.Fatalf("fresh sso: %v", err)
	}
	// An SSO session may replace a forgotten password while fresh.
	if err := s.SetPassword(ctx, session(without, management.MethodSSO, time.Minute), "", "sam other password"); err != nil {
		t.Fatalf("fresh sso replace: %v", err)
	}
	// A management key (console /setup) needs no proof and keeps no session.
	key := without
	key.Method = management.MethodKey
	if err := s.SetPassword(ctx, key, "", "sam key password!"); err != nil || !store.kept.IsZero() {
		t.Fatalf("key: %v", err)
	}
}

func TestMustChangePassword(t *testing.T) {
	ctx := context.Background()
	owner := management.Principal{WorkspaceID: identity.NewWorkspaceID(), OperatorID: identity.NewOperatorID(), Role: "owner"}
	store := &passwordStore{accounts: map[string]management.PasswordAccount{"owner@acme.com": {Principal: owner}}}
	s := New(nil, store, &fakeSecrets{}, plainPasswords{})
	if err := s.SetTemporaryPassword(ctx, owner, "bootstrap password"); err != nil || !store.must {
		t.Fatalf("temporary: %v", err)
	}
	// Wrong password: the usual answer, nothing about the change.
	if _, _, err := s.Login(ctx, "owner@acme.com", "wrong password!!", ""); code(err) != string(errx.TypeAuthorization) {
		t.Fatalf("wrong: %v", err)
	}
	if _, _, err := s.Login(ctx, "owner@acme.com", "bootstrap password", ""); code(err) != management.CodePasswordChangeRequired || store.created != 0 {
		t.Fatalf("must change: %v", err)
	}
	if _, _, err := s.Login(ctx, "owner@acme.com", "bootstrap password", "bootstrap password"); code(err) != string(errx.TypeValidation) {
		t.Fatalf("same password: %v", err)
	}
	if _, _, err := s.Login(ctx, "owner@acme.com", "bootstrap password", "short"); code(err) != string(errx.TypeValidation) || store.created != 0 {
		t.Fatalf("short: %v", err)
	}
	if _, p, err := s.Login(ctx, "owner@acme.com", "bootstrap password", "owner chosen password"); err != nil || p.OperatorID != owner.OperatorID || store.must || store.created != 1 {
		t.Fatalf("change at login: %v", err)
	}
	if _, _, err := s.Login(ctx, "owner@acme.com", "owner chosen password", ""); err != nil {
		t.Fatalf("login after change: %v", err)
	}
}

// fakeControl plays ControlRepository for SetPasswordAccess.
type fakeControl struct {
	management.ControlRepository
	allowed map[identity.OperatorID]bool
}

func (f *fakeControl) SetPasswordAccess(_ context.Context, _ identity.WorkspaceID, operator identity.OperatorID, allowed bool) error {
	f.allowed[operator] = allowed
	return nil
}

func TestSetPasswordAccess(t *testing.T) {
	ctx := context.Background()
	repo := &fakeControl{allowed: map[identity.OperatorID]bool{}}
	c := NewControl(repo, &fakeSecrets{})
	target := identity.NewOperatorID()
	for _, role := range []string{"admin", "viewer"} {
		if err := c.SetPasswordAccess(ctx, management.Principal{Role: role}, target, true); code(err) != "FORBIDDEN" {
			t.Fatalf("%s: %v", role, err)
		}
	}
	owner := management.Principal{Role: "owner"}
	if err := c.SetPasswordAccess(ctx, owner, identity.OperatorID{}, true); code(err) != string(errx.TypeNotFound) {
		t.Fatalf("zero id: %v", err)
	}
	if err := c.SetPasswordAccess(ctx, owner, target, true); err != nil || !repo.allowed[target] {
		t.Fatalf("grant: %v", err)
	}
}
