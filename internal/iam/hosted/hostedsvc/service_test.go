package hostedsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var (
	env    = identity.NewEnvironmentID()
	app    = identity.NewApplicationID()
	res    = identity.NewResourceID()
	orgA   = identity.NewOrganizationID()
	orgB   = identity.NewOrganizationID()
	user   = identity.NewUserID()
	client = identity.NewClientID()
)

type fakeAuthorizations struct {
	hosted bool
	err    error
}

func (f fakeAuthorizations) Pending(context.Context, string, string) (oauth.Pending, error) {
	return oauth.Pending{Client: &oauth.Client{ID: client, Environment: env, Application: app, Resource: res, HostedLogin: f.hosted}}, f.err
}

type fakeAuthenticator struct {
	organizations []authentication.Organization
	issued        []authentication.Context
}

func (f *fakeAuthenticator) VerifyPassword(_ context.Context, _ identity.EnvironmentID, email, password string) (authentication.Verified, error) {
	if password != "right" {
		return authentication.Verified{}, errx.Unauthorized("invalid credentials")
	}
	return authentication.Verified{User: user, Email: email, Method: authentication.MethodPassword}, nil
}
func (f *fakeAuthenticator) VerifyCode(context.Context, identity.EnvironmentID, identity.ChallengeID, string) (authentication.Verified, error) {
	return authentication.Verified{User: user, Method: authentication.MethodCode}, nil
}
func (f *fakeAuthenticator) Organizations(context.Context, authentication.Target, identity.UserID) ([]authentication.Organization, error) {
	return f.organizations, nil
}
func (f *fakeAuthenticator) Issue(_ context.Context, b authentication.Context, v authentication.Verified) (authentication.Issued, error) {
	f.issued = append(f.issued, b)
	return authentication.Issued{Context: b, User: v.User, Session: identity.NewSessionID()}, nil
}

type fakeRepository struct {
	hosted.Repository
	saved    map[string]hosted.Login
	deleted  int
	branding hosted.Settings
	styles   map[identity.ClientID]hosted.Settings
	signIn   *hosted.SignIn
}

func (r *fakeRepository) SignIn(context.Context, identity.EnvironmentID, identity.ClientID) (hosted.SignIn, bool, error) {
	if r.signIn == nil {
		return hosted.SignIn{}, false, nil
	}
	return *r.signIn, true, nil
}
func (r *fakeRepository) SaveSignIn(_ context.Context, _ hosted.Mutation, _ identity.ClientID, in hosted.SignIn) (hosted.SignIn, error) {
	r.signIn = &in
	return in, nil
}

func (r *fakeRepository) Settings(_ context.Context, environment identity.EnvironmentID) (hosted.Settings, error) {
	out := r.branding
	out.Environment = environment
	return out, nil
}
func (r *fakeRepository) ClientSettings(_ context.Context, _ identity.EnvironmentID, c identity.ClientID) (hosted.Settings, error) {
	s, ok := r.styles[c]
	if !ok {
		return s, errx.NotFound("client uses the environment branding")
	}
	return s, nil
}

func (r *fakeRepository) SaveLogin(_ context.Context, hash []byte, _ identity.EnvironmentID, l hosted.Login, _ time.Time) error {
	r.saved[string(hash)] = l
	return nil
}
func (r *fakeRepository) Login(_ context.Context, hash []byte, _ identity.EnvironmentID) (hosted.Login, error) {
	l, ok := r.saved[string(hash)]
	if !ok {
		return l, errx.Unauthorized("sign in again")
	}
	return l, nil
}
func (r *fakeRepository) Attempt(_ context.Context, hash []byte, limit int) (bool, error) {
	l, ok := r.saved[string(hash)]
	if !ok || l.Attempts >= limit {
		return false, nil
	}
	l.Attempts++
	r.saved[string(hash)] = l
	return true, nil
}
func (r *fakeRepository) DeleteLogin(_ context.Context, hash []byte) error {
	if _, ok := r.saved[string(hash)]; ok {
		r.deleted++
	}
	delete(r.saved, string(hash))
	return nil
}

// fakeSecondFactor: enrolled users need a code, required organizations
// make the others enroll; "123456" is the right code.
type fakeSecondFactor struct {
	enrolled bool
	required map[identity.OrganizationID]bool
	verified int
}

func (f *fakeSecondFactor) Requirement(_ context.Context, b authentication.Context, _ identity.UserID, federated bool) (authentication.Requirement, error) {
	if federated {
		return authentication.Requirement{}, nil
	}
	if f.enrolled {
		return authentication.Requirement{Needed: true, Factors: []string{"totp", "recovery"}}, nil
	}
	if f.required[b.OrganizationID] {
		return authentication.Requirement{Needed: true, Enroll: true}, nil
	}
	return authentication.Requirement{}, nil
}
func (f *fakeSecondFactor) Verify(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, code string, enroll bool) (mfa.Verification, error) {
	if code != "123456" {
		return mfa.Verification{}, errx.Unauthorized("invalid verification code")
	}
	f.verified++
	if enroll {
		f.enrolled = true
		return mfa.Verification{Proof: mfa.ProofTOTP, RecoveryCodes: []string{"aaaa-bbbb-cccc"}}, nil
	}
	return mfa.Verification{Proof: mfa.ProofTOTP}, nil
}
func (f *fakeSecondFactor) Enrolling(context.Context, identity.EnvironmentID, identity.UserID) (authentication.Enrollment, error) {
	return authentication.Enrollment{Secret: "ABC", URI: "otpauth://totp/x"}, nil
}

type hashSecrets struct{}

func (hashSecrets) Hash(raw string) []byte { return []byte("h:" + raw) }

type fakeFederation struct {
	discovery   federation.Discovery
	started     []authentication.Target
	connections []federation.ConnectionSummary
}

func (f *fakeFederation) Discover(context.Context, identity.EnvironmentID, string) (federation.Discovery, error) {
	return f.discovery, nil
}
func (f *fakeFederation) EnvironmentConnections(context.Context, identity.EnvironmentID) ([]federation.ConnectionSummary, error) {
	return f.connections, nil
}
func (f *fakeFederation) StartHosted(_ context.Context, t authentication.Target, _ identity.ConnectionID, continuation string) (federation.Start, error) {
	f.started = append(f.started, t)
	return federation.Start{URL: "https://idp.example/authorize", Binding: "b"}, nil
}

func setup(orgs ...identity.OrganizationID) (*Service, *fakeAuthenticator, *fakeRepository, *fakeFederation) {
	auth := &fakeAuthenticator{}
	for _, o := range orgs {
		auth.organizations = append(auth.organizations, authentication.Organization{ID: o, Name: o.String()})
	}
	repo := &fakeRepository{saved: map[string]hosted.Login{}}
	fed := &fakeFederation{}
	return New(repo, hashSecrets{}, fakeAuthorizations{hosted: true}, auth, nil, fed, nil), auth, repo, fed
}

func setupMFA(second *fakeSecondFactor, orgs ...identity.OrganizationID) (*Service, *fakeAuthenticator, *fakeRepository) {
	_, auth, repo, fed := setup(orgs...)
	return New(repo, hashSecrets{}, fakeAuthorizations{hosted: true}, auth, nil, fed, second), auth, repo
}

var request = hosted.Request{Ticket: "ik_authorize_t", Binding: "bind"}

func TestPasswordSingleOrganizationFinishes(t *testing.T) {
	s, auth, repo, _ := setup(orgA)
	out, err := s.Password(context.Background(), request, "a@example.com", "right")
	if err != nil || out.Login == nil {
		t.Fatalf("want login, got %+v %v", out, err)
	}
	if out.Login.Organization != orgA || len(auth.issued) != 1 || auth.issued[0].ApplicationID != app || auth.issued[0].ResourceID != res {
		t.Fatalf("issued in wrong boundary %+v", auth.issued)
	}
	if len(repo.saved) != 0 {
		t.Fatal("single organization must not keep a pending login")
	}
}

func TestPasswordSeveralOrganizationsThenChoose(t *testing.T) {
	s, auth, repo, _ := setup(orgA, orgB)
	out, err := s.Password(context.Background(), request, "a@example.com", "right")
	if err != nil || out.Login != nil || len(out.Organizations) != 2 {
		t.Fatalf("want choice, got %+v %v", out, err)
	}
	if len(auth.issued) != 0 {
		t.Fatal("no session before the organization is chosen")
	}
	out, err = s.Choose(context.Background(), request, orgB)
	if err != nil || out.Login == nil || out.Login.Organization != orgB {
		t.Fatalf("choose: %+v %v", out, err)
	}
	if repo.deleted != 1 || len(repo.saved) != 0 {
		t.Fatal("pending login must be single-use")
	}
	if _, err = s.Choose(context.Background(), request, orgB); err == nil {
		t.Fatal("second choose must fail")
	}
}

func TestChooseWithoutVerificationFails(t *testing.T) {
	s, auth, _, _ := setup(orgA, orgB)
	if _, err := s.Choose(context.Background(), request, orgA); err == nil {
		t.Fatal("choose without a verified login must fail")
	}
	if len(auth.issued) != 0 {
		t.Fatal("no session may be issued")
	}
}

func TestNoAccessAnywhere(t *testing.T) {
	s, _, _, _ := setup()
	if _, err := s.Password(context.Background(), request, "a@example.com", "right"); err == nil {
		t.Fatal("user without access must be refused")
	}
}

func TestWrongPassword(t *testing.T) {
	s, _, repo, _ := setup(orgA, orgB)
	if _, err := s.Password(context.Background(), request, "a@example.com", "wrong"); err == nil {
		t.Fatal("wrong password must fail")
	}
	if len(repo.saved) != 0 {
		t.Fatal("failed login must not be kept")
	}
}

func TestOrganizationSSOOnlyEntersItsOrganization(t *testing.T) {
	s, auth, _, _ := setup(orgA, orgB)
	out, err := s.Federated(context.Background(), request, authentication.Verified{User: user, Method: authentication.MethodSSO, Organization: orgB})
	if err != nil || out.Login == nil || out.Login.Organization != orgB {
		t.Fatalf("want direct login to orgB, got %+v %v", out, err)
	}
	if len(auth.issued) != 1 || auth.issued[0].OrganizationID != orgB {
		t.Fatalf("issued %+v", auth.issued)
	}
	s, _, _, _ = setup(orgA)
	if _, err = s.Federated(context.Background(), request, authentication.Verified{User: user, Method: authentication.MethodSSO, Organization: orgB}); err == nil {
		t.Fatal("SSO of an organization without access must be refused")
	}
}

func TestNonHostedClientRefused(t *testing.T) {
	_, auth, repo, fed := setup(orgA)
	s := New(repo, hashSecrets{}, fakeAuthorizations{hosted: false}, auth, nil, fed, nil)
	if _, err := s.Password(context.Background(), request, "a@example.com", "right"); err == nil {
		t.Fatal("headless client must not use hosted pages")
	}
	s = New(repo, hashSecrets{}, fakeAuthorizations{hosted: true, err: errx.Unauthorized("bad ticket")}, auth, nil, fed, nil)
	if _, err := s.Page(context.Background(), request); err == nil {
		t.Fatal("dead ticket must fail")
	}
	if len(auth.issued) != 0 {
		t.Fatal("no session may be issued")
	}
}

func TestIdentifyRoutes(t *testing.T) {
	connection := identity.NewConnectionID()
	s, _, _, fed := setup(orgA)
	route, err := s.Identify(context.Background(), request, "a@example.com")
	if err != nil || route.Method != federation.MethodPassword || route.Connection != nil {
		t.Fatalf("plain email: %+v %v", route, err)
	}
	fed.discovery = federation.Discovery{Method: federation.MethodSSO, Organization: &orgA, Connection: &connection}
	route, _ = s.Identify(context.Background(), request, "a@example.com")
	if route.Method != federation.MethodPassword || route.Connection == nil || route.Redirect != "" {
		t.Fatalf("optional SSO offers both: %+v", route)
	}
	fed.discovery.Required = true
	route, _ = s.Identify(context.Background(), request, "a@example.com")
	if route.Method != federation.MethodSSO || route.Redirect == "" || len(fed.started) != 1 {
		t.Fatalf("enforced SSO redirects: %+v", route)
	}
	if fed.started[0].Application != app || fed.started[0].Resource != res {
		t.Fatalf("SSO target %+v", fed.started[0])
	}
}

func TestHostedSecondFactorBeforeChooser(t *testing.T) {
	second := &fakeSecondFactor{enrolled: true}
	s, auth, repo := setupMFA(second, orgA, orgB)
	out, err := s.Password(context.Background(), request, "a@example.com", "right")
	if err != nil || !out.SecondFactor || len(out.Organizations) != 0 {
		t.Fatalf("want second factor first, got %+v %v", out, err)
	}
	if out, err = s.Choose(context.Background(), request, orgA); err != nil || !out.SecondFactor {
		t.Fatalf("choosing before the second factor must ask for it again: %+v %v", out, err)
	}
	if len(auth.issued) != 0 {
		t.Fatal("no session before the second factor")
	}
	for range 5 {
		if _, err = s.SecondFactor(context.Background(), request, "000000"); err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	if _, err = s.SecondFactor(context.Background(), request, "123456"); err == nil || len(repo.saved) != 0 {
		t.Fatal("after 5 wrong codes the login must be dropped")
	}

	// Fresh login, right code → chooser → session.
	s, auth, _ = setupMFA(second, orgA, orgB)
	if _, err = s.Password(context.Background(), request, "a@example.com", "right"); err != nil {
		t.Fatal(err)
	}
	out, err = s.SecondFactor(context.Background(), request, "123456")
	if err != nil || len(out.Organizations) != 2 {
		t.Fatalf("want chooser after code, got %+v %v", out, err)
	}
	out, err = s.Choose(context.Background(), request, orgB)
	if err != nil || out.Login == nil || len(auth.issued) != 1 {
		t.Fatalf("choose after mfa: %+v %v", out, err)
	}
}

func TestHostedRequiredOrganizationEnrolls(t *testing.T) {
	second := &fakeSecondFactor{required: map[identity.OrganizationID]bool{orgA: true}}
	s, auth, repo := setupMFA(second, orgA)
	out, err := s.Password(context.Background(), request, "a@example.com", "right")
	if err != nil || out.Enroll == nil || out.Enroll.Secret == "" {
		t.Fatalf("want enrollment, got %+v %v", out, err)
	}
	if e, err := s.Enrollment(context.Background(), request); err != nil || e.URI == "" {
		t.Fatalf("enrollment page: %+v %v", e, err)
	}
	out, err = s.SecondFactor(context.Background(), request, "123456")
	if err != nil || len(out.RecoveryCodes) == 0 || out.Login != nil {
		t.Fatalf("want recovery codes, got %+v %v", out, err)
	}
	out, err = s.Continue(context.Background(), request)
	if err != nil || out.Login == nil || len(auth.issued) != 1 || len(repo.saved) != 0 {
		t.Fatalf("continue: %+v %v", out, err)
	}
}

func TestHostedFederatedSkipsSecondFactor(t *testing.T) {
	second := &fakeSecondFactor{enrolled: true}
	s, auth, _ := setupMFA(second, orgA)
	out, err := s.Federated(context.Background(), request, authentication.Verified{User: user, Method: authentication.MethodSSO, Organization: orgA})
	if err != nil || out.Login == nil || len(auth.issued) != 1 {
		t.Fatalf("organization SSO should skip MFA, got %+v %v", out, err)
	}
}

// A social (environment) connection is no organization's identity
// provider, so it never stands in for the second factor.
func TestHostedSocialRequiresSecondFactor(t *testing.T) {
	second := &fakeSecondFactor{enrolled: true}
	s, auth, _ := setupMFA(second, orgA)
	out, err := s.Federated(context.Background(), request, authentication.Verified{User: user, Method: authentication.MethodSSO})
	if err != nil || !out.SecondFactor || len(auth.issued) != 0 {
		t.Fatalf("social login should need the second factor, got %+v %v", out, err)
	}
}

func TestSettingsValidate(t *testing.T) {
	for _, bad := range []hosted.Settings{
		{LogoURL: "http://example.com/logo.png"},
		{LogoURL: "javascript:alert(1)"},
		{AccentColor: "red"},
		{AccentColor: "#12345"},
		{AccentColor: "#1234567"},
	} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	ok := hosted.Settings{DisplayName: "  Acme ", LogoURL: "https://cdn.example/l.png", AccentColor: "#AABBCC"}
	if err := ok.Validate(); err != nil || ok.DisplayName != "Acme" || ok.AccentColor != "#aabbcc" {
		t.Fatalf("normalize: %+v %v", ok, err)
	}
	if ok.Theme.Light.Primary != "#aabbcc" || ok.Theme.Mode != hosted.ModeLight || *ok.Theme.Radius != hosted.DefaultRadius ||
		ok.Theme.Spacing != hosted.SpacingNormal || ok.Theme.Align != hosted.AlignCenter || ok.Theme.LogoPosition != hosted.PositionCard || ok.Theme.Footer.Links == nil {
		t.Fatalf("theme defaults: %+v", ok.Theme)
	}
	// theme.light.primary wins over accent_color and is mirrored into it.
	both := hosted.Settings{AccentColor: "#111111", Theme: hosted.Theme{Light: hosted.Palette{Primary: "#222222"}}}
	if err := both.Validate(); err != nil || both.AccentColor != "#222222" {
		t.Fatalf("primary: %+v %v", both, err)
	}
}

func TestThemeValidate(t *testing.T) {
	big, negative := 25, -1
	links := make([]hosted.Link, 6)
	for i := range links {
		links[i] = hosted.Link{Label: "x", URL: "https://x.example"}
	}
	for name, bad := range map[string]hosted.Theme{
		"mode":           {Mode: "sepia"},
		"spacing":        {Spacing: "huge"},
		"align":          {Align: "top"},
		"radius high":    {Radius: &big},
		"radius low":     {Radius: &negative},
		"dark color":     {Dark: hosted.Palette{Card: "black"}},
		"css injection":  {Light: hosted.Palette{Background: "#fff;}body{display:none"}},
		"favicon http":   {FaviconURL: "http://cdn.example/f.ico"},
		"dark logo js":   {LogoDarkURL: "javascript:alert(1)"},
		"header logo":    {LogoPosition: hosted.PositionHeader},
		"too many links": {Footer: hosted.Footer{Links: links}},
		"link js":        {Footer: hosted.Footer{Links: []hosted.Link{{Label: "x", URL: "javascript:alert(1)"}}}},
		"link no label":  {Footer: hosted.Footer{Links: []hosted.Link{{URL: "https://x.example"}}}},
		"footer text":    {Footer: hosted.Footer{Text: strings.Repeat("a", 201)}},
	} {
		s := hosted.Settings{Theme: bad}
		if s.Validate() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	good := hosted.Settings{Theme: hosted.Theme{Mode: " Adaptive ", Header: hosted.Header{Show: true}, LogoPosition: "header",
		Footer: hosted.Footer{Links: []hosted.Link{{Label: " Help ", URL: "mailto:help@acme.example"}}}}}
	if err := good.Validate(); err != nil || good.Theme.Mode != hosted.ModeAdaptive || good.Theme.Footer.Links[0].Label != "Help" {
		t.Fatalf("good: %+v %v", good.Theme, err)
	}
}

func TestPageUsesClientStyleOrDefault(t *testing.T) {
	s, _, repo, _ := setup(orgA)
	repo.branding = hosted.Settings{DisplayName: "Default"}
	page, err := s.Page(context.Background(), request)
	if err != nil || page.Settings.DisplayName != "Default" || page.Settings.Theme.Mode != hosted.ModeLight {
		t.Fatalf("default: %+v %v", page.Settings, err)
	}
	repo.styles = map[identity.ClientID]hosted.Settings{client: {DisplayName: "Billing", Theme: hosted.Theme{Mode: hosted.ModeDark}}}
	page, err = s.Page(context.Background(), request)
	if err != nil || page.Settings.DisplayName != "Billing" || page.Settings.Theme.Mode != hosted.ModeDark {
		t.Fatalf("client: %+v %v", page.Settings, err)
	}
}

// Per-client sign-in options gate every step, not just what the page shows.
func TestSignInOptionsGateMethods(t *testing.T) {
	google, github, orgSSO := identity.NewConnectionID(), identity.NewConnectionID(), identity.NewConnectionID()
	s, _, repo, fed := setup(orgA)
	fed.connections = []federation.ConnectionSummary{{ID: google, Name: "Google", Provider: "google"}, {ID: github, Name: "GitHub", Provider: "github"}}
	repo.signIn = &hosted.SignIn{EmailCode: true, Connections: []identity.ConnectionID{google}}
	ctx := context.Background()

	page, err := s.Page(ctx, request)
	if err != nil || len(page.Connections) != 1 || page.Connections[0].ID != google {
		t.Fatalf("page must list only the offered connection: %+v %v", page.Connections, err)
	}
	if _, err = s.Password(ctx, request, "a@example.com", "right"); !unavailable(err) {
		t.Fatalf("password must be refused, got %v", err)
	}
	if _, err = s.SendReset(ctx, request, "a@example.com"); !unavailable(err) {
		t.Fatalf("reset must be refused, got %v", err)
	}
	if _, err = s.SSO(ctx, request, github); !unavailable(err) {
		t.Fatalf("unlisted connection must be refused, got %v", err)
	}
	if _, err = s.SSO(ctx, request, orgSSO); !unavailable(err) {
		t.Fatalf("organization SSO must be refused, got %v", err)
	}
	if _, err = s.SSO(ctx, request, google); err != nil {
		t.Fatalf("offered connection: %v", err)
	}
	// Email code only: an organization that enforces SSO cannot sign in.
	fed.discovery = federation.Discovery{Method: federation.MethodSSO, Connection: &orgSSO, Required: true}
	if _, err = s.Identify(ctx, request, "a@acme.com"); err == nil {
		t.Fatal("enforced SSO the client does not offer must be refused")
	}
	fed.discovery = federation.Discovery{Method: federation.MethodSSO, Connection: &orgSSO}
	if route, err := s.Identify(ctx, request, "a@acme.com"); err != nil || route.Connection != nil || route.Redirect != "" {
		t.Fatalf("optional SSO must not be offered: %+v %v", route, err)
	}

	// Organization SSO only: optional SSO starts at once, other emails fail.
	repo.signIn = &hosted.SignIn{OrganizationSSO: true}
	if route, err := s.Identify(ctx, request, "a@acme.com"); err != nil || route.Redirect == "" {
		t.Fatalf("SSO-only client must start SSO: %+v %v", route, err)
	}
	fed.discovery = federation.Discovery{Method: federation.MethodPassword}
	if _, err = s.Identify(ctx, request, "a@gmail.com"); err == nil {
		t.Fatal("email without SSO must be refused by an SSO-only client")
	}
	if _, err = s.SendCode(ctx, request, "a@gmail.com"); !unavailable(err) {
		t.Fatalf("email code must be refused, got %v", err)
	}

	// Connections only: no email form at all.
	repo.signIn = &hosted.SignIn{AllConnections: true}
	if _, err = s.Identify(ctx, request, "a@acme.com"); !unavailable(err) {
		t.Fatalf("email form must be refused, got %v", err)
	}
	if _, err = s.SSO(ctx, request, github); err != nil {
		t.Fatalf("all connections offered: %v", err)
	}
}

func unavailable(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Code == "SIGN_IN_METHOD_UNAVAILABLE"
}

func TestSaveSignInValidates(t *testing.T) {
	google := identity.NewConnectionID()
	s, _, _, fed := setup(orgA)
	fed.connections = []federation.ConnectionSummary{{ID: google}}
	m := hosted.Mutation{Environment: identity.NewEnvironmentID()}
	client := identity.NewClientID()
	if _, err := s.SaveSignIn(context.Background(), m, client, hosted.SignIn{}); err == nil {
		t.Fatal("no method must be refused")
	}
	if _, err := s.SaveSignIn(context.Background(), m, client, hosted.SignIn{Connections: []identity.ConnectionID{identity.NewConnectionID()}}); err == nil {
		t.Fatal("unknown connection must be refused")
	}
	out, err := s.SaveSignIn(context.Background(), m, client, hosted.SignIn{Password: true, AllConnections: true, Connections: []identity.ConnectionID{google}})
	if err != nil || len(out.Connections) != 0 || out.Client != client {
		t.Fatalf("all connections drops the list: %+v %v", out, err)
	}
	out, err = s.SaveSignIn(context.Background(), m, client, hosted.SignIn{Connections: []identity.ConnectionID{google, google}})
	if err != nil || len(out.Connections) != 1 {
		t.Fatalf("duplicates dropped: %+v %v", out, err)
	}
	if def, err := (&Service{repository: &fakeRepository{}}).SignIn(context.Background(), m.Environment, client); err != nil || !def.Password || !def.AllConnections || def.Custom {
		t.Fatalf("default offers everything: %+v %v", def, err)
	}
}
