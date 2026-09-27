package hostedsvc

import (
	"context"
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
	env  = identity.NewEnvironmentID()
	app  = identity.NewApplicationID()
	res  = identity.NewResourceID()
	orgA = identity.NewOrganizationID()
	orgB = identity.NewOrganizationID()
	user = identity.NewUserID()
)

type fakeAuthorizations struct {
	hosted bool
	err    error
}

func (f fakeAuthorizations) Pending(context.Context, string, string) (oauth.Pending, error) {
	return oauth.Pending{Client: &oauth.Client{Environment: env, Application: app, Resource: res, HostedLogin: f.hosted}}, f.err
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
	saved   map[string]hosted.Login
	deleted int
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
	discovery federation.Discovery
	started   []authentication.Target
}

func (f *fakeFederation) Discover(context.Context, identity.EnvironmentID, string) (federation.Discovery, error) {
	return f.discovery, nil
}
func (f *fakeFederation) EnvironmentConnections(context.Context, identity.EnvironmentID) ([]federation.ConnectionSummary, error) {
	return nil, nil
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
	out, err := s.Federated(context.Background(), request, authentication.Verified{User: user, Method: authentication.MethodSSO})
	if err != nil || out.Login == nil || len(auth.issued) != 1 {
		t.Fatalf("federated login should skip MFA, got %+v %v", out, err)
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
}
