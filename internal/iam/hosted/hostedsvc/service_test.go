package hostedsvc

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
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
	saved   map[string]authentication.Verified
	deleted int
}

func (r *fakeRepository) SaveLogin(_ context.Context, hash []byte, _ identity.EnvironmentID, v authentication.Verified, _ time.Time) error {
	r.saved[string(hash)] = v
	return nil
}
func (r *fakeRepository) Login(_ context.Context, hash []byte, _ identity.EnvironmentID) (authentication.Verified, error) {
	v, ok := r.saved[string(hash)]
	if !ok {
		return v, errx.Unauthorized("sign in again")
	}
	return v, nil
}
func (r *fakeRepository) DeleteLogin(_ context.Context, hash []byte) error {
	delete(r.saved, string(hash))
	r.deleted++
	return nil
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
	repo := &fakeRepository{saved: map[string]authentication.Verified{}}
	fed := &fakeFederation{}
	return New(repo, hashSecrets{}, fakeAuthorizations{hosted: true}, auth, nil, fed), auth, repo, fed
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
	login, err := s.Choose(context.Background(), request, orgB)
	if err != nil || login.Organization != orgB {
		t.Fatalf("choose: %+v %v", login, err)
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
	s := New(repo, hashSecrets{}, fakeAuthorizations{hosted: false}, auth, nil, fed)
	if _, err := s.Password(context.Background(), request, "a@example.com", "right"); err == nil {
		t.Fatal("headless client must not use hosted pages")
	}
	s = New(repo, hashSecrets{}, fakeAuthorizations{hosted: true, err: errx.Unauthorized("bad ticket")}, auth, nil, fed)
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
