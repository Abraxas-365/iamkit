package apikeysvc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type fakeRepo struct {
	policy    apikey.Policy
	reach     []string
	held      []string
	stored    []apikey.APIKey
	limit     int
	revoked   []identity.APIKeyID
	last      apikey.Mutation
	findError error
	reachCall int
}

func (f *fakeRepo) Create(_ context.Context, m apikey.Mutation, key apikey.APIKey, _ []byte, limit int) (apikey.APIKey, error) {
	f.last, f.limit = m, limit
	key.State = apikey.StateActive
	f.stored = append(f.stored, key)
	return key, nil
}
func (f *fakeRepo) Revoke(_ context.Context, m apikey.Mutation, id identity.APIKeyID) error {
	f.last = m
	f.revoked = append(f.revoked, id)
	return nil
}
func (f *fakeRepo) List(context.Context, apikey.Scope, apikey.Filter, query.Pagination) (query.Paginated[apikey.APIKey], error) {
	return query.Paginated[apikey.APIKey]{}, nil
}
func (f *fakeRepo) Find(_ context.Context, _ apikey.Scope, id identity.APIKeyID) (apikey.APIKey, error) {
	if f.findError != nil {
		return apikey.APIKey{}, f.findError
	}
	return apikey.APIKey{ID: id, Owner: apikey.Owner{Type: apikey.OwnerOrganization}, Organization: identity.NewOrganizationID()}, nil
}
func (f *fakeRepo) Reach(context.Context, identity.EnvironmentID, apikey.NewAPIKey) ([]string, error) {
	f.reachCall++
	return f.reach, nil
}
func (f *fakeRepo) Held(context.Context, identity.EnvironmentID, identity.OrganizationID, identity.UserID, identity.ResourceID) ([]string, error) {
	return f.held, nil
}
func (f *fakeRepo) OptionResources(context.Context, apikey.Scope, apikey.OwnerKind, identity.UserID, identity.ApplicationID) ([]apikey.OptionResource, error) {
	return nil, nil
}
func (f *fakeRepo) Policy(context.Context, identity.EnvironmentID) (apikey.Policy, error) {
	return f.policy, nil
}
func (f *fakeRepo) SavePolicy(_ context.Context, m apikey.Mutation, p apikey.Policy) (apikey.Policy, error) {
	f.last = m
	return p, nil
}

type fakeSecrets struct{}

func (fakeSecrets) Generate(prefix string) (string, []byte, error) {
	return prefix + "abcdefgh1234", []byte("hash"), nil
}

type fixture struct {
	repo *fakeRepo
	svc  *Service
	env  identity.EnvironmentID
	org  identity.OrganizationID
	user identity.UserID
	res  identity.ResourceID
	app  identity.ApplicationID
	now  time.Time
}

func newFixture() *fixture {
	f := &fixture{
		repo: &fakeRepo{policy: apikey.Policy{UserKeys: true, OrganizationKeys: true, MaxPerUser: 10, MaxPerOrganization: 50},
			reach: []string{"orders:read", "orders:write"}, held: []string{"orders:read", "orders:write"}},
		env: identity.NewEnvironmentID(), org: identity.NewOrganizationID(), user: identity.NewUserID(),
		res: identity.NewResourceID(), app: identity.NewApplicationID(), now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	f.svc = New(f.repo, fakeSecrets{})
	f.svc.SetClock(func() time.Time { return f.now })
	return f
}

func (f *fixture) self() apikey.Mutation {
	return apikey.Mutation{Scope: apikey.SelfScope(f.env, f.org, f.user), Actor: f.user.String(), Application: f.app, AuthTime: f.now.Add(-time.Minute).Unix()}
}

func (f *fixture) userKey(perms ...string) apikey.NewAPIKey {
	return apikey.NewAPIKey{Owner: apikey.Owner{Type: apikey.OwnerUser, User: f.user}, Organization: f.org, Resource: f.res, Name: "ci", Permissions: perms}
}

func code(err error) (string, int) {
	var e *errx.Error
	if errors.As(err, &e) {
		return e.Code, e.HTTPStatus
	}
	return "", 0
}

func TestCreateUserKey(t *testing.T) {
	f := newFixture()
	out, err := f.svc.Create(context.Background(), f.self(), f.userKey("orders:write", "orders:read", "orders:read"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.Value, identity.APIKeyPrefix) {
		t.Errorf("value %q", out.Value)
	}
	if out.ObfuscatedValue != identity.ObfuscatedAPIKey("1234") {
		t.Errorf("obfuscated %q", out.ObfuscatedValue)
	}
	if got := f.repo.stored[0].Permissions; len(got) != 2 || got[0] != "orders:read" {
		t.Errorf("permissions not normalized: %v", got)
	}
	if f.repo.limit != 10 {
		t.Errorf("user key limit = %d", f.repo.limit)
	}
	if f.repo.last.Action != apikey.ActionCreate || f.repo.last.Target != apikey.Target(apikey.OwnerUser, f.org, out.ID) {
		t.Errorf("audit = %q %q", f.repo.last.Action, f.repo.last.Target)
	}
	if want := f.now.Add(identity.NoExpiry).Truncate(time.Second); !out.ExpiresAt.Equal(want) {
		t.Errorf("expires %v, want never %v", out.ExpiresAt, want)
	}
}

func TestPolicyGate(t *testing.T) {
	f := newFixture()
	f.repo.policy.UserKeys = false
	_, err := f.svc.Create(context.Background(), f.self(), f.userKey("orders:read"))
	if c, s := code(err); c != "API_KEYS_DISABLED" || s != 403 {
		t.Fatalf("disabled user keys: %v", err)
	}
	// Machine keys ignore the policy.
	f.repo.policy = apikey.Policy{}
	m := apikey.Mutation{Scope: apikey.EnvironmentScope(f.env), Actor: "op"}
	_, err = f.svc.Create(context.Background(), m, apikey.NewAPIKey{Owner: apikey.Owner{Type: apikey.OwnerMachine, User: f.user}, Organization: f.org, Application: f.app, Resource: f.res, Name: "m"})
	if err != nil {
		t.Fatalf("machine key under empty policy: %v", err)
	}
	if f.repo.limit != 0 {
		t.Errorf("machine keys have no limit, got %d", f.repo.limit)
	}
	if f.repo.stored[0].Application == nil || *f.repo.stored[0].Application != f.app {
		t.Error("machine key lost its application")
	}
	if f.repo.reachCall != 0 {
		t.Error("machine key without permissions checked reach")
	}
}

func TestMaxTTL(t *testing.T) {
	f := newFixture()
	days := 30
	f.repo.policy.MaxTTLDays = &days
	in := f.userKey("orders:read")
	if _, err := f.svc.Create(context.Background(), f.self(), in); err == nil {
		t.Fatal("never accepted under max_ttl_days")
	}
	in.ExpiresIn = ptr("720h")
	if _, err := f.svc.Create(context.Background(), f.self(), in); err != nil {
		t.Fatalf("720h under 30d: %v", err)
	}
	in.ExpiresIn = ptr("721h")
	if _, err := f.svc.Create(context.Background(), f.self(), in); err == nil {
		t.Fatal("721h accepted under 30d")
	}
}

func ptr(s string) *string { return &s }

func TestPermissionsWithinReach(t *testing.T) {
	f := newFixture()
	_, err := f.svc.Create(context.Background(), f.self(), f.userKey("orders:read", "orders:admin"))
	if c, s := code(err); s != 422 || !strings.Contains(err.Error(), "orders:admin") {
		t.Fatalf("extra permission: %v (%s)", err, c)
	}
}

func TestSelfScopeRules(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	stale := f.self()
	stale.AuthTime = f.now.Add(-time.Hour).Unix()
	if _, err := f.svc.Create(ctx, stale, f.userKey("orders:read")); err == nil {
		t.Error("stale sign-in accepted")
	} else if c, _ := code(err); c != "REAUTHENTICATION_REQUIRED" {
		t.Errorf("stale code %q", c)
	}
	other := f.userKey("orders:read")
	other.Owner.User = identity.NewUserID()
	if _, err := f.svc.Create(ctx, f.self(), other); err == nil {
		t.Error("key for another user accepted")
	}
	foreign := f.userKey("orders:read")
	foreign.Organization = identity.NewOrganizationID()
	if _, err := f.svc.Create(ctx, f.self(), foreign); err == nil {
		t.Error("key in another organization accepted")
	}
	noApp := f.self()
	noApp.Application = identity.ApplicationID{}
	if _, err := f.svc.Create(ctx, noApp, f.userKey("orders:read")); err == nil {
		t.Error("self scope without application accepted")
	}
	org := f.userKey("orders:read")
	org.Owner = apikey.Owner{Type: apikey.OwnerOrganization}
	if _, err := f.svc.Create(ctx, f.self(), org); err == nil {
		t.Error("organization key from a self scope accepted")
	}
}

func TestOrganizationScope(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	m := apikey.Mutation{Scope: apikey.OrganizationScope(f.env, f.org), Actor: f.user.String(), Granter: f.user}
	in := apikey.NewAPIKey{Owner: apikey.Owner{Type: apikey.OwnerOrganization}, Organization: f.org, Resource: f.res, Name: "svc", Permissions: []string{"orders:read"}}
	out, err := f.svc.Create(ctx, m, in)
	if err != nil {
		t.Fatal(err)
	}
	if f.repo.limit != 50 || out.Owner.Type != apikey.OwnerOrganization {
		t.Errorf("limit %d owner %v", f.repo.limit, out.Owner)
	}
	// Granter check: the admin lacks orders:write.
	f.repo.held = []string{"orders:read"}
	in.Permissions = []string{"orders:read", "orders:write"}
	if _, err := f.svc.Create(ctx, m, in); err == nil {
		t.Error("permission the admin lacks accepted")
	}
	// No user behind the call (setup link): no keys.
	m.Granter = identity.UserID{}
	if _, err := f.svc.Create(ctx, m, in); err == nil {
		t.Error("granter-less organization scope accepted")
	}
	// Another organization.
	m.Granter = f.user
	in.Organization = identity.NewOrganizationID()
	if _, err := f.svc.Create(ctx, m, in); err == nil {
		t.Error("other organization accepted")
	}
	// An organization admin cannot create machine keys.
	mach := apikey.NewAPIKey{Owner: apikey.Owner{Type: apikey.OwnerMachine, User: f.user}, Organization: f.org, Application: f.app, Resource: f.res, Name: "m"}
	if _, err := f.svc.Create(ctx, m, mach); err == nil {
		t.Error("machine key from an organization scope accepted")
	}
}

func TestOperatorCannotCreateUserKey(t *testing.T) {
	f := newFixture()
	m := apikey.Mutation{Scope: apikey.EnvironmentScope(f.env), Actor: "op"}
	if _, err := f.svc.Create(context.Background(), m, f.userKey("orders:read")); err == nil {
		t.Error("operator created a user key")
	}
}

func TestRevokeAndPolicy(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	id := identity.NewAPIKeyID()
	m := apikey.Mutation{Scope: apikey.EnvironmentScope(f.env), Actor: "op"}
	if err := f.svc.Revoke(ctx, m, id); err != nil {
		t.Fatal(err)
	}
	if len(f.repo.revoked) != 1 || f.repo.last.Action != apikey.ActionRevoke {
		t.Errorf("revoke audit %q", f.repo.last.Action)
	}
	if err := f.svc.Revoke(ctx, m, identity.APIKeyID{}); err == nil {
		t.Error("zero id accepted")
	}
	f.repo.findError = errx.NotFound("API key not found")
	if err := f.svc.Revoke(ctx, m, id); err == nil || len(f.repo.revoked) != 1 {
		t.Error("a key outside the scope was revoked")
	}
	if _, err := f.svc.SavePolicy(ctx, m, apikey.Policy{MaxPerUser: 0, MaxPerOrganization: 1}); err == nil {
		t.Error("invalid policy saved")
	}
	if _, err := f.svc.SavePolicy(ctx, m, apikey.Policy{MaxPerUser: 5, MaxPerOrganization: 5}); err != nil || f.repo.last.Action != apikey.ActionPolicyUpdate {
		t.Errorf("save policy: %v %q", err, f.repo.last.Action)
	}
}

func TestListFilters(t *testing.T) {
	f := newFixture()
	scope := apikey.EnvironmentScope(f.env)
	if _, err := f.svc.List(context.Background(), scope, apikey.Filter{OwnerType: "robot"}, query.Pagination{}); err == nil {
		t.Error("bad owner_type accepted")
	}
	if _, err := f.svc.List(context.Background(), scope, apikey.Filter{State: "gone"}, query.Pagination{}); err == nil {
		t.Error("bad state accepted")
	}
	if _, err := f.svc.List(context.Background(), scope, apikey.Filter{State: apikey.StateActive}, query.Pagination{}); err != nil {
		t.Error(err)
	}
}

func TestOptions(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	f.repo.policy.UserKeys = false
	out, err := f.svc.Options(ctx, apikey.SelfScope(f.env, f.org, f.user), f.user, f.app)
	if err != nil || out.Enabled || out.Resources == nil {
		t.Fatalf("disabled options: %+v %v", out, err)
	}
	f.repo.policy.UserKeys = true
	out, _ = f.svc.Options(ctx, apikey.SelfScope(f.env, f.org, f.user), f.user, f.app)
	if !out.Enabled {
		t.Error("enabled options not enabled")
	}
	if _, err = f.svc.Options(ctx, apikey.EnvironmentScope(f.env), f.user, f.app); err == nil {
		t.Error("environment scope options accepted")
	}
}
