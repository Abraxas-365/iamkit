package apikey

import (
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func str(s string) *string { return &s }

func valid(kind OwnerKind) NewAPIKey {
	n := NewAPIKey{
		Owner: Owner{Type: kind}, Name: "ci", Organization: identity.NewOrganizationID(),
		Resource: identity.NewResourceID(), Permissions: []string{"orders:read"},
	}
	if kind != OwnerOrganization {
		n.Owner.User = identity.NewUserID()
	}
	if kind == OwnerMachine {
		n.Application = identity.NewApplicationID()
	}
	return n
}

func TestNewAPIKeyValidate(t *testing.T) {
	for _, kind := range []OwnerKind{OwnerUser, OwnerOrganization, OwnerMachine} {
		if err := valid(kind).Validate(); err != nil {
			t.Fatalf("%s: valid key refused: %v", kind, err)
		}
	}
	machine := valid(OwnerMachine)
	machine.Permissions = nil
	if machine.Validate() != nil {
		t.Error("machine key without permissions refused")
	}
	for name, mutate := range map[string]func(*NewAPIKey){
		"owner type":          func(n *NewAPIKey) { n.Owner.Type = "robot" },
		"org key with user":   func(n *NewAPIKey) { n.Owner = Owner{Type: OwnerOrganization, User: identity.NewUserID()} },
		"user key no user":    func(n *NewAPIKey) { n.Owner = Owner{Type: OwnerUser} },
		"name":                func(n *NewAPIKey) { n.Name = " " },
		"long name":           func(n *NewAPIKey) { n.Name = string(make([]byte, MaxName+1)) },
		"organization":        func(n *NewAPIKey) { n.Organization = identity.OrganizationID{} },
		"resource":            func(n *NewAPIKey) { n.Resource = identity.ResourceID{} },
		"user key permission": func(n *NewAPIKey) { n.Permissions = nil },
		"blank permission":    func(n *NewAPIKey) { n.Permissions = []string{" "} },
		"application on user": func(n *NewAPIKey) { n.Application = identity.NewApplicationID() },
		"bad ttl":             func(n *NewAPIKey) { n.ExpiresIn = str("soon") },
		"short ttl":           func(n *NewAPIKey) { n.ExpiresIn = str("10m") },
	} {
		n := valid(OwnerUser)
		mutate(&n)
		if n.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	m := valid(OwnerMachine)
	m.Application = identity.ApplicationID{}
	if m.Validate() == nil {
		t.Error("machine key without application accepted")
	}
}

func TestTTL(t *testing.T) {
	n := valid(OwnerUser)
	if d, err := n.TTL(); err != nil || d != identity.NoExpiry {
		t.Fatalf("omitted = %v, %v; want never", d, err)
	}
	n.ExpiresIn = str("never")
	if d, _ := n.TTL(); d != identity.NoExpiry {
		t.Errorf("never = %v", d)
	}
	n.ExpiresIn = str("720h")
	if d, _ := n.TTL(); d != 720*time.Hour {
		t.Errorf("720h = %v", d)
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{MaxPerUser: 10, MaxPerOrganization: 50}
	if p.Allows(OwnerUser) || p.Allows(OwnerOrganization) || !p.Allows(OwnerMachine) {
		t.Error("default policy allows wrong kinds")
	}
	p.UserKeys = true
	if !p.Allows(OwnerUser) || p.Allows(OwnerOrganization) {
		t.Error("user_keys not honoured")
	}
	if p.Validate() != nil {
		t.Error("valid policy refused")
	}
	days := 30
	p.MaxTTLDays = &days
	if p.CheckTTL(24*time.Hour) != nil || p.CheckTTL(30*24*time.Hour) != nil {
		t.Error("ttl within maximum refused")
	}
	if p.CheckTTL(31*24*time.Hour) == nil || p.CheckTTL(identity.NoExpiry) == nil {
		t.Error("ttl past maximum accepted")
	}
	p.MaxTTLDays = nil
	if p.CheckTTL(identity.NoExpiry) != nil {
		t.Error("no maximum refused never")
	}
	for name, mutate := range map[string]func(*Policy){
		"ttl zero":  func(p *Policy) { d := 0; p.MaxTTLDays = &d },
		"ttl big":   func(p *Policy) { d := 366; p.MaxTTLDays = &d },
		"per user":  func(p *Policy) { p.MaxPerUser = 0 },
		"per user+": func(p *Policy) { p.MaxPerUser = 101 },
		"per org":   func(p *Policy) { p.MaxPerOrganization = 0 },
		"per org+":  func(p *Policy) { p.MaxPerOrganization = 501 },
	} {
		q := Policy{MaxPerUser: 10, MaxPerOrganization: 50}
		mutate(&q)
		if q.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScopeNarrow(t *testing.T) {
	env, org, user, other := identity.NewEnvironmentID(), identity.NewOrganizationID(), identity.NewUserID(), identity.NewOrganizationID()
	f := Filter{Organization: other, OwnerType: OwnerMachine, User: identity.NewUserID()}
	if got := EnvironmentScope(env).Narrow(f); got != f {
		t.Error("environment scope changed the filter")
	}
	got := OrganizationScope(env, org).Narrow(f)
	if got.Organization != org {
		t.Error("organization scope did not pin the organization")
	}
	self := SelfScope(env, org, user).Narrow(f)
	if self.Organization != org || self.User != user || self.OwnerType != OwnerUser {
		t.Errorf("self scope = %+v", self)
	}
}

func TestFreshAuth(t *testing.T) {
	now := time.Now()
	if FreshAuth(now.Add(-time.Minute).Unix(), now) != nil {
		t.Error("recent sign-in refused")
	}
	for _, at := range []int64{0, now.Add(-time.Hour).Unix()} {
		err := FreshAuth(at, now)
		var e *errx.Error
		if err == nil || !errAs(err, &e) || e.Code != "REAUTHENTICATION_REQUIRED" {
			t.Errorf("auth_time %d: %v", at, err)
		}
	}
}

func TestTarget(t *testing.T) {
	org, key := identity.NewOrganizationID(), identity.NewAPIKeyID()
	if Target(OwnerMachine, org, key) != key.String() {
		t.Error("machine target is the bare id")
	}
	if Target(OwnerUser, org, key) != "/organizations/"+org.String()+"/api-keys/"+key.String() {
		t.Error("user target")
	}
}

func TestErrLimitReached(t *testing.T) {
	var e *errx.Error
	if !errAs(ErrLimitReached("x"), &e) || e.Code != "API_KEY_LIMIT_REACHED" || e.HTTPStatus != 422 {
		t.Errorf("limit error = %+v", e)
	}
}
