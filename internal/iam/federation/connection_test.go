package federation

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestConnectionInputDefaultsAndRules(t *testing.T) {
	org := identity.NewOrganizationID()
	valid := ConnectionInput{Organization: org, Name: "Acme", Issuer: "https://idp.example", Client: "c", ClientSecret: "s"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	c := valid.Connection(identity.NewEnvironmentID())
	if !c.JIT || c.Enforcement != EnforcementOptional || c.Validate() != nil {
		t.Fatalf("org defaults = %+v", c)
	}
	legacy := ConnectionInput{Name: "Env", Issuer: "https://idp.example", Client: "c", SecretEnv: "IAMKIT_PROVIDER_X"}
	if c := legacy.Connection(identity.NewEnvironmentID()); c.JIT || c.Validate() != nil {
		t.Fatalf("legacy defaults = %+v", c)
	}
	for name, in := range map[string]ConnectionInput{
		"both secrets": {Name: "a", Issuer: "https://i", Client: "c", ClientSecret: "s", SecretEnv: "IAMKIT_PROVIDER_X"},
		"no secret":    {Name: "a", Issuer: "https://i", Client: "c"},
		"bad env":      {Name: "a", Issuer: "https://i", Client: "c", SecretEnv: "HOME"},
		"http issuer":  {Name: "a", Issuer: "http://i", Client: "c", ClientSecret: "s"},
		"enforcement":  {Name: "a", Issuer: "https://i", Client: "c", ClientSecret: "s", Enforcement: "always"},
	} {
		if in.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	on := true
	env := ConnectionInput{Name: "a", Issuer: "https://i", Client: "c", ClientSecret: "s", JIT: &on}
	if env.Connection(identity.NewEnvironmentID()).Validate() == nil {
		t.Error("environment-wide JIT accepted")
	}
	off := false
	c = ConnectionInput{Organization: org, Name: "a", Issuer: "https://i", Client: "c", ClientSecret: "s", JIT: &off, JITGroup: identity.NewGroupID()}.Connection(identity.NewEnvironmentID())
	if c.Validate() == nil {
		t.Error("group without JIT accepted")
	}
}

func TestUpdateClearsGroup(t *testing.T) {
	c := Connection{Organization: identity.NewOrganizationID(), JIT: true, JITGroup: identity.NewGroupID(), Enforcement: EnforcementOptional}
	var zero identity.GroupID
	if got := (ConnectionUpdate{JITGroup: &zero}).Apply(c); !got.JITGroup.IsZero() {
		t.Fatal("group not cleared")
	}
	if got := (ConnectionUpdate{}).Apply(c); got.JITGroup != c.JITGroup {
		t.Fatal("empty update changed group")
	}
}

func TestAdmit(t *testing.T) {
	yes, no := true, false
	c := Connection{Organization: identity.NewOrganizationID(), JIT: true}
	if email, err := c.Admit(Claims{Email: "Bob@Example.com"}); err != nil || email != "bob@example.com" {
		t.Fatalf("absent email_verified: %q %v", email, err)
	}
	if _, err := c.Admit(Claims{Email: "bob@example.com", EmailVerified: &yes}); err != nil {
		t.Fatal(err)
	}
	for name, claims := range map[string]Claims{"unverified": {Email: "bob@example.com", EmailVerified: &no}, "no email": {}, "bad email": {Email: "bob"}} {
		if _, err := c.Admit(claims); err == nil {
			t.Errorf("%s admitted", name)
		}
	}
	c.JIT = false
	if _, err := c.Admit(Claims{Email: "bob@example.com"}); err == nil {
		t.Error("admitted without JIT")
	}
	if got := (Claims{}).DisplayName("bob@example.com"); got != "bob" {
		t.Errorf("display name = %q", got)
	}
}
