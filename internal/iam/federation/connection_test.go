package federation

import (
	"fmt"
	"strings"
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
	if got, err := (ConnectionUpdate{JITGroup: &zero}).Apply(c); err != nil || !got.JITGroup.IsZero() {
		t.Fatal("group not cleared")
	}
	if got, err := (ConnectionUpdate{}).Apply(c); err != nil || got.JITGroup != c.JITGroup {
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

func TestGroupMappingValidation(t *testing.T) {
	org, group := identity.NewOrganizationID(), identity.NewGroupID()
	base := ConnectionInput{Organization: org, Name: "a", Issuer: "https://i", Client: "c", ClientSecret: "s"}
	ok := base
	ok.GroupMappings = []GroupMapping{{Value: " eng ", Group: group}, {Value: "eng", Group: identity.NewGroupID()}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	c := ok.Connection(identity.NewEnvironmentID())
	if c.GroupMappings[0].Value != "eng" || c.Validate() != nil {
		t.Fatalf("mappings %+v", c.GroupMappings)
	}
	tooMany := make([]GroupMapping, MaxGroupMappings+1)
	for i := range tooMany {
		tooMany[i] = GroupMapping{Value: fmt.Sprint(i), Group: group}
	}
	for name, m := range map[string][]GroupMapping{
		"empty value": {{Value: "  ", Group: group}},
		"long value":  {{Value: strings.Repeat("x", MaxGroupValue+1), Group: group}},
		"no group":    {{Value: "eng"}},
		"duplicate":   {{Value: "eng", Group: group}, {Value: "eng ", Group: group}},
		"too many":    tooMany,
	} {
		in := base
		in.GroupMappings = m
		if in.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	env := ConnectionInput{Name: "a", Issuer: "https://i", Client: "c", ClientSecret: "s", GroupMappings: []GroupMapping{{Value: "eng", Group: group}}}
	if env.Validate() == nil {
		t.Error("environment connection with mappings accepted")
	}
}

func TestUpdateGroupMappings(t *testing.T) {
	group := identity.NewGroupID()
	c := Connection{Organization: identity.NewOrganizationID(), JIT: true, Enforcement: EnforcementOptional, GroupMappings: []GroupMapping{{Value: "a", Group: group}}}
	if got, err := (ConnectionUpdate{}).Apply(c); err != nil || len(got.GroupMappings) != 1 {
		t.Fatalf("nil must keep: %+v %v", got.GroupMappings, err)
	}
	if got, err := (ConnectionUpdate{GroupMappings: []GroupMapping{}}).Apply(c); err != nil || len(got.GroupMappings) != 0 {
		t.Fatalf("[] must clear: %+v %v", got.GroupMappings, err)
	}
	if got, err := (ConnectionUpdate{GroupMappings: []GroupMapping{{Value: " b ", Group: group}}}).Apply(c); err != nil || got.GroupMappings[0].Value != "b" {
		t.Fatalf("replace: %+v %v", got.GroupMappings, err)
	}
	if (ConnectionUpdate{GroupMappings: []GroupMapping{{Value: "", Group: group}}}).Validate() == nil {
		t.Error("invalid mapping accepted")
	}
	env := Connection{Enforcement: EnforcementOptional}
	// The service validates the updated connection (check).
	if got, err := (ConnectionUpdate{GroupMappings: []GroupMapping{{Value: "a", Group: group}}}).Apply(env); err != nil || got.Validate() == nil {
		t.Errorf("mappings on an environment connection accepted: %v", err)
	}
}

func TestCleanGroups(t *testing.T) {
	var in []string
	for i := 0; i < 300; i++ {
		in = append(in, fmt.Sprint("g", i))
	}
	out := CleanGroups(append([]string{" a ", "", "a", strings.Repeat("x", MaxGroupValue+1), "b"}, in...))
	if len(out) != MaxGroupValues || out[0] != "a" || out[1] != "b" || out[2] != "g0" {
		t.Fatalf("clean: %d %q", len(out), out[:3])
	}
	if CleanGroups(nil) != nil {
		t.Fatal("nil in, non-nil out")
	}
}
