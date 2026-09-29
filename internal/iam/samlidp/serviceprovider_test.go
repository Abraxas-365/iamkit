package samlidp_test

import (
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func validCreate() samlidp.Create {
	return samlidp.Create{Name: "Wiki", Application: identity.NewApplicationID(), Resource: identity.NewResourceID(), EntityID: "https://wiki.example.com/saml", ACSURLs: []string{"https://wiki.example.com/acs"}}.WithDefaults()
}

func TestCreateValidate(t *testing.T) {
	if err := validCreate().Validate(); err != nil {
		t.Fatalf("valid create: %v", err)
	}
	cases := map[string]func(*samlidp.Create){
		"name":           func(c *samlidp.Create) { c.Name = "" },
		"application":    func(c *samlidp.Create) { c.Application = identity.ApplicationID{} },
		"resource":       func(c *samlidp.Create) { c.Resource = identity.ResourceID{} },
		"entity":         func(c *samlidp.Create) { c.EntityID = "not a uri" },
		"relative":       func(c *samlidp.Create) { c.EntityID = "wiki" },
		"no acs":         func(c *samlidp.Create) { c.ACSURLs = nil },
		"http acs":       func(c *samlidp.Create) { c.ACSURLs = []string{"http://wiki.example.com/acs"} },
		"duplicate acs":  func(c *samlidp.Create) { c.ACSURLs = []string{"https://a.example/acs", "https://a.example/acs"} },
		"format":         func(c *samlidp.Create) { c.NameIDFormat = "transient" },
		"source":         func(c *samlidp.Create) { c.Attributes = map[string]string{"mail": "password"} },
		"attribute name": func(c *samlidp.Create) { c.Attributes = map[string]string{" ": "email"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validCreate()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
	urn := validCreate()
	urn.EntityID = "urn:example:wiki"
	if err := urn.Validate(); err != nil {
		t.Fatalf("URN entity ID: %v", err)
	}
}

func TestUpdateValidate(t *testing.T) {
	if err := (samlidp.Update{}).Validate(); err == nil {
		t.Fatal("empty update accepted")
	}
	format := "persistent"
	if err := (samlidp.Update{NameIDFormat: &format}).Validate(); err != nil {
		t.Fatalf("persistent format: %v", err)
	}
	bad := []string{}
	if err := (samlidp.Update{ACSURLs: &bad}).Validate(); err == nil {
		t.Fatal("empty ACS list accepted")
	}
}

func TestAssert(t *testing.T) {
	sp := samlidp.ServiceProvider{NameIDFormat: samlidp.NameIDEmail, Attributes: map[string]string{"mail": "email", "roles": "permissions", "uid": "user_id", "display": "name", "org": "organization_id"}}
	login := samlidp.Login{User: identity.NewUserID(), Organization: identity.NewOrganizationID(), Session: identity.NewSessionID(), Permissions: []string{"wiki:read", "wiki:write"}}
	out := sp.Assert(login, samlidp.Subject{Email: "ada@example.com", Name: "Ada"})
	if out.NameID != "ada@example.com" || out.NameIDFormat != samlidp.NameIDEmail || out.Session != login.Session {
		t.Fatalf("subject: %+v", out)
	}
	want := map[string][]string{"display": {"Ada"}, "mail": {"ada@example.com"}, "org": {login.Organization.String()}, "roles": {"wiki:read", "wiki:write"}, "uid": {login.User.String()}}
	if len(out.Attributes) != len(want) {
		t.Fatalf("attributes: %+v", out.Attributes)
	}
	for i, a := range out.Attributes {
		if i > 0 && out.Attributes[i-1].Name >= a.Name {
			t.Fatalf("attributes not sorted: %+v", out.Attributes)
		}
		if len(a.Values) != len(want[a.Name]) {
			t.Fatalf("attribute %s: %v", a.Name, a.Values)
		}
		for j := range a.Values {
			if a.Values[j] != want[a.Name][j] {
				t.Fatalf("attribute %s: %v", a.Name, a.Values)
			}
		}
	}
	sp.NameIDFormat = samlidp.NameIDPersistent
	if out := sp.Assert(login, samlidp.Subject{Email: "ada@example.com"}); out.NameID != login.User.String() || out.NameIDFormat != samlidp.NameIDPersistent {
		t.Fatalf("persistent subject: %+v", out)
	}
	// No organization chosen, no permissions: those attributes are left out.
	login.Organization, login.Permissions = identity.OrganizationID{}, nil
	if out := sp.Assert(login, samlidp.Subject{Email: "ada@example.com", Name: "Ada"}); len(out.Attributes) != 3 {
		t.Fatalf("empty attributes kept: %+v", out.Attributes)
	}
}

func TestCheck(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sso := "https://iam.example.com/saml/env/sso"
	sp := samlidp.ServiceProvider{ID: identity.NewServiceProviderID(), ACSURLs: []string{"https://a.example/acs", "https://a.example/acs2"}}
	base := samlidp.AuthnRequest{ID: "id-1", Issuer: "https://a.example", Version: "2.0", IssueInstant: now.Add(-10 * time.Second), Destination: sso, ProtocolBinding: samlidp.PostBinding, RelayState: "state"}

	out, err := base.Check(sso, now, sp)
	if err != nil || out.ACSURL != sp.ACSURLs[0] || out.ID != "id-1" || out.RelayState != "state" || out.ServiceProvider != sp.ID {
		t.Fatalf("default ACS: %+v %v", out, err)
	}
	explicit := base
	explicit.ACSURL = sp.ACSURLs[1]
	if out, err := explicit.Check(sso, now, sp); err != nil || out.ACSURL != sp.ACSURLs[1] {
		t.Fatalf("explicit ACS: %+v %v", out, err)
	}
	indexed := base
	indexed.ACSIndex = "1"
	if out, err := indexed.Check(sso, now, sp); err != nil || out.ACSURL != sp.ACSURLs[1] {
		t.Fatalf("indexed ACS: %+v %v", out, err)
	}
	bad := map[string]func(*samlidp.AuthnRequest){
		"version":     func(r *samlidp.AuthnRequest) { r.Version = "1.1" },
		"id":          func(r *samlidp.AuthnRequest) { r.ID = "" },
		"destination": func(r *samlidp.AuthnRequest) { r.Destination = "https://evil.example/sso" },
		"old":         func(r *samlidp.AuthnRequest) { r.IssueInstant = now.Add(-2 * time.Minute) },
		"future":      func(r *samlidp.AuthnRequest) { r.IssueInstant = now.Add(2 * time.Minute) },
		"binding": func(r *samlidp.AuthnRequest) {
			r.ProtocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
		},
		"acs":          func(r *samlidp.AuthnRequest) { r.ACSURL = "https://evil.example/acs" },
		"index":        func(r *samlidp.AuthnRequest) { r.ACSIndex = "5" },
		"index format": func(r *samlidp.AuthnRequest) { r.ACSIndex = "x" },
		"relay state":  func(r *samlidp.AuthnRequest) { r.RelayState = string(make([]byte, samlidp.MaxRelayState+1)) },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if _, err := r.Check(sso, now, sp); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
