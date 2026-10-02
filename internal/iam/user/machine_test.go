package user

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestCreateMachine(t *testing.T) {
	ok := Create{Kind: KindMachine, Name: "Invoice sync"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("machine user refused: %v", err)
	}
	for name, c := range map[string]Create{
		"email":    {Kind: KindMachine, Name: "bot", Email: "bot@example.com"},
		"password": {Kind: KindMachine, Name: "bot", Password: "correct horse battery"},
		"username": {Kind: KindMachine, Name: "bot", Username: "bot"},
		"otp":      {Kind: KindMachine, Name: "bot", OTPEnabled: true},
		"kind":     {Kind: "robot", Name: "bot"},
		"name":     {Kind: KindMachine},
	} {
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (Filter{Kind: "robot"}).Validate() == nil {
		t.Error("unknown filter kind accepted")
	}
	if (Filter{Kind: KindMachine}).Validate() != nil {
		t.Error("machine filter refused")
	}
}

func TestNewAccessToken(t *testing.T) {
	s := func(v string) *string { return &v }
	ok := NewAccessToken{Name: "ci", Organization: identity.NewOrganizationID(), Application: identity.NewApplicationID(), Resource: identity.NewResourceID()}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	never := ok
	never.ExpiresIn = s("never")
	if never.Validate() != nil {
		t.Fatal("never refused")
	}
	for name, mutate := range map[string]func(*NewAccessToken){
		"name":         func(n *NewAccessToken) { n.Name = " " },
		"organization": func(n *NewAccessToken) { n.Organization = identity.OrganizationID{} },
		"application":  func(n *NewAccessToken) { n.Application = identity.ApplicationID{} },
		"resource":     func(n *NewAccessToken) { n.Resource = identity.ResourceID{} },
		"short ttl":    func(n *NewAccessToken) { n.ExpiresIn = s("10m") },
		"bad ttl":      func(n *NewAccessToken) { n.ExpiresIn = s("soon") },
	} {
		n := ok
		mutate(&n)
		if n.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
