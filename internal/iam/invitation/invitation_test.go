package invitation

import (
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestState(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	cases := []struct {
		inv  Invitation
		want string
	}{
		{Invitation{ExpiresAt: future}, StatusPending},
		{Invitation{ExpiresAt: now}, StatusExpired},
		{Invitation{ExpiresAt: future, RevokedAt: &past}, StatusRevoked},
		{Invitation{ExpiresAt: past, AcceptedAt: &past}, StatusAccepted},
	}
	for _, c := range cases {
		if got := c.inv.State(now); got != c.want {
			t.Errorf("%+v: got %s want %s", c.inv, got, c.want)
		}
	}
	if !(Invitation{ExpiresAt: past}).Open() || (Invitation{RevokedAt: &past}).Open() {
		t.Error("open: expired stays open, revoked does not")
	}
}

func TestInputValidate(t *testing.T) {
	role := identity.NewRoleID()
	in := Input{Email: " Bob@Example.COM ", Roles: []identity.RoleID{role, {}, role}}
	if err := in.Validate(); err != nil || in.Email != "bob@example.com" || len(in.Roles) != 1 || in.Groups == nil {
		t.Fatalf("normalized = %+v %v", in, err)
	}
	if err := (&Input{Email: "nope"}).Validate(); err == nil {
		t.Error("bad email accepted")
	}
	if err := (&Input{Email: "a@b.example", Groups: make([]identity.GroupID, MaxReferences+1)}).Validate(); err == nil {
		t.Error("too many groups accepted")
	}
}

func TestAcceptanceValidate(t *testing.T) {
	for _, a := range []Acceptance{{Token: "x"}, {Token: TokenPrefix + "a", Password: strings.Repeat("x", 73)}} {
		if err := a.Validate(); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	a := Acceptance{Token: TokenPrefix + "a", Name: "  Bob  "}
	if err := a.Validate(); err != nil || a.Name != "Bob" {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestMask(t *testing.T) {
	for in, want := range map[string]string{"bob@example.com": "b***@example.com", "@x": "***", "x": "***"} {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q", in, got)
		}
	}
}
