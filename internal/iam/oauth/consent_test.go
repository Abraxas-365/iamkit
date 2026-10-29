package oauth

import (
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

func TestCheckConsentPolicy(t *testing.T) {
	cases := []struct {
		policy, source, preset string
		ok                     bool
	}{
		{ConsentSkip, SourceRegistered, "", true},
		{ConsentRequired, SourceRegistered, "", true},
		{ConsentSkip, "", "", true},
		{ConsentSkip, SourceRegistered, "gemini_cli", false},
		{ConsentRequired, SourceRegistered, "gemini_cli", true},
		{ConsentSkip, SourceCIMD, "", false},
		{ConsentSkip, "dcr", "", false},
		{ConsentRequired, SourceCIMD, "", true},
		{"maybe", SourceRegistered, "", false},
		{"", SourceRegistered, "", false},
	}
	for _, c := range cases {
		if err := CheckConsentPolicy(c.policy, c.source, c.preset); (err == nil) != c.ok {
			t.Errorf("CheckConsentPolicy(%q, %q, %q) = %v, want ok %v", c.policy, c.source, c.preset, err, c.ok)
		}
	}
}

func TestRequiresConsent(t *testing.T) {
	if (Client{ConsentPolicy: ConsentSkip, Source: SourceRegistered}).RequiresConsent() {
		t.Error("first-party skip client requires consent")
	}
	if !(Client{ConsentPolicy: ConsentRequired}).RequiresConsent() {
		t.Error("required client skips consent")
	}
	// A row that says skip never lets an external client through.
	if !(Client{ConsentPolicy: ConsentSkip, Source: SourceCIMD}).RequiresConsent() {
		t.Error("external client skips consent")
	}
}

func TestConsentScopes(t *testing.T) {
	target := &ProtectedTarget{Scopes: []string{"mcp:read", "mcp:write"}}
	got := ConsentScopes(target, []string{"openid", "offline_access", "mcp:read", "email", "profile", "mcp:read", "billing:read"})
	if want := []string{"mcp:read", "email", "profile"}; !slices.Equal(got, want) {
		t.Fatalf("ConsentScopes = %v, want %v", got, want)
	}
}

func TestPendingConsent(t *testing.T) {
	asked := []string{"mcp:read", "mcp:write", "email"}
	cases := []struct {
		name   string
		agreed Agreed
		force  bool
		want   []string
	}{
		{"first time", Agreed{}, false, asked},
		{"all agreed", Agreed{User: asked}, false, []string{}},
		{"step-up asks only what is new", Agreed{User: []string{"mcp:read", "email"}}, false, []string{"mcp:write"}},
		{"admin grant covers", Agreed{Admin: []string{"mcp:read"}, User: []string{"email"}}, false, []string{"mcp:write"}},
		{"prompt=consent re-asks the user's", Agreed{User: asked}, true, asked},
		{"prompt=consent keeps the admin's", Agreed{User: asked, Admin: []string{"mcp:read"}}, true, []string{"mcp:write", "email"}},
	}
	for _, c := range cases {
		if got := PendingConsent(asked, c.agreed, c.force); !slices.Equal(got, c.want) {
			t.Errorf("%s: PendingConsent = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAllowedAtRefresh(t *testing.T) {
	consented := []string{"mcp:read", "mcp:write"}
	cases := []struct {
		agreed Agreed
		want   []string
	}{
		{Agreed{User: []string{"mcp:read", "mcp:write", "mcp:admin"}}, consented},
		// A narrowed consent narrows the refresh; it never widens it.
		{Agreed{User: []string{"mcp:read", "mcp:admin"}}, []string{"mcp:read"}},
		{Agreed{Admin: []string{"mcp:write"}}, []string{"mcp:write"}},
		{Agreed{}, []string{}},
	}
	for _, c := range cases {
		if got := AllowedAtRefresh(consented, c.agreed); !slices.Equal(got, c.want) {
			t.Errorf("AllowedAtRefresh(%v) = %v, want %v", c.agreed, got, c.want)
		}
	}
}

func TestNewConsentPrompt(t *testing.T) {
	held, unheld, agreed := NewConsentPrompt([]string{"mcp:write", "mcp:admin", "email"}, []string{"mcp:read", "mcp:write", "mcp:admin", "email"}, []string{"mcp:read", "mcp:write"})
	if !slices.Equal(held, []string{"mcp:write", "email"}) || !slices.Equal(unheld, []string{"mcp:admin"}) || !slices.Equal(agreed, []string{"mcp:read"}) {
		t.Fatalf("held %v, unheld %v, agreed %v", held, unheld, agreed)
	}
}

func TestClientGrantInput(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	for name, c := range map[string]struct {
		in ClientGrantInput
		ok bool
	}{
		"valid":         {ClientGrantInput{Scopes: []string{"mcp:read"}}, true},
		"with expiry":   {ClientGrantInput{Scopes: []string{"mcp:read"}, ExpiresAt: &future}, true},
		"no scopes":     {ClientGrantInput{}, false},
		"duplicates":    {ClientGrantInput{Scopes: []string{"mcp:read", "mcp:read"}}, false},
		"expired":       {ClientGrantInput{Scopes: []string{"mcp:read"}, ExpiresAt: &past}, false},
		"too many":      {ClientGrantInput{Scopes: manyScopes(MaxConsentScopes + 1)}, false},
		"exactly limit": {ClientGrantInput{Scopes: manyScopes(MaxConsentScopes)}, true},
	} {
		if err := c.in.Validate(now); (err == nil) != c.ok {
			t.Errorf("%s: Validate = %v, want ok %v", name, err, c.ok)
		}
	}
	in := ClientGrantInput{Scopes: []string{"mcp:read", "billing:read"}}
	if err := in.CheckScopes([]string{"mcp:read", "mcp:write"}); err == nil {
		t.Error("CheckScopes accepted a scope outside the resource")
	}
}

func manyScopes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "mcp:p" + strconv.Itoa(i)
	}
	return out
}

func TestConsentErrors(t *testing.T) {
	var pending error = &ConsentPending{Scopes: []string{"mcp:read"}}
	if !errors.Is(pending, ErrConsentPending) {
		t.Error("ConsentPending is not ErrConsentPending")
	}
	for err, code := range map[error]string{ErrConsentNotPending(): CodeConsentNotPending, ErrConsentUI(): CodeConsentHosted} {
		var e *errx.Error
		if !errors.As(err, &e) || e.Code != code {
			t.Errorf("%v: code %v, want %s", err, e, code)
		}
	}
}

func TestValidateAccessTTL(t *testing.T) {
	for _, c := range []struct {
		ttl, idle int64
		ok        bool
	}{
		{900, 86400, true}, {60, 86400, true}, {3600, 86400, true},
		{59, 86400, false}, {3601, 86400, false},
		{900, 600, false}, {600, 600, true},
		// An idle TTL below the minimum still allows the minimum.
		{60, 30, true},
	} {
		if err := validateAccessTTL(c.ttl, c.idle); (err == nil) != c.ok {
			t.Errorf("validateAccessTTL(%d, %d) = %v, want ok %v", c.ttl, c.idle, err, c.ok)
		}
	}
	if err := validateConsentMode("bogus"); err == nil {
		t.Error("validateConsentMode accepted bogus")
	}
	for _, m := range []string{ConsentModePerUser, ConsentModeAdminGranted} {
		if err := validateConsentMode(m); err != nil {
			t.Errorf("validateConsentMode(%s) = %v", m, err)
		}
	}
}
