package management

import (
	"strconv"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

func ptr(v bool) *bool { return &v }

const tenant = "11111111-2222-3333-4444-555555555555"

var acme = []string{"acme.com"}

// tooMany is one allowed domain over the limit.
var tooMany = func() []string {
	out := make([]string, MaxSSODomains+1)
	for i := range out {
		out[i] = "d" + strconv.Itoa(i) + ".acme.com"
	}
	return out
}()

func TestSSOProviderValidate(t *testing.T) {
	ok := []SSOProvider{
		{ID: "okta", Name: "Okta", Type: SSOTypeOIDC, Issuer: "https://acme.okta.com", Client: "c", AllowedDomains: acme},
		{ID: "google", Name: "Google", Type: SSOTypeGoogle, Client: "c", AllowedDomains: []string{"acme.com"}},
		{ID: "entra", Name: "Entra", Type: SSOTypeMicrosoft, Client: "c", Tenant: tenant, AllowedDomains: acme},
		{ID: "entra-2", Name: "Entra", Type: SSOTypeMicrosoft, Client: "c", Tenant: SSOTenantOrganizations, Tenants: []string{tenant}, AllowedDomains: acme},
	}
	for _, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", p.ID, err)
		}
	}
	bad := map[string]SSOProvider{
		"id":                  {ID: "Okta", Name: "Okta", Type: SSOTypeOIDC, Issuer: "https://acme.okta.com", Client: "c", AllowedDomains: acme},
		"name":                {ID: "okta", Type: SSOTypeOIDC, Issuer: "https://acme.okta.com", Client: "c"},
		"client":              {ID: "okta", Name: "Okta", Type: SSOTypeOIDC, Issuer: "https://acme.okta.com", AllowedDomains: acme},
		"http issuer":         {ID: "okta", Name: "Okta", Type: SSOTypeOIDC, Issuer: "http://acme.okta.com", Client: "c", AllowedDomains: acme},
		"no issuer":           {ID: "okta", Name: "Okta", Type: SSOTypeOIDC, Client: "c", AllowedDomains: acme},
		"preset issuer":       {ID: "g", Name: "G", Type: SSOTypeGoogle, Issuer: "https://accounts.google.com", Client: "c", AllowedDomains: []string{"acme.com"}},
		"google no domains":   {ID: "g", Name: "G", Type: SSOTypeGoogle, Client: "c"},
		"oidc no domains":     {ID: "o", Name: "O", Type: SSOTypeOIDC, Issuer: "https://idp.example", Client: "c"},
		"entra no domains":    {ID: "m", Name: "M", Type: SSOTypeMicrosoft, Client: "c", Tenant: tenant},
		"too many domains":    {ID: "o", Name: "O", Type: SSOTypeOIDC, Issuer: "https://idp.example", Client: "c", AllowedDomains: tooMany},
		"domain not normal":   {ID: "g", Name: "G", Type: SSOTypeGoogle, Client: "c", AllowedDomains: []string{"ACME.com"}},
		"public suffix":       {ID: "g", Name: "G", Type: SSOTypeGoogle, Client: "c", AllowedDomains: []string{"com"}},
		"common":              {ID: "m", Name: "M", Type: SSOTypeMicrosoft, Client: "c", Tenant: "common", AllowedDomains: acme},
		"consumers":           {ID: "m", Name: "M", Type: SSOTypeMicrosoft, Client: "c", Tenant: "consumers", AllowedDomains: acme},
		"organizations alone": {ID: "m", Name: "M", Type: SSOTypeMicrosoft, Client: "c", Tenant: SSOTenantOrganizations, AllowedDomains: acme},
		"tenant list on id":   {ID: "m", Name: "M", Type: SSOTypeMicrosoft, Client: "c", Tenant: tenant, Tenants: []string{tenant}},
		"bad tenant in list":  {ID: "m", Name: "M", Type: SSOTypeMicrosoft, Client: "c", Tenant: SSOTenantOrganizations, Tenants: []string{"x"}},
		"tenant on oidc":      {ID: "o", Name: "O", Type: SSOTypeOIDC, Issuer: "https://idp.example", Client: "c", Tenant: tenant, AllowedDomains: acme},
		"github":              {ID: "gh", Name: "GH", Type: "github", Client: "c", AllowedDomains: acme},
		"apple":               {ID: "a", Name: "A", Type: "apple", Client: "c", AllowedDomains: acme},
		"unknown":             {ID: "x", Name: "X", Type: "saml", Client: "c", AllowedDomains: acme},
	}
	for name, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSSOSettingsValidate(t *testing.T) {
	okta := SSOProvider{ID: "okta", Name: "Okta", Type: SSOTypeOIDC, Issuer: "https://acme.okta.com", Client: "c", AllowedDomains: acme}
	if err := (SSOSettings{Password: PasswordEnabled}).Validate(); err != nil {
		t.Fatalf("password only: %v", err)
	}
	if err := (SSOSettings{Password: PasswordDisabled, Providers: []SSOProvider{okta}}).Validate(); err != nil {
		t.Fatalf("sso only: %v", err)
	}
	if err := (SSOSettings{Password: PasswordBreakGlass, Providers: []SSOProvider{okta}}).Validate(); err != nil {
		t.Fatalf("break glass: %v", err)
	}
	for _, mode := range []PasswordMode{PasswordDisabled, PasswordBreakGlass} {
		if err := (SSOSettings{Password: mode}).Validate(); err == nil {
			t.Fatalf("%s without a provider accepted", mode)
		}
	}
	if err := (SSOSettings{Password: "maybe", Providers: []SSOProvider{okta}}).Validate(); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if err := (SSOSettings{Password: PasswordEnabled, Providers: []SSOProvider{okta, okta}}).Validate(); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	s := SSOSettings{Password: PasswordDisabled, Providers: []SSOProvider{okta}}
	if p, found := s.Provider("okta"); !found || p.Issuer != okta.Issuer {
		t.Fatal("provider lookup")
	}
	if _, found := s.Provider("other"); found {
		t.Fatal("unknown provider found")
	}
	o := s.Options()
	if o.Password || o.PasswordMode != PasswordDisabled || len(o.Providers) != 1 || o.Providers[0] != (SSOProviderView{ID: "okta", Name: "Okta", Type: SSOTypeOIDC}) {
		t.Fatalf("options: %+v", o)
	}
	// Break-glass keeps the password form for emergency access.
	if o := (SSOSettings{Password: PasswordBreakGlass, Providers: []SSOProvider{okta}}).Options(); !o.Password || o.PasswordMode != PasswordBreakGlass {
		t.Fatalf("break glass options: %+v", o)
	}
	if o := (SSOSettings{}).Options(); o.Providers == nil || !o.Password || o.PasswordMode != PasswordEnabled {
		t.Fatalf("zero options: %+v", o)
	}
}

func TestPasswordModePermits(t *testing.T) {
	for _, c := range []struct {
		mode             PasswordMode
		allowed, permits bool
	}{
		{PasswordEnabled, false, true}, {PasswordEnabled, true, true}, {"", false, true},
		{PasswordBreakGlass, false, false}, {PasswordBreakGlass, true, true},
		{PasswordDisabled, false, false}, {PasswordDisabled, true, false},
	} {
		if got := c.mode.Permits(c.allowed); got != c.permits {
			t.Errorf("%q allowed=%v: %v", c.mode, c.allowed, got)
		}
	}
}

func TestSSOAdmit(t *testing.T) {
	okta := SSOProvider{ID: "okta", Type: SSOTypeOIDC, AllowedDomains: acme}
	google := SSOProvider{ID: "google", Type: SSOTypeGoogle, AllowedDomains: []string{"acme.com"}}
	multi := SSOProvider{ID: "entra", Type: SSOTypeMicrosoft, Tenant: SSOTenantOrganizations, Tenants: []string{tenant}, AllowedDomains: acme}
	single := SSOProvider{ID: "entra", Type: SSOTypeMicrosoft, Tenant: tenant, AllowedDomains: acme}
	claims := func(email string, verified *bool, hd string) SSOClaims {
		return SSOClaims{Issuer: "https://idp.example", Subject: "s-1", Email: email, EmailVerified: verified, HostedDomain: hd}
	}
	cases := []struct {
		name   string
		p      SSOProvider
		c      SSOClaims
		linked bool
		email  string // "" means refused
	}{
		{"verified", okta, claims("Ann@Acme.com", ptr(true), ""), false, "ann@acme.com"},
		{"unverified", okta, claims("ann@acme.com", ptr(false), ""), false, ""},
		{"directory vouches for unknown", okta, claims("ann@acme.com", nil, ""), false, "ann@acme.com"},
		{"single tenant vouches", single, claims("ann@acme.com", nil, ""), false, "ann@acme.com"},
		{"multi tenant does not vouch", multi, claims("ann@acme.com", nil, ""), false, ""},
		{"google unknown", google, claims("ann@acme.com", nil, "acme.com"), false, ""},
		{"google workspace", google, claims("ann@acme.com", ptr(true), "acme.com"), false, "ann@acme.com"},
		{"google personal account", google, claims("ann@acme.com", ptr(true), ""), false, ""},
		{"google other workspace", google, claims("ann@acme.com", ptr(true), "evil.com"), false, ""},
		{"domain not allowed", google, claims("ann@evil.com", ptr(true), "acme.com"), false, ""},
		{"domain gate on linked", google, claims("ann@evil.com", ptr(true), "acme.com"), true, ""},
		{"hd gate on linked", google, claims("ann@acme.com", ptr(true), ""), true, ""},
		{"linked skips email rules", okta, claims("ann@acme.com", ptr(false), ""), true, "ann@acme.com"},
		{"no email unlinked", okta, claims("", ptr(true), ""), false, ""},
		{"no subject", okta, SSOClaims{Issuer: "https://idp.example", Email: "ann@acme.com", EmailVerified: ptr(true)}, false, ""},
		{"no issuer", okta, SSOClaims{Subject: "s", Email: "ann@acme.com", EmailVerified: ptr(true)}, true, ""},
		{"long subject", okta, SSOClaims{Issuer: "https://idp.example", Subject: strings.Repeat("s", 513), Email: "ann@acme.com"}, true, ""},
		// nOAuth: a tenant administrator sets an account's email to an
		// operator's address outside the allowed domains.
		{"unverified outside domains", single, claims("founder@gmail.com", nil, ""), false, ""},
		{"oidc outside domains", okta, claims("founder@gmail.com", ptr(true), ""), false, ""},
		{"linked without email", okta, claims("", nil, ""), true, ""},
	}
	for _, tc := range cases {
		email, err := tc.p.Admit(tc.c, tc.linked)
		if tc.email == "" {
			var e *errx.Error
			if err == nil || !errx.As(err, &e) || e.Code != CodeSSONotAuthorized {
				t.Errorf("%s: want refusal, got %q %v", tc.name, email, err)
			}
			continue
		}
		if err != nil || email != tc.email {
			t.Errorf("%s: want %q, got %q %v", tc.name, tc.email, email, err)
		}
	}
}

func TestSSOErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{ErrSSONotAuthorized("x"), CodeSSONotAuthorized, 401},
		{ErrSSOExpired(), CodeSSOExpired, 401},
		{ErrPasswordLoginDisabled(), CodePasswordLoginDisabled, 403},
		{ErrSSORequired(), CodeSSORequired, 403},
	} {
		var e *errx.Error
		if !errx.As(tc.err, &e) || e.Code != tc.code || e.HTTPStatus != tc.status {
			t.Errorf("%s: %+v", tc.code, e)
		}
	}
}
