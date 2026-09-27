package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

const tenantA = "11111111-2222-3333-4444-555555555555"

func appleKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestPresetsDeriveIssuer(t *testing.T) {
	env := identity.NewEnvironmentID()
	for provider, want := range map[string]string{
		ProviderGoogle: "https://accounts.google.com",
		ProviderGitHub: "https://github.com",
	} {
		in := ConnectionInput{Name: "x", Provider: provider, Client: "c", ClientSecret: "s"}
		if err := in.Validate(); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if c := in.Connection(env); c.Issuer != want || c.Provider != provider {
			t.Fatalf("%s: got %+v", provider, c)
		}
	}
	in := ConnectionInput{Name: "x", Provider: ProviderMicrosoft, Options: Options{Tenant: "Common"}, Client: "c", ClientSecret: "s"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := in.Connection(env); c.Issuer != "https://login.microsoftonline.com/common/v2.0" || c.Options.Tenant != "common" {
		t.Fatalf("microsoft: %+v", c)
	}
	in = ConnectionInput{Name: "x", Provider: ProviderGoogle, Issuer: "https://evil.example", Client: "c", ClientSecret: "s"}
	if in.Validate() == nil {
		t.Fatal("a preset's issuer cannot be overridden")
	}
	if (ConnectionInput{Name: "x", Client: "c", ClientSecret: "s"}).Validate() == nil {
		t.Fatal("generic OIDC needs an issuer")
	}
	if (ConnectionInput{Name: "x", Provider: "facebook", Client: "c", ClientSecret: "s"}).Validate() == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestProviderOptions(t *testing.T) {
	bad := []ConnectionInput{
		{Provider: ProviderMicrosoft},
		{Provider: ProviderMicrosoft, Options: Options{Tenant: "contoso.com"}},
		{Provider: ProviderMicrosoft, Options: Options{Tenant: TenantConsumers, Tenants: []string{tenantA}}},
		{Provider: ProviderMicrosoft, Options: Options{Tenant: TenantCommon, Tenants: []string{"nope"}}},
		{Provider: ProviderGoogle, Options: Options{Tenant: TenantCommon}},
		{Provider: ProviderApple, Options: Options{Team: "short", Key: "ABCDEFGHIJ"}},
		{Provider: ProviderOIDC, Issuer: "https://idp.example", Options: Options{Team: "ABCDEFGHIJ"}},
	}
	for i, in := range bad {
		in.Name, in.Client, in.ClientSecret = "x", "c", "s"
		if in.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, in.Options)
		}
	}
	ok := ConnectionInput{Name: "x", Provider: ProviderMicrosoft, Options: Options{Tenant: TenantOrganizations, Tenants: []string{tenantA, tenantA}}, Client: "c", ClientSecret: "s"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := ok.Connection(identity.NewEnvironmentID()); len(c.Options.Tenants) != 1 {
		t.Fatalf("tenants not deduplicated: %v", c.Options.Tenants)
	}
}

func TestAppleConnection(t *testing.T) {
	in := ConnectionInput{Name: "Apple", Provider: ProviderApple, Options: Options{Team: "abcdefghij", Key: "KEY1234567"}, Client: "com.example.web", ClientSecret: appleKey(t)}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := in.Connection(identity.NewEnvironmentID()); c.Options.Team != "ABCDEFGHIJ" || c.Issuer != "https://appleid.apple.com" {
		t.Fatalf("apple: %+v", c)
	}
	if _, err := ParseAppleKey(strings.Join(strings.Fields(in.ClientSecret), " ")); err != nil {
		t.Fatalf("single-line key: %v", err)
	}
	in.ClientSecret = "not a key"
	if in.Validate() == nil {
		t.Fatal("Apple needs its .p8 key as the secret")
	}
	in.ClientSecret, in.SecretEnv = "", "IAMKIT_PROVIDER_APPLE"
	if in.Validate() == nil {
		t.Fatal("Apple keys are stored sealed, not in the environment")
	}
	rsa := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOTHnS2t6DZX/a8m7l0Qjc+bKDcmU4Tw4lLpMdgxdg9v\n-----END PRIVATE KEY-----\n"
	if _, err := ParseAppleKey(rsa); err == nil {
		t.Fatal("non-P-256 key accepted")
	}
}

func TestMicrosoftTenants(t *testing.T) {
	other := "99999999-2222-3333-4444-555555555555"
	cases := []struct {
		o      Options
		tenant string
		want   bool
	}{
		{Options{Tenant: TenantCommon}, tenantA, true},
		{Options{Tenant: TenantCommon}, ConsumerTenant, true},
		{Options{Tenant: TenantCommon}, "not-a-tenant", false},
		{Options{Tenant: TenantOrganizations}, ConsumerTenant, false},
		{Options{Tenant: TenantOrganizations, Tenants: []string{tenantA}}, tenantA, true},
		{Options{Tenant: TenantOrganizations, Tenants: []string{tenantA}}, other, false},
		{Options{Tenant: TenantConsumers}, ConsumerTenant, true},
		{Options{Tenant: TenantConsumers}, tenantA, false},
		{Options{Tenant: tenantA}, tenantA, true},
		{Options{Tenant: tenantA}, other, false},
	}
	for _, c := range cases {
		if got := c.o.AcceptsTenant(c.tenant); got != c.want {
			t.Errorf("%+v accepts %s = %v", c.o, c.tenant, got)
		}
	}
}

func TestSignupRules(t *testing.T) {
	org := identity.NewOrganizationID()
	base := func() ConnectionInput {
		return ConnectionInput{Name: "g", Provider: ProviderGoogle, Client: "c", ClientSecret: "s"}
	}
	env := identity.NewEnvironmentID()
	in := base()
	in.Signup = true
	if in.Connection(env).Validate() == nil {
		t.Fatal("signup without organization accepted")
	}
	in.SignupOrganization = org
	if err := in.Connection(env).Validate(); err != nil {
		t.Fatal(err)
	}
	in = base()
	in.SignupOrganization = org
	if in.Connection(env).Validate() == nil {
		t.Fatal("organization without signup accepted")
	}
	in = base()
	in.SignupGroup = identity.NewGroupID()
	if in.Connection(env).Validate() == nil {
		t.Fatal("group without signup accepted")
	}
	in = base()
	in.Organization, in.LinkEmail = org, true
	if in.Connection(env).Validate() == nil {
		t.Fatal("organization connections cannot link by email")
	}
}

func TestJoining(t *testing.T) {
	yes, no := true, false
	c := Connection{LinkEmail: true}
	if email, err := c.Joining(Claims{Subject: "s", Email: "Ann@Example.com", EmailVerified: &yes}); err != nil || email != "ann@example.com" {
		t.Fatalf("verified email: %q %v", email, err)
	}
	for _, claims := range []Claims{
		{Email: "ann@example.com"},
		{Email: "ann@example.com", EmailVerified: &no},
		{Email: "not-an-email", EmailVerified: &yes},
	} {
		if _, err := c.Joining(claims); err == nil {
			t.Fatalf("joined with %+v", claims)
		}
	}
	if _, err := (Connection{}).Joining(Claims{Email: "a@example.com", EmailVerified: &yes}); err == nil {
		t.Fatal("connection without signup or linking must not join")
	}
	if _, err := (Connection{Organization: identity.NewOrganizationID(), LinkEmail: true}).Joining(Claims{Email: "a@example.com", EmailVerified: &yes}); err == nil {
		t.Fatal("organization connections provision through JIT, not joining")
	}
}

func TestUpdateOptions(t *testing.T) {
	c := Connection{Provider: ProviderMicrosoft, Options: Options{Tenant: TenantCommon}, Enforcement: EnforcementOptional}
	o := Options{Tenant: TenantCommon, Tenants: []string{tenantA}}
	got, err := (ConnectionUpdate{Options: &o}).Apply(c)
	if err != nil || len(got.Options.Tenants) != 1 {
		t.Fatalf("tenant allow-list: %+v %v", got.Options, err)
	}
	o = Options{Tenant: TenantOrganizations}
	if _, err = (ConnectionUpdate{Options: &o}).Apply(c); err == nil {
		t.Fatal("tenant policy changed the issuer")
	}
	apple := Connection{Provider: ProviderApple, Options: Options{Team: "ABCDEFGHIJ", Key: "KEY1234567"}}
	o = Options{Team: "ABCDEFGHIJ", Key: "KEY7654321"}
	if _, err = (ConnectionUpdate{Options: &o}).Apply(apple); err == nil {
		t.Fatal("new key ID without its key accepted")
	}
	secret := appleKey(t)
	if got, err = (ConnectionUpdate{Options: &o, ClientSecret: &secret}).Apply(apple); err != nil || got.Options.Key != "KEY7654321" {
		t.Fatalf("key rotation: %+v %v", got.Options, err)
	}
}
