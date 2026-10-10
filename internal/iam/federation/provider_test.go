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

func TestPromptOption(t *testing.T) {
	cases := []struct {
		provider string
		o        Options
		ok       bool
	}{
		{ProviderMicrosoft, Options{Tenant: TenantCommon, Prompt: " select_account "}, true},
		{ProviderMicrosoft, Options{Tenant: tenantA, Prompt: PromptLogin}, true},
		{ProviderGoogle, Options{Prompt: PromptSelectAccount}, true},
		{ProviderOIDC, Options{Prompt: PromptSelectAccount}, true},
		{ProviderMicrosoft, Options{Tenant: tenantA, Prompt: "none"}, false},
		{ProviderMicrosoft, Options{Tenant: tenantA, Prompt: "consent"}, false},
		{ProviderGitHub, Options{Prompt: PromptSelectAccount}, false},
		{ProviderApple, Options{Team: "ABCDEFGHIJ", Key: "ABCDEFGHIJ", Prompt: PromptSelectAccount}, false},
	}
	for _, c := range cases {
		if err := validOptions(c.provider, c.o.Normalized()); (err == nil) != c.ok {
			t.Errorf("%s %+v: %v", c.provider, c.o, err)
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
	if err := in.Connection(env).Validate(); err != nil {
		t.Fatalf("organization connections link by email to members: %v", err)
	}
	in.Signup, in.SignupOrganization = true, org
	if in.Connection(env).Validate() == nil {
		t.Fatal("organization connections cannot sign up")
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

func TestGoogleDomains(t *testing.T) {
	in := ConnectionInput{Name: "x", Provider: ProviderGoogle, Options: Options{Domains: []string{" Acme.com. ", "acme.com", "BÜCHER.example"}}, Client: "c", ClientSecret: "s"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	o := in.Connection(identity.NewEnvironmentID()).Options
	if strings.Join(o.Domains, ",") != "acme.com,xn--bcher-kva.example" {
		t.Fatalf("domains not normalized: %v", o.Domains)
	}
	cases := []struct {
		hd   string
		want bool
	}{{"acme.com", true}, {"ACME.com", true}, {"other.com", false}, {"", false}}
	for _, c := range cases {
		if got := o.AcceptsHostedDomain(c.hd); got != c.want {
			t.Errorf("accepts %q = %v", c.hd, got)
		}
	}
	if !(Options{}).AcceptsHostedDomain("") {
		t.Fatal("without domains every Google account is accepted")
	}
	for _, bad := range []Options{{Domains: []string{"com"}}, {Domains: []string{"*.acme.com"}}, {Domains: []string{"not a domain"}}} {
		in.Options = bad
		if in.Validate() == nil {
			t.Errorf("accepted %v", bad.Domains)
		}
	}
	in.Provider, in.Options = ProviderMicrosoft, Options{Tenant: TenantCommon, Domains: []string{"acme.com"}}
	if in.Validate() == nil {
		t.Fatal("domains only apply to Google")
	}
	c := Connection{Provider: ProviderGoogle, Enforcement: EnforcementOptional}
	update := Options{Domains: []string{"acme.com"}}
	if got, err := (ConnectionUpdate{Options: &update}).Apply(c); err != nil || len(got.Options.Domains) != 1 || got.Validate() != nil {
		t.Fatalf("update domains: %+v %v", got.Options, err)
	}
}

func TestUpdateOptions(t *testing.T) {
	c := Connection{Provider: ProviderMicrosoft, Options: Options{Tenant: TenantCommon}, Enforcement: EnforcementOptional}
	o := Options{Tenant: TenantCommon, Tenants: []string{tenantA}}
	got, err := (ConnectionUpdate{Options: &o}).Apply(c)
	if err != nil || len(got.Options.Tenants) != 1 {
		t.Fatalf("tenant allow-list: %+v %v", got.Options, err)
	}
	o = Options{Tenant: TenantCommon, Prompt: PromptSelectAccount}
	if got, err = (ConnectionUpdate{Options: &o}).Apply(c); err != nil || got.Options.Prompt != PromptSelectAccount || got.Validate() != nil {
		t.Fatalf("account choice: %+v %v", got.Options, err)
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

func TestMoreProviders(t *testing.T) {
	env := identity.NewEnvironmentID()
	mapping := &ClaimMapping{Subject: "id", Email: "email", EmailVerified: "email_verified", Name: "name"}
	oauth := Options{AuthorizeURL: "https://auth.example.com/oauth/authorize", TokenURL: "https://auth.example.com/oauth/token", UserinfoURL: "https://api.example.com/me", Claims: mapping}
	for name, in := range map[string]ConnectionInput{
		"gitlab.com":        {Provider: ProviderGitLab},
		"self-managed":      {Provider: ProviderGitLab, Options: Options{BaseURL: "https://git.example.com/"}},
		"github enterprise": {Provider: ProviderGitHubEnterprise, Options: Options{BaseURL: "https://ghe.example.com"}},
		"oauth2":            {Provider: ProviderOAuth2, Options: oauth},
	} {
		in.Name, in.Client, in.ClientSecret = "x", "c", "s"
		if err := in.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := in.Connection(env).Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if c := (ConnectionInput{Provider: ProviderGitLab, Options: Options{BaseURL: "https://git.example.com/"}}).Connection(env); c.Issuer != "https://git.example.com" {
		t.Fatalf("self-managed issuer = %q", c.Issuer)
	}
	if c := (ConnectionInput{Provider: ProviderOAuth2, Options: oauth}).Connection(env); c.Issuer != "https://auth.example.com" {
		t.Fatalf("oauth2 issuer = %q", c.Issuer)
	}
	bad := map[string]ConnectionInput{
		"enterprise without base":  {Provider: ProviderGitHubEnterprise},
		"enterprise on github.com": {Provider: ProviderGitHubEnterprise, Options: Options{BaseURL: "https://github.com"}},
		"http gitlab":              {Provider: ProviderGitLab, Options: Options{BaseURL: "http://git.example.com"}},
		"base url on google":       {Provider: ProviderGoogle, Options: Options{BaseURL: "https://x.example.com"}},
		"oauth2 without mapping":   {Provider: ProviderOAuth2, Options: Options{AuthorizeURL: oauth.AuthorizeURL, TokenURL: oauth.TokenURL, UserinfoURL: oauth.UserinfoURL}},
		"oauth2 http endpoint":     {Provider: ProviderOAuth2, Options: Options{AuthorizeURL: oauth.AuthorizeURL, TokenURL: "http://auth.example.com/token", UserinfoURL: oauth.UserinfoURL, Claims: mapping}},
		"oauth2 bad path":          {Provider: ProviderOAuth2, Options: Options{AuthorizeURL: oauth.AuthorizeURL, TokenURL: oauth.TokenURL, UserinfoURL: oauth.UserinfoURL, Claims: &ClaimMapping{Subject: "a b"}}},
		"verified without email":   {Provider: ProviderOAuth2, Options: Options{AuthorizeURL: oauth.AuthorizeURL, TokenURL: oauth.TokenURL, UserinfoURL: oauth.UserinfoURL, Claims: &ClaimMapping{Subject: "id", EmailVerified: "v"}}},
		"endpoints on oidc":        {Provider: ProviderOIDC, Issuer: "https://idp.example.com", Options: Options{TokenURL: oauth.TokenURL}},
		"issuer with preset":       {Provider: ProviderOAuth2, Issuer: "https://other.example.com", Options: oauth},
		"scope with space":         {Provider: ProviderOAuth2, Options: Options{AuthorizeURL: oauth.AuthorizeURL, TokenURL: oauth.TokenURL, UserinfoURL: oauth.UserinfoURL, Claims: mapping, Scopes: []string{"a b"}}},
	}
	for name, in := range bad {
		in.Name, in.Client, in.ClientSecret = "x", "c", "s"
		if in.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Endpoints may move within the host; base URLs and hosts may not.
	c := ConnectionInput{Provider: ProviderOAuth2, Options: oauth}.Connection(env)
	moved := oauth
	moved.TokenURL = "https://auth.example.com/v2/token"
	if got, err := (ConnectionUpdate{Options: &moved}).Apply(c); err != nil || got.Options.TokenURL != moved.TokenURL {
		t.Fatalf("endpoint change: %+v %v", got.Options, err)
	}
	moved.AuthorizeURL = "https://evil.example.com/authorize"
	if _, err := (ConnectionUpdate{Options: &moved}).Apply(c); err == nil {
		t.Fatal("authorization host changed")
	}
	g := ConnectionInput{Provider: ProviderGitLab, Options: Options{BaseURL: "https://git.example.com"}}.Connection(env)
	if _, err := (ConnectionUpdate{Options: &Options{BaseURL: "https://other.example.com"}}).Apply(g); err == nil {
		t.Fatal("base URL changed")
	}
}

func TestLinkingOptions(t *testing.T) {
	yes, no := true, false
	org := Connection{Organization: identity.NewOrganizationID(), LinkEmail: true}
	if email, err := org.Admit(Claims{Email: "Ann@Example.com"}); err != nil || email != "ann@example.com" {
		t.Fatalf("link by email without JIT: %q %v", email, err)
	}
	if _, err := org.Admit(Claims{Email: "ann@example.com", EmailVerified: &no}); err == nil {
		t.Fatal("unverified email linked")
	}
	// Profile refreshes: environment connections need an explicitly
	// verified email; organization connections accept an unreported one.
	social := Connection{}
	if p := social.Profile(Claims{Subject: "s", Name: " Ann ", Email: "ann@example.com"}); p.Email != "" || p.Name != "Ann" || p.Subject != "s" {
		t.Fatalf("social unverified: %+v", p)
	}
	if p := social.Profile(Claims{Email: "Ann@Example.com", EmailVerified: &yes}); p.Email != "ann@example.com" {
		t.Fatalf("social verified: %+v", p)
	}
	if p := org.Profile(Claims{Email: "ann@example.com"}); p.Email != "ann@example.com" || p.Organization != org.Organization {
		t.Fatalf("organization: %+v", p)
	}
	if p := org.Profile(Claims{Email: "ann@example.com", EmailVerified: &no}); p.Email != "" {
		t.Fatalf("organization unverified: %+v", p)
	}
	if p := social.Profile(Claims{Picture: " https://cdn.example/ann.png "}); p.AvatarURL != "https://cdn.example/ann.png" {
		t.Fatalf("picture: %+v", p)
	}
	if p := social.Profile(Claims{Picture: "http://cdn.example/ann.png"}); p.AvatarURL != "" {
		t.Fatalf("a non-https picture is dropped: %+v", p)
	}
	on := true
	if got, err := (ConnectionUpdate{UpdateProfile: &on}).Apply(Connection{}); err != nil || !got.UpdateProfile {
		t.Fatalf("update_profile: %+v %v", got, err)
	}
}

func TestSAMLConnection(t *testing.T) {
	org := identity.NewOrganizationID()
	base := ConnectionInput{Organization: org, Name: "Okta", Provider: ProviderSAML, Options: Options{MetadataURL: "https://idp.example.com/metadata"}}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	c := base.Connection(identity.NewEnvironmentID())
	if !c.JIT || c.Enforcement != EnforcementOptional || c.Options.NameIDFormat != "" {
		t.Fatalf("defaults: %+v", c)
	}
	for name, in := range map[string]ConnectionInput{
		"no organization":   {Name: "x", Provider: ProviderSAML, Options: Options{MetadataXML: "<x/>"}},
		"no metadata":       {Organization: org, Name: "x", Provider: ProviderSAML},
		"http metadata":     {Organization: org, Name: "x", Provider: ProviderSAML, Options: Options{MetadataURL: "http://idp/metadata"}},
		"client secret":     {Organization: org, Name: "x", Provider: ProviderSAML, ClientSecret: "s", Options: Options{MetadataXML: "<x/>"}},
		"issuer":            {Organization: org, Name: "x", Provider: ProviderSAML, Issuer: "https://idp", Options: Options{MetadataXML: "<x/>"}},
		"bad format":        {Organization: org, Name: "x", Provider: ProviderSAML, Options: Options{MetadataXML: "<x/>", NameIDFormat: "kerberos"}},
		"transient alone":   {Organization: org, Name: "x", Provider: ProviderSAML, Options: Options{MetadataXML: "<x/>", NameIDFormat: "transient"}},
		"huge metadata":     {Organization: org, Name: "x", Provider: ProviderSAML, Options: Options{MetadataXML: strings.Repeat("a", MaxMetadata+1)}},
		"saml options oidc": {Organization: org, Name: "x", Issuer: "https://idp", Client: "c", ClientSecret: "s", Options: Options{MetadataURL: "https://idp/metadata"}},
	} {
		if err := in.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	transient := ConnectionInput{Organization: org, Name: "x", Provider: ProviderSAML, Options: Options{MetadataXML: "<x/>", NameIDFormat: " Transient ", Attributes: &AttributeMapping{Subject: " uid "}}}
	if err := transient.Validate(); err != nil {
		t.Fatalf("transient with subject attribute: %v", err)
	}
	if o := transient.Options.Normalized(); o.NameIDFormat != NameIDTransient || o.Attributes.Subject != "uid" {
		t.Fatalf("normalized: %+v", o)
	}
	// Assembled: an environment SAML connection is refused.
	if err := (Connection{Provider: ProviderSAML, Enforcement: EnforcementOptional, Options: Options{MetadataXML: "<x/>"}}).Validate(); err == nil {
		t.Fatal("environment SAML connection accepted")
	}
	secret := "s"
	if _, err := (ConnectionUpdate{ClientSecret: &secret}).Apply(c); err == nil {
		t.Fatal("client_secret on SAML")
	}
	sp := SAMLServiceProvider("https://iam.example.com", c.Environment, c.ID)
	if sp.EntityID != sp.Metadata || !strings.HasSuffix(sp.Metadata, "/metadata") || sp.ACS != "https://iam.example.com/identity/v1/federation/saml/acs" {
		t.Fatalf("service provider: %+v", sp)
	}
}

func TestLDAPConnection(t *testing.T) {
	org := identity.NewOrganizationID()
	base := ConnectionInput{Organization: org, Name: "AD", Provider: ProviderLDAP, ClientSecret: "svc", Options: Options{URL: " LDAPS://DC1.Corp.Example/ ", BindDN: "cn=svc,dc=corp", UserBaseDN: "OU=People,DC=corp"}}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	c := base.Connection(identity.NewEnvironmentID())
	c.Sealed = "sealed"
	if c.Issuer != "ldaps://dc1.corp.example:636" || c.Client != "ou=people,dc=corp" || !c.JIT {
		t.Fatalf("assembled: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("assembled valid: %v", err)
	}
	if LDAPServer("ldap://h") != "ldap://h:389" || LDAPServer("https://h") != "" {
		t.Fatal("LDAPServer defaults")
	}
	anonymous := ConnectionInput{Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldap://h", StartTLS: true, UserBaseDN: "dc=h", UserFilter: "(uid={username})"}}
	if err := anonymous.Validate(); err != nil {
		t.Fatalf("anonymous StartTLS: %v", err)
	}
	for name, in := range map[string]ConnectionInput{
		"no organization":     {Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h"}},
		"plaintext":           {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldap://h", UserBaseDN: "dc=h"}},
		"starttls on ldaps":   {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h", StartTLS: true, UserBaseDN: "dc=h"}},
		"https url":           {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "https://h", UserBaseDN: "dc=h"}},
		"url with dn":         {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h/dc=h", UserBaseDN: "dc=h"}},
		"no base":             {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h"}},
		"bind without secret": {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h", BindDN: "cn=svc"}},
		"secret without bind": {Organization: org, Name: "x", Provider: ProviderLDAP, ClientSecret: "s", Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h"}},
		"filter placeholder":  {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h", UserFilter: "(uid=jane)"}},
		"filter parens":       {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h", UserFilter: "uid={username}"}},
		"bad ca":              {Organization: org, Name: "x", Provider: ProviderLDAP, Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h", CAPEM: "nope"}},
		"issuer":              {Organization: org, Name: "x", Provider: ProviderLDAP, Issuer: "ldaps://h", Options: Options{URL: "ldaps://h", UserBaseDN: "dc=h"}},
		"ldap options oidc":   {Organization: org, Name: "x", Issuer: "https://idp", Client: "c", ClientSecret: "s", Options: Options{URL: "ldaps://h"}},
	} {
		if err := in.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	moved := Options{URL: "ldaps://dc2.corp.example", BindDN: "cn=svc,dc=corp", UserBaseDN: "ou=people,dc=corp"}
	if _, err := (ConnectionUpdate{Options: &moved}).Apply(c); err == nil {
		t.Fatal("changing the directory host accepted")
	}
	same := Options{URL: "ldaps://dc1.corp.example:636", BindDN: "cn=svc,dc=corp", UserBaseDN: "ou=people,dc=corp", UserFilter: "(sAMAccountName={username})"}
	if got, err := (ConnectionUpdate{Options: &same}).Apply(c); err != nil || got.Options.UserFilter == "" {
		t.Fatalf("changing the filter: %+v %v", got, err)
	}
	unbound := Options{URL: "ldaps://dc1.corp.example", UserBaseDN: "ou=people,dc=corp"}
	secret := "s"
	if _, err := (ConnectionUpdate{Options: &unbound, ClientSecret: &secret}).Apply(c); err == nil {
		t.Fatal("secret on an anonymous connection accepted")
	}
}
