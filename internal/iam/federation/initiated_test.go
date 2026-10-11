package federation

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

const testIssuer = "https://iam.example.com"

func TestParseSAMLEntityID(t *testing.T) {
	env, conn := identity.NewEnvironmentID(), identity.NewConnectionID()
	entity := SAMLServiceProvider(testIssuer, env, conn).EntityID
	e, c, ok := ParseSAMLEntityID(testIssuer, entity)
	if !ok || e != env || c != conn {
		t.Fatalf("own entity ID: %v %v %v", e, c, ok)
	}
	for name, id := range map[string]string{
		"other issuer":   SAMLServiceProvider("https://other.example.com", env, conn).EntityID,
		"not metadata":   strings.TrimSuffix(entity, "/metadata") + "/acs",
		"extra segment":  strings.TrimSuffix(entity, "/metadata") + "/x/metadata",
		"bad connection": testIssuer + "/identity/v1/federation/saml/" + env.String() + "/nope/metadata",
		"bad env":        testIssuer + "/identity/v1/federation/saml/nope/" + conn.String() + "/metadata",
		"uppercase":      strings.ToUpper(entity),
		"empty":          "",
	} {
		if _, _, ok := ParseSAMLEntityID(testIssuer, id); ok {
			t.Errorf("%s: accepted %q", name, id)
		}
	}
}

func TestResponseConnection(t *testing.T) {
	env, conn := identity.NewEnvironmentID(), identity.NewConnectionID()
	entity := SAMLServiceProvider(testIssuer, env, conn).EntityID
	other := SAMLServiceProvider(testIssuer, env, identity.NewConnectionID()).EntityID
	e, c, err := ResponseConnection(testIssuer, ResponseHint{Audiences: []string{"https://unrelated", entity, entity}})
	if err != nil || e != env || c != conn {
		t.Fatalf("lookup: %v %v %v", e, c, err)
	}
	for name, audiences := range map[string][]string{
		"none":      nil,
		"foreign":   {"https://wiki.example.com/saml"},
		"two conns": {entity, other},
	} {
		if _, _, err := ResponseConnection(testIssuer, ResponseHint{Audiences: audiences}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRelayState(t *testing.T) {
	client := identity.NewClientID()
	for name, tc := range map[string]struct {
		raw      string
		client   identity.ClientID
		redirect string
	}{
		"empty":          {raw: ""},
		"client":         {raw: "client_id=" + client.String(), client: client},
		"leading ?":      {raw: "?client_id=" + client.String() + "&redirect_uri=https%3A%2F%2Fapp.example%2Fcb", client: client, redirect: "https://app.example/cb"},
		"redirect only":  {raw: "redirect_uri=https://app.example/cb", redirect: "https://app.example/cb"},
		"unknown params": {raw: "foo=bar&client_id=" + client.String() + "&organization_id=x", client: client},
		"bad client":     {raw: "client_id=nope&redirect_uri=https://a.example/", redirect: "https://a.example/"},
		"not a query":    {raw: "%zz"},
		"opaque relay":   {raw: "https://app.example/dashboard"},
		"too long":       {raw: "client_id=" + client.String() + "&x=" + strings.Repeat("a", MaxRelayState)},
	} {
		got := ParseRelayState(tc.raw)
		if got.Client != tc.client || got.Redirect != tc.redirect {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestLoginClientTarget(t *testing.T) {
	conn, org := identity.NewConnectionID(), identity.NewOrganizationID()
	c := LoginClient{ID: identity.NewClientID(), InitiateLoginURI: "https://app.example/login?tenant=acme&iss=spoof", Redirects: []string{"https://app.example/cb"}}
	to, err := c.Target(testIssuer, conn, org, RelayState{Redirect: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	q := u.Query()
	if u.Host != "app.example" || u.Path != "/login" || q.Get("tenant") != "acme" || q.Get("iss") != testIssuer || q.Get("connection_id") != conn.String() || q.Get("organization_id") != org.String() || q.Get("target_link_uri") != "https://app.example/cb" {
		t.Fatalf("target = %s", to)
	}
	// A redirect URI the client did not register is dropped.
	to, _ = c.Target(testIssuer, conn, org, RelayState{Redirect: "https://evil.example/cb"})
	if strings.Contains(to, "target_link_uri") || strings.Contains(to, "evil") {
		t.Fatalf("unregistered redirect leaked: %s", to)
	}
}

func TestIdPInitiatedOption(t *testing.T) {
	org, client := identity.NewOrganizationID(), identity.NewClientID()
	in := ConnectionInput{Organization: org, Name: "Okta", Provider: ProviderSAML, Options: Options{MetadataXML: "<x/>", IdPInitiatedClientID: " " + strings.ToUpper(client.String()) + " "}}
	if err := in.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	c := in.Connection(identity.NewEnvironmentID())
	if c.Options.IdPInitiatedClientID != client.String() {
		t.Fatalf("not normalized: %q", c.Options.IdPInitiatedClientID)
	}
	bad := in
	bad.Options.IdPInitiatedClientID = "not-a-client"
	if bad.Validate() == nil {
		t.Error("malformed client ID accepted")
	}
	// Only SAML connections take it.
	oidc := ConnectionInput{Organization: org, Name: "x", Issuer: "https://idp", Client: "c", ClientSecret: "s", Options: Options{IdPInitiatedClientID: client.String()}}
	if oidc.Validate() == nil {
		t.Error("idp_initiated_client_id on an OIDC connection accepted")
	}
}
