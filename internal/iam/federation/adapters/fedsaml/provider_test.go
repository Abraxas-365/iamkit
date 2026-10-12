package fedsaml_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/crewjam/saml"
)

type keyring struct{ key *rsa.PrivateKey }

func (k keyring) Signer(context.Context, identity.EnvironmentID) (signing.Signer, error) {
	return signing.Signer{ID: "kid-1", Private: k.key}, nil
}
func (k keyring) Verifier(context.Context, string) (signing.Verifier, error) {
	return signing.Verifier{}, nil
}
func (k keyring) JWKS(context.Context) ([]signing.JWK, error) { return nil, nil }

const issuer = "https://iam.example.com"

func setup(t *testing.T, options federation.Options) (fedsaml.Provider, *samltest.IdP, federation.Connection) {
	t.Helper()
	return setupSLO(t, options, "")
}

// setupSLO is setup with an identity provider publishing the
// SingleLogoutService bindings ("redirect", "post", "both" or "").
func setupSLO(t *testing.T, options federation.Options, slo string) (fedsaml.Provider, *samltest.IdP, federation.Connection) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := fedsaml.New(issuer, keyring{key}, nil)
	idp := samltest.New("https://idp.example.com")
	idp.SLO = slo
	options.MetadataXML = idp.Metadata()
	c := federation.Connection{ID: identity.NewConnectionID(), Environment: identity.NewEnvironmentID(), Organization: identity.NewOrganizationID(), Provider: federation.ProviderSAML, Options: options.Normalized()}
	if c, err = p.Prepare(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if c.Issuer != idp.EntityID() || c.Client != federation.SAMLServiceProvider(issuer, c.Environment, c.ID).EntityID {
		t.Fatalf("prepare: %q %q", c.Issuer, c.Client)
	}
	metadata, err := p.Metadata(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if err = idp.Trust(metadata); err != nil {
		t.Fatal(err)
	}
	return p, idp, c
}

func login(t *testing.T, p fedsaml.Provider, idp *samltest.IdP, c federation.Connection, nonce string, user samltest.User) samltest.Form {
	t.Helper()
	address, err := p.Authorize(context.Background(), c, "ik_state_abc", nonce, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(address)
	if u.Host != "idp.example.com" || u.Query().Get("RelayState") != "ik_state_abc" {
		t.Fatalf("redirect %s", address)
	}
	form, err := idp.Answer(address, user)
	if err != nil {
		t.Fatal(err)
	}
	if form.URL != issuer+"/identity/v1/federation/saml/acs" || form.RequestID != fedsaml.RequestID(nonce) {
		t.Fatalf("form %+v", form)
	}
	return form
}

func TestLogin(t *testing.T) {
	p, idp, c := setup(t, federation.Options{})
	form := login(t, p, idp, c, "nonce-1", samltest.User{NameID: "u-42", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "ada@example.com", Name: "Ada Lovelace"})
	claims, err := p.Verify(context.Background(), c, form.SAMLResponse, "nonce-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "u-42" || claims.Email != "ada@example.com" || claims.Name != "Ada Lovelace" || claims.Issuer != idp.EntityID() || claims.Assertion == "" || claims.AssertionExpires.Before(time.Now()) {
		t.Fatalf("claims %+v", claims)
	}
	// Another login's nonce: InResponseTo does not match.
	if _, err = p.Verify(context.Background(), c, form.SAMLResponse, "nonce-2", ""); err == nil {
		t.Fatal("response accepted for another request")
	}
}

func TestEncryptedAndSigned(t *testing.T) {
	p, idp, c := setup(t, federation.Options{SignRequests: true, NameIDFormat: "persistent"})
	idp.Encrypt = true
	metadata, _ := p.Metadata(context.Background(), c)
	if !strings.Contains(string(metadata), `AuthnRequestsSigned="true"`) || !strings.Contains(string(metadata), `use="encryption"`) {
		t.Fatalf("metadata %s", metadata)
	}
	if err := idp.Trust(metadata); err != nil {
		t.Fatal(err)
	}
	address, err := p.Authorize(context.Background(), c, "ik_state_abc", "n", "")
	if err != nil || !strings.Contains(address, "Signature=") || !strings.Contains(address, "SigAlg=") {
		t.Fatalf("signed redirect %s %v", address, err)
	}
	form, err := idp.Answer(address, samltest.User{NameID: "u-1", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "e@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(form.SAMLResponse)
	if !strings.Contains(string(raw), "EncryptedAssertion") {
		t.Fatal("assertion not encrypted")
	}
	claims, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", "")
	if err != nil || claims.Subject != "u-1" {
		t.Fatalf("encrypted: %+v %v", claims, err)
	}
}

func TestRefusals(t *testing.T) {
	p, idp, c := setup(t, federation.Options{})
	user := samltest.User{NameID: "u-1", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "e@example.com"}

	t.Run("forged signature", func(t *testing.T) {
		// Same entity ID, another key: the signature does not verify.
		other := samltest.New("https://idp.example.com")
		metadata, _ := p.Metadata(context.Background(), c)
		_ = other.Trust(metadata)
		address, _ := p.Authorize(context.Background(), c, "ik_state_abc", "n", "")
		form, err := other.Answer(address, user)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Verify(context.Background(), c, form.SAMLResponse, "n", ""); err == nil {
			t.Fatal("forged response accepted")
		}
	})
	t.Run("tampered", func(t *testing.T) {
		form := login(t, p, idp, c, "n", user)
		raw, _ := base64.StdEncoding.DecodeString(form.SAMLResponse)
		tampered := strings.Replace(string(raw), "u-1", "u-2", -1)
		if _, err := p.Verify(context.Background(), c, base64.StdEncoding.EncodeToString([]byte(tampered)), "n", ""); err == nil {
			t.Fatal("tampered response accepted")
		}
	})
	t.Run("audience", func(t *testing.T) {
		form := login(t, p, idp, c, "n", samltest.User{NameID: "u-1", NameIDFormat: string(saml.PersistentNameIDFormat), Edit: func(a *saml.Assertion) {
			a.Conditions.AudienceRestrictions = []saml.AudienceRestriction{{Audience: saml.Audience{Value: "https://other.example.com"}}}
		}})
		if _, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", ""); err == nil {
			t.Fatal("foreign audience accepted")
		}
	})
	t.Run("expired", func(t *testing.T) {
		form := login(t, p, idp, c, "n", samltest.User{NameID: "u-1", NameIDFormat: string(saml.PersistentNameIDFormat), Edit: func(a *saml.Assertion) {
			a.Conditions.NotOnOrAfter = time.Now().Add(-time.Hour)
		}})
		if _, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", ""); err == nil {
			t.Fatal("expired assertion accepted")
		}
	})
	t.Run("transient subject", func(t *testing.T) {
		form := login(t, p, idp, c, "n", samltest.User{NameID: "tmp", NameIDFormat: string(saml.TransientNameIDFormat)})
		if _, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", ""); err == nil {
			t.Fatal("transient NameID used as subject")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		for _, response := range []string{"%%%", base64.StdEncoding.EncodeToString([]byte("<x/>")), base64.StdEncoding.EncodeToString([]byte("not xml"))} {
			if _, err := p.Verify(context.Background(), c, response, "n", ""); err == nil {
				t.Fatalf("accepted %q", response)
			}
		}
	})
}

func TestAttributeMapping(t *testing.T) {
	p, idp, c := setup(t, federation.Options{NameIDFormat: "transient", Attributes: &federation.AttributeMapping{Subject: "employeeID", Email: "corpMail", Name: "fullName"}})
	form := login(t, p, idp, c, "n", samltest.User{NameID: "tmp", NameIDFormat: string(saml.TransientNameIDFormat), Email: "ignored@example.com",
		Attributes: map[string]string{"employeeID": "E-7", "corpMail": "grace@corp.example", "fullName": "Grace Hopper"}})
	claims, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", "")
	if err != nil || claims.Subject != "E-7" || claims.Email != "grace@corp.example" || claims.Name != "Grace Hopper" {
		t.Fatalf("mapped claims %+v %v", claims, err)
	}
}

func TestMetadataValidation(t *testing.T) {
	for name, xml := range map[string]string{
		"not xml":  "hello",
		"sp only":  `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><SPSSODescriptor/></EntityDescriptor>`,
		"no certs": `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/></IDPSSODescriptor></EntityDescriptor>`,
	} {
		if _, err := fedsaml.ParseMetadata([]byte(xml)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	idp := samltest.New("https://idp.example.com")
	wrapped := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + strings.TrimPrefix(idp.Metadata(), "") + `</EntitiesDescriptor>`
	if e, err := fedsaml.ParseMetadata([]byte(wrapped)); err != nil || e.EntityID != idp.EntityID() {
		t.Fatalf("entities descriptor: %v", err)
	}
}

func TestCertificateStableAcrossReplicas(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := samltest.New("https://idp.example.com")
	c := federation.Connection{ID: identity.NewConnectionID(), Environment: identity.NewEnvironmentID(), Provider: federation.ProviderSAML, Issuer: idp.EntityID(), Options: federation.Options{MetadataXML: idp.Metadata()}}
	cert := func() string {
		out, err := fedsaml.New(issuer, keyring{key}, nil).Metadata(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		_, rest, _ := strings.Cut(string(out), "X509Certificate>")
		value, _, _ := strings.Cut(rest, "<")
		return value
	}
	if a, b := cert(), cert(); a == "" || a != b {
		t.Fatal("certificate differs between replicas")
	}
}

func groupsOf(t *testing.T, options federation.Options, user samltest.User) []string {
	t.Helper()
	p, idp, c := setup(t, options)
	user.NameID, user.NameIDFormat, user.Email = "u-1", string(saml.PersistentNameIDFormat), "e@example.com"
	form := login(t, p, idp, c, "n", user)
	claims, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", "")
	if err != nil {
		t.Fatal(err)
	}
	return claims.Groups
}

func TestGroups(t *testing.T) {
	// Default attribute names; every value of a multi-valued attribute.
	got := groupsOf(t, federation.Options{}, samltest.User{MultiAttributes: map[string][]string{"groups": {"eng", " ops ", "eng", ""}}})
	if !slices.Equal(got, []string{"eng", "ops"}) {
		t.Fatalf("groups: %q", got)
	}
	got = groupsOf(t, federation.Options{}, samltest.User{MultiAttributes: map[string][]string{"memberOf": {"cn=a", "cn=b"}}})
	if !slices.Equal(got, []string{"cn=a", "cn=b"}) {
		t.Fatalf("memberOf: %q", got)
	}
	ms := "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
	got = groupsOf(t, federation.Options{}, samltest.User{MultiAttributes: map[string][]string{ms: {"guid-1", "guid-2"}}})
	if !slices.Equal(got, []string{"guid-1", "guid-2"}) {
		t.Fatalf("microsoft claim: %q", got)
	}
	// A configured attribute replaces the defaults.
	user := samltest.User{MultiAttributes: map[string][]string{"roles": {"x", "y"}, "groups": {"ignored"}}}
	got = groupsOf(t, federation.Options{Attributes: &federation.AttributeMapping{Groups: "roles"}}, user)
	if !slices.Equal(got, []string{"x", "y"}) {
		t.Fatalf("configured: %q", got)
	}
	if got = groupsOf(t, federation.Options{}, samltest.User{Attributes: map[string]string{"other": "v"}}); len(got) != 0 {
		t.Fatalf("no groups attribute: %q", got)
	}
}

func unsolicited(t *testing.T, idp *samltest.IdP, c federation.Connection, user samltest.User) samltest.Form {
	t.Helper()
	sp := federation.SAMLServiceProvider(issuer, c.Environment, c.ID)
	form, err := idp.Unsolicited(sp.EntityID, "", user)
	if err != nil {
		t.Fatal(err)
	}
	return form
}

func TestVerifyUnsolicited(t *testing.T) {
	p, idp, c := setup(t, federation.Options{})
	ctx := context.Background()
	user := samltest.User{NameID: "u-1", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "e@example.com"}

	claims, err := p.VerifyUnsolicited(ctx, c, unsolicited(t, idp, c, user).SAMLResponse)
	if err != nil || claims.Assertion == "" || claims.Issuer != idp.EntityID() {
		t.Fatalf("valid: %+v %v", claims, err)
	}

	refused := map[string]func(*saml.Assertion){
		"no audience restriction": func(a *saml.Assertion) { a.Conditions.AudienceRestrictions = nil },
		"empty audience":          func(a *saml.Assertion) { a.Conditions.AudienceRestrictions = []saml.AudienceRestriction{{}} },
		"foreign audience": func(a *saml.Assertion) {
			a.Conditions.AudienceRestrictions = []saml.AudienceRestriction{{Audience: saml.Audience{Value: "https://other.example.com"}}}
		},
		"solicited assertion re-wrapped": func(a *saml.Assertion) {
			for _, sc := range a.Subject.SubjectConfirmations {
				sc.SubjectConfirmationData.InResponseTo = "id-of-one-of-our-requests"
			}
		},
	}
	for name, edit := range refused {
		t.Run(name, func(t *testing.T) {
			u := user
			u.Edit = edit
			if _, err := p.VerifyUnsolicited(ctx, c, unsolicited(t, idp, c, u).SAMLResponse); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	t.Run("two assertions", func(t *testing.T) {
		raw, _ := base64.StdEncoding.DecodeString(unsolicited(t, idp, c, user).SAMLResponse)
		xml := string(raw)
		start := strings.Index(xml, "<saml:Assertion")
		end := strings.Index(xml, "</saml:Assertion>") + len("</saml:Assertion>")
		if start < 0 || end < start {
			t.Fatalf("no assertion in %s", xml)
		}
		doubled := xml[:end] + xml[start:end] + xml[end:]
		if n := fedsaml.CountAssertions([]byte(doubled)); n != 2 {
			t.Fatalf("count = %d", n)
		}
		if n := fedsaml.CountAssertions(raw); n != 1 {
			t.Fatalf("count of the original = %d", n)
		}
		if _, err := p.VerifyUnsolicited(ctx, c, base64.StdEncoding.EncodeToString([]byte(doubled))); err == nil {
			t.Fatal("two assertions accepted")
		}
	})

	t.Run("solicited response", func(t *testing.T) {
		if _, err := p.VerifyUnsolicited(ctx, c, login(t, p, idp, c, "n", user).SAMLResponse); err == nil {
			t.Fatal("a response to a request was accepted as unsolicited")
		}
	})
}
