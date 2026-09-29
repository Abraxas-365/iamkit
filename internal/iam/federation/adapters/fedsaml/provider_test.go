package fedsaml_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := fedsaml.New(issuer, keyring{key}, nil)
	idp := samltest.New("https://idp.example.com")
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
