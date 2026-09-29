package samlxml_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml/samltest"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type keyring struct{ signer signing.Signer }

func (k keyring) Signer(ctx context.Context, environment identity.EnvironmentID) (signing.Signer, error) {
	return k.signer, nil
}
func (k keyring) Verifier(ctx context.Context, key string) (signing.Verifier, error) {
	return signing.Verifier{}, nil
}
func (k keyring) JWKS(ctx context.Context) ([]signing.JWK, error) { return nil, nil }

func setup(t *testing.T) (samlxml.Protocol, identity.EnvironmentID, *samltest.SP, samlidp.ServiceProvider) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	protocol := samlxml.New(keyring{signing.Signer{ID: "kid-1", Private: key}}, "https://iam.example.com/")
	environment := identity.NewEnvironmentID()
	metadata, err := protocol.Metadata(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	sp := samltest.New("https://wiki.example.com/saml", "https://wiki.example.com/acs")
	if err := sp.Trust(metadata); err != nil {
		t.Fatal(err)
	}
	registered := samlidp.ServiceProvider{ID: identity.NewServiceProviderID(), EntityID: "https://wiki.example.com/saml", ACSURLs: []string{"https://wiki.example.com/acs"}, NameIDFormat: samlidp.NameIDEmail}
	return protocol, environment, sp, registered
}

func TestIdentityProvider(t *testing.T) {
	protocol, environment, _, _ := setup(t)
	idp, err := protocol.IdentityProvider(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	base := "https://iam.example.com/saml/" + environment.String()
	if idp.EntityID != base+"/metadata" || idp.SSOURL != base+"/sso" || !strings.HasPrefix(idp.Certificate, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("identity provider: %+v", idp)
	}
	again, _ := protocol.IdentityProvider(context.Background(), environment)
	if again.Certificate != idp.Certificate {
		t.Fatal("certificate not stable")
	}
}

func TestRoundTrip(t *testing.T) {
	protocol, environment, sp, registered := setup(t)
	ctx := context.Background()
	redirect, requestID, err := sp.Redirect("relay-1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	decoded, err := protocol.Decode(samlidp.Message{Redirect: true, SAMLRequest: u.Query().Get("SAMLRequest"), RelayState: u.Query().Get("RelayState")})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ID != requestID || decoded.Issuer != registered.EntityID || decoded.RelayState != "relay-1" || decoded.ACSURL != "https://wiki.example.com/acs" {
		t.Fatalf("decoded: %+v", decoded)
	}
	idp, _ := protocol.IdentityProvider(ctx, environment)
	request, err := decoded.Check(idp.SSOURL, decoded.IssueInstant, registered)
	if err != nil {
		t.Fatal(err)
	}
	session := identity.NewSessionID()
	registered.Attributes = map[string]string{"mail": samlidp.SourceEmail, "roles": samlidp.SourcePermissions}
	assertion := registered.Assert(samlidp.Login{User: identity.NewUserID(), Session: session, Permissions: []string{"wiki:read"}}, samlidp.Subject{Email: "ada@example.com"})
	response, err := protocol.Respond(ctx, environment, registered, request, assertion)
	if err != nil {
		t.Fatal(err)
	}
	if response.ACSURL != "https://wiki.example.com/acs" || response.RelayState != "relay-1" || response.Environment != environment {
		t.Fatalf("response: %+v", response)
	}
	result, err := sp.Verify(response.SAMLResponse, requestID)
	if err != nil {
		t.Fatalf("service provider refused the response: %v", err)
	}
	if result.NameID != "ada@example.com" || result.SessionIndex != session.String() || result.Attributes["roles"][0] != "wiki:read" || result.Attributes["mail"][0] != "ada@example.com" {
		t.Fatalf("result: %+v", result)
	}
	if _, err := sp.Verify(response.SAMLResponse, "another-request"); err == nil {
		t.Fatal("response accepted for another request")
	}
}

func TestPostBindingAndNoAttributes(t *testing.T) {
	protocol, environment, sp, registered := setup(t)
	ctx := context.Background()
	form, requestID, err := sp.Post()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.Decode(samlidp.Message{SAMLRequest: form})
	if err != nil || decoded.ID != requestID {
		t.Fatalf("decode post: %+v %v", decoded, err)
	}
	idp, _ := protocol.IdentityProvider(ctx, environment)
	request, err := decoded.Check(idp.SSOURL, decoded.IssueInstant, registered)
	if err != nil {
		t.Fatal(err)
	}
	registered.NameIDFormat = samlidp.NameIDPersistent
	user := identity.NewUserID()
	response, err := protocol.Respond(ctx, environment, registered, request, registered.Assert(samlidp.Login{User: user, Session: identity.NewSessionID()}, samlidp.Subject{Email: "ada@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := sp.Verify(response.SAMLResponse, requestID)
	if err != nil {
		t.Fatalf("service provider refused the response: %v", err)
	}
	if result.NameID != user.String() || !strings.HasSuffix(result.NameIDFormat, ":persistent") || len(result.Attributes) != 0 {
		t.Fatalf("result: %+v", result)
	}
}

func TestDecodeRejects(t *testing.T) {
	protocol, _, _, _ := setup(t)
	for name, message := range map[string]samlidp.Message{
		"empty":       {},
		"not base64":  {SAMLRequest: "%%%"},
		"not deflate": {Redirect: true, SAMLRequest: base64.StdEncoding.EncodeToString([]byte("plain"))},
		"not xml":     {SAMLRequest: base64.StdEncoding.EncodeToString([]byte("plain"))},
		"no issuer":   {SAMLRequest: base64.StdEncoding.EncodeToString([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0"/>`))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := protocol.Decode(message); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
