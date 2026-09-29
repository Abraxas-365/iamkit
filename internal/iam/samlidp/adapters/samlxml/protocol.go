// Package samlxml reads AuthnRequests and writes signed SAML responses and
// IdP metadata with github.com/crewjam/saml. The environment's signing key
// signs (RSA-SHA256), with the certificate derived from it
// (signing.Signer.Certificate).
package samlxml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// maxRequest bounds an AuthnRequest, encoded and inflated.
const maxRequest = 64 << 10

// Protocol implements samlidp.Protocol.
type Protocol struct {
	keys   signing.Keyring
	issuer string
	certs  *sync.Map
}

var _ samlidp.Protocol = Protocol{}

func New(keys signing.Keyring, issuer string) Protocol {
	return Protocol{keys: keys, issuer: strings.TrimRight(issuer, "/"), certs: &sync.Map{}}
}

func (p Protocol) url(environment identity.EnvironmentID, path string) (url.URL, error) {
	u, err := url.Parse(p.issuer + "/saml/" + environment.String() + "/" + path)
	if err != nil {
		return url.URL{}, errx.Wrap(err, "SAML issuer invalid", errx.TypeInternal)
	}
	return *u, nil
}

// provider is crewjam's identity provider for the environment's key.
func (p Protocol) provider(ctx context.Context, environment identity.EnvironmentID) (*saml.IdentityProvider, error) {
	if p.keys == nil {
		return nil, errx.Internal("SAML signing keys not configured")
	}
	signer, err := p.keys.Signer(ctx, environment)
	if err != nil {
		return nil, err
	}
	var cert *x509.Certificate
	if cached, ok := p.certs.Load(signer.ID); ok {
		cert = cached.(*x509.Certificate)
	} else {
		if cert, err = signer.Certificate(); err != nil {
			return nil, err
		}
		p.certs.Store(signer.ID, cert)
	}
	metadata, err := p.url(environment, "metadata")
	if err != nil {
		return nil, err
	}
	sso, err := p.url(environment, "sso")
	if err != nil {
		return nil, err
	}
	return &saml.IdentityProvider{Key: signer.Private, Certificate: cert, MetadataURL: metadata, SSOURL: sso, SignatureMethod: dsig.RSASHA256SignatureMethod}, nil
}

func (p Protocol) IdentityProvider(ctx context.Context, environment identity.EnvironmentID) (samlidp.IdentityProvider, error) {
	idp, err := p.provider(ctx, environment)
	if err != nil {
		return samlidp.IdentityProvider{}, err
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate.Raw})
	return samlidp.IdentityProvider{EntityID: idp.MetadataURL.String(), SSOURL: idp.SSOURL.String(), MetadataURL: idp.MetadataURL.String(), Certificate: string(certificate)}, nil
}

// Metadata is crewjam's IdP metadata with the NameID formats IAMKit sends;
// AuthnRequests need not be signed.
func (p Protocol) Metadata(ctx context.Context, environment identity.EnvironmentID) ([]byte, error) {
	idp, err := p.provider(ctx, environment)
	if err != nil {
		return nil, err
	}
	metadata := idp.Metadata()
	metadata.IDPSSODescriptors[0].NameIDFormats = []saml.NameIDFormat{saml.EmailAddressNameIDFormat, saml.PersistentNameIDFormat}
	out, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, errx.Wrap(err, "SAML metadata failed", errx.TypeInternal)
	}
	return out, nil
}

// Decode reads the AuthnRequest: deflated and base64 in the query string
// (HTTP-Redirect) or base64 in a form (HTTP-POST). Signatures on requests
// are not checked; the response only ever goes to a registered ACS URL.
func (p Protocol) Decode(message samlidp.Message) (samlidp.AuthnRequest, error) {
	invalid := errx.Validation("SAMLRequest is not a valid AuthnRequest")
	if message.SAMLRequest == "" || len(message.SAMLRequest) > maxRequest {
		return samlidp.AuthnRequest{}, errx.Validation("SAMLRequest is required")
	}
	raw, err := base64.StdEncoding.DecodeString(message.SAMLRequest)
	if err != nil {
		return samlidp.AuthnRequest{}, invalid
	}
	if message.Redirect {
		raw, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), maxRequest+1))
		if err != nil || len(raw) > maxRequest {
			return samlidp.AuthnRequest{}, invalid
		}
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return samlidp.AuthnRequest{}, invalid
	}
	var request saml.AuthnRequest
	if err := xml.Unmarshal(raw, &request); err != nil {
		return samlidp.AuthnRequest{}, invalid
	}
	out := samlidp.AuthnRequest{ID: request.ID, Version: request.Version, IssueInstant: request.IssueInstant, Destination: request.Destination, ACSURL: request.AssertionConsumerServiceURL, ACSIndex: request.AssertionConsumerServiceIndex, ProtocolBinding: request.ProtocolBinding, RelayState: message.RelayState}
	if request.Issuer != nil {
		out.Issuer = strings.TrimSpace(request.Issuer.Value)
	}
	if out.Issuer == "" {
		return samlidp.AuthnRequest{}, errx.Validation("SAML request issuer is required")
	}
	return out, nil
}

// Respond signs the assertion and the response around it. crewjam builds
// both from a synthetic request whose service provider metadata lists only
// the chosen ACS URL (and no encryption key: assertions are not encrypted).
func (p Protocol) Respond(ctx context.Context, environment identity.EnvironmentID, sp samlidp.ServiceProvider, request samlidp.Request, assertion samlidp.Assertion) (samlidp.Response, error) {
	idp, err := p.provider(ctx, environment)
	if err != nil {
		return samlidp.Response{}, err
	}
	acs := saml.IndexedEndpoint{Binding: saml.HTTPPostBinding, Location: request.ACSURL}
	descriptor := saml.SPSSODescriptor{AssertionConsumerServices: []saml.IndexedEndpoint{acs}}
	now := saml.TimeNow()
	req := &saml.IdpAuthnRequest{
		IDP:                     idp,
		HTTPRequest:             &http.Request{RemoteAddr: ""},
		RelayState:              request.RelayState,
		Request:                 saml.AuthnRequest{ID: request.ID, IssueInstant: now},
		ServiceProviderMetadata: &saml.EntityDescriptor{EntityID: sp.EntityID, SPSSODescriptors: []saml.SPSSODescriptor{descriptor}},
		SPSSODescriptor:         &descriptor,
		ACSEndpoint:             &acs,
		Now:                     now,
	}
	session := &saml.Session{ID: assertion.Session.String(), CreateTime: now, ExpireTime: now.Add(time.Hour), Index: assertion.Session.String(), NameID: assertion.NameID, NameIDFormat: nameIDFormat(assertion.NameIDFormat)}
	for _, a := range assertion.Attributes {
		attribute := saml.Attribute{Name: a.Name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", Values: []saml.AttributeValue{}}
		for _, v := range a.Values {
			attribute.Values = append(attribute.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		session.CustomAttributes = append(session.CustomAttributes, attribute)
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return samlidp.Response{}, errx.Wrap(err, "SAML assertion failed", errx.TypeInternal)
	}
	// An AttributeStatement needs at least one attribute; the browser's
	// address is not asserted.
	if len(session.CustomAttributes) == 0 {
		req.Assertion.AttributeStatements = nil
	}
	req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Address = ""
	req.Assertion.AuthnStatements[0].SubjectLocality = nil
	form, err := req.PostBinding()
	if err != nil {
		return samlidp.Response{}, errx.Wrap(err, "SAML response failed", errx.TypeInternal)
	}
	return samlidp.Response{Environment: environment, ACSURL: form.URL, SAMLResponse: form.SAMLResponse, RelayState: form.RelayState}, nil
}

func nameIDFormat(format string) string {
	if format == samlidp.NameIDPersistent {
		return string(saml.PersistentNameIDFormat)
	}
	return string(saml.EmailAddressNameIDFormat)
}
