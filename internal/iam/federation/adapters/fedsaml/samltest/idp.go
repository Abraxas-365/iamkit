// Package samltest is a SAML 2.0 identity provider for tests: it answers
// an HTTP-Redirect AuthnRequest URL with the signed HTTP-POST response the
// browser would carry to the service provider's assertion consumer service.
package samltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
)

// IdP is an in-memory identity provider at Base (an HTTPS URL that is never
// dialed: tests pass the redirect URL to Answer).
type IdP struct {
	Base string
	idp  *saml.IdentityProvider
	sps  map[string]*saml.EntityDescriptor
	// Encrypt makes assertions encrypted to the service provider's
	// certificate (from its metadata).
	Encrypt bool
	// SLO publishes a SingleLogoutService at Base+"/slo" in the metadata:
	// "redirect", "post" or "both"; "" publishes none.
	SLO string
}

// New returns an identity provider with a fresh key.
func New(base string) *IdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return NewWithKey(base, key)
}

// NewWithKey returns an identity provider signing with key.
func NewWithKey(base string, key *rsa.PrivateKey) *IdP {
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "samltest"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, _ := x509.ParseCertificate(der)
	metadata, _ := url.Parse(base + "/metadata")
	sso, _ := url.Parse(base + "/sso")
	out := &IdP{Base: base, sps: map[string]*saml.EntityDescriptor{}}
	out.idp = &saml.IdentityProvider{Key: key, Certificate: cert, MetadataURL: *metadata, SSOURL: *sso, ServiceProviderProvider: out}
	return out
}

// EntityID is the identity provider's entity ID (its metadata URL).
func (i *IdP) EntityID() string { return i.idp.MetadataURL.String() }

// Metadata is the identity provider's metadata XML.
func (i *IdP) Metadata() string {
	entity := i.idp.Metadata()
	if i.SLO != "" {
		slo := i.Base + "/slo"
		if i.SLO == "redirect" || i.SLO == "both" {
			entity.IDPSSODescriptors[0].SingleLogoutServices = append(entity.IDPSSODescriptors[0].SingleLogoutServices, saml.Endpoint{Binding: saml.HTTPRedirectBinding, Location: slo})
		}
		if i.SLO == "post" || i.SLO == "both" {
			entity.IDPSSODescriptors[0].SingleLogoutServices = append(entity.IDPSSODescriptors[0].SingleLogoutServices, saml.Endpoint{Binding: saml.HTTPPostBinding, Location: slo})
		}
	}
	out, err := xml.MarshalIndent(entity, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(out)
}

// Trust registers a service provider's metadata.
func (i *IdP) Trust(metadata []byte) error {
	entity := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(metadata, entity); err != nil {
		return err
	}
	if !i.Encrypt {
		for d := range entity.SPSSODescriptors {
			keys := entity.SPSSODescriptors[d].KeyDescriptors[:0]
			for _, k := range entity.SPSSODescriptors[d].KeyDescriptors {
				if k.Use != "encryption" {
					keys = append(keys, k)
				}
			}
			entity.SPSSODescriptors[d].KeyDescriptors = keys
		}
	}
	i.sps[entity.EntityID] = entity
	return nil
}

func (i *IdP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if sp, ok := i.sps[id]; ok {
		return sp, nil
	}
	return nil, os.ErrNotExist
}

// User is who signs in and how the assertion describes them.
type User struct {
	NameID       string
	NameIDFormat string
	Email        string
	Name         string
	// SessionIndex is the identity provider's session ("" = "session").
	SessionIndex string
	// Attributes are extra attributes by name.
	Attributes map[string]string
	// MultiAttributes are multi-valued attributes by name (group lists).
	MultiAttributes map[string][]string
	// Edit changes the assertion before it is signed (tests of invalid
	// responses).
	Edit func(*saml.Assertion)
}

// Form is the auto-submitted HTTP-POST form the browser carries to the ACS.
type Form struct {
	URL, SAMLResponse, RelayState string
	// RequestID is the AuthnRequest ID the response answers.
	RequestID string
}

// Answer handles the AuthnRequest at redirect (the URL the service
// provider sent the browser to) and returns the response form.
func (i *IdP) Answer(redirect string, user User) (Form, error) {
	req, err := saml.NewIdpAuthnRequest(i.idp, httptest.NewRequest(http.MethodGet, redirect, nil))
	if err != nil {
		return Form{}, err
	}
	if err = req.Validate(); err != nil {
		return Form{}, err
	}
	return i.respond(req, user)
}

// Unsolicited returns the response an identity provider posts when the user
// starts at the IdP (IdP-initiated): signed like any other, but answering no
// AuthnRequest (no InResponseTo). The service provider must have been
// registered with Trust; relayState may be empty.
func (i *IdP) Unsolicited(serviceProvider, relayState string, user User) (Form, error) {
	metadata, ok := i.sps[serviceProvider]
	if !ok {
		return Form{}, os.ErrNotExist
	}
	req := &saml.IdpAuthnRequest{IDP: i.idp, HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil), RelayState: relayState, Now: time.Now(), ServiceProviderMetadata: metadata}
	for d := range metadata.SPSSODescriptors {
		for _, endpoint := range metadata.SPSSODescriptors[d].AssertionConsumerServices {
			if endpoint.Binding == saml.HTTPPostBinding && req.ACSEndpoint == nil {
				endpoint, descriptor := endpoint, metadata.SPSSODescriptors[d]
				req.ACSEndpoint, req.SPSSODescriptor = &endpoint, &descriptor
			}
		}
	}
	if req.ACSEndpoint == nil {
		return Form{}, os.ErrNotExist
	}
	return i.respond(req, user)
}

func (i *IdP) respond(req *saml.IdpAuthnRequest, user User) (Form, error) {
	var err error
	index := user.SessionIndex
	if index == "" {
		index = "session"
	}
	session := &saml.Session{ID: "session", Index: index, NameID: user.NameID, NameIDFormat: user.NameIDFormat, UserEmail: user.Email, UserCommonName: user.Name, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour)}
	for name, value := range user.Attributes {
		session.CustomAttributes = append(session.CustomAttributes, saml.Attribute{Name: name, Values: []saml.AttributeValue{{Type: "xs:string", Value: value}}})
	}
	for name, values := range user.MultiAttributes {
		attribute := saml.Attribute{Name: name}
		for _, v := range values {
			attribute.Values = append(attribute.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		session.CustomAttributes = append(session.CustomAttributes, attribute)
	}
	if err = (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return Form{}, err
	}
	if user.Edit != nil {
		user.Edit(req.Assertion)
	}
	if err = req.MakeAssertionEl(); err != nil {
		return Form{}, err
	}
	form, err := req.PostBinding()
	if err != nil {
		return Form{}, err
	}
	return Form{URL: form.URL, SAMLResponse: form.SAMLResponse, RelayState: form.RelayState, RequestID: req.Request.ID}, nil
}
