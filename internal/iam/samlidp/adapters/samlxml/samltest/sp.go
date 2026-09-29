// Package samltest is a SAML 2.0 service provider for tests: it builds
// AuthnRequests for IAMKit's identity provider and verifies the responses
// it posts back (signature, audience, destination, InResponseTo, validity)
// with github.com/crewjam/saml.
package samltest

import (
	"encoding/base64"
	"encoding/xml"
	"net/url"

	"github.com/crewjam/saml"
)

// SP is an in-memory service provider (its ACS URL is never dialed).
type SP struct {
	sp *saml.ServiceProvider
}

// Result is what a verified response asserts.
type Result struct {
	NameID       string
	NameIDFormat string
	SessionIndex string
	Attributes   map[string][]string
}

// New returns a service provider with entityID posting to acs.
func New(entityID, acs string) *SP {
	u, err := url.Parse(acs)
	if err != nil {
		panic(err)
	}
	return &SP{sp: &saml.ServiceProvider{EntityID: entityID, AcsURL: *u, AuthnNameIDFormat: saml.EmailAddressNameIDFormat}}
}

// Trust reads the identity provider's metadata.
func (s *SP) Trust(metadata []byte) error {
	var descriptor saml.EntityDescriptor
	if err := xml.Unmarshal(metadata, &descriptor); err != nil {
		return err
	}
	s.sp.IDPMetadata = &descriptor
	return nil
}

// Redirect is the HTTP-Redirect binding URL of a new AuthnRequest (at the
// SSO location in the trusted metadata) and the request ID.
func (s *SP) Redirect(relayState string) (string, string, error) {
	req, err := s.sp.MakeAuthenticationRequest(s.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}
	u, err := req.Redirect(relayState, s.sp)
	if err != nil {
		return "", "", err
	}
	return u.String(), req.ID, nil
}

// Post is the HTTP-POST binding SAMLRequest form value of a new
// AuthnRequest and the request ID.
func (s *SP) Post() (string, string, error) {
	req, err := s.sp.MakeAuthenticationRequest(s.sp.GetSSOBindingLocation(saml.HTTPPostBinding), saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}
	doc, err := xml.Marshal(req)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(doc), req.ID, nil
}

// Verify checks a posted SAMLResponse answering one of requestIDs.
func (s *SP) Verify(samlResponse string, requestIDs ...string) (Result, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return Result{}, err
	}
	assertion, err := s.sp.ParseXMLResponse(raw, requestIDs, s.sp.AcsURL)
	if err != nil {
		if invalid, ok := err.(*saml.InvalidResponseError); ok {
			return Result{}, invalid.PrivateErr
		}
		return Result{}, err
	}
	out := Result{Attributes: map[string][]string{}}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		out.NameID = assertion.Subject.NameID.Value
		out.NameIDFormat = assertion.Subject.NameID.Format
	}
	for _, statement := range assertion.AuthnStatements {
		out.SessionIndex = statement.SessionIndex
	}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			for _, value := range attribute.Values {
				out.Attributes[attribute.Name] = append(out.Attributes[attribute.Name], value.Value)
			}
		}
	}
	return out, nil
}
