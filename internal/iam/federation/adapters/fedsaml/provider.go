// Package fedsaml is the SAML 2.0 service provider side of federation: it
// sends HTTP-Redirect authentication requests to an organization's
// identity provider and verifies the HTTP-POST responses it answers with.
//
// The service provider signs requests and decrypts assertions with the
// environment's active signing key (signing.Keyring); its certificate is
// self-signed, deterministic per key, and published in the SP metadata.
package fedsaml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// Provider implements federation.Provider for SAML connections.
type Provider struct {
	// Issuer is the deployment's public URL; the SP endpoints live under it.
	Issuer string
	Keys   signing.Keyring
	// Transport fetches identity provider metadata; nil uses a guarded
	// transport (public addresses only).
	Transport http.RoundTripper
	certs     *sync.Map
}

// New returns a SAML provider.
func New(issuer string, keys signing.Keyring, transport http.RoundTripper) Provider {
	return Provider{Issuer: issuer, Keys: keys, Transport: transport, certs: &sync.Map{}}
}

func (Provider) Approved(federation.Connection) bool { return false }
func (Provider) Verifier() string                    { return "" }
func (p Provider) Callback() string                  { return p.Issuer + "/identity/v1/federation/saml/acs" }

// Prepare fetches the metadata at MetadataURL (when no XML is given), checks
// that it describes an identity provider IAMKit can use, and sets the issuer
// (the IdP entity ID) and client ID (the SP entity ID).
func (p Provider) Prepare(ctx context.Context, c federation.Connection) (federation.Connection, error) {
	if c.Options.MetadataXML == "" {
		raw, err := p.fetch(ctx, c.Options.MetadataURL)
		if err != nil {
			return c, err
		}
		c.Options.MetadataXML = raw
	}
	entity, err := ParseMetadata([]byte(c.Options.MetadataXML))
	if err != nil {
		return c, err
	}
	c.Issuer = entity.EntityID
	c.Client = federation.SAMLServiceProvider(p.Issuer, c.Environment, c.ID).EntityID
	return c, nil
}

func (p Provider) fetch(ctx context.Context, address string) (string, error) {
	transport := p.Transport
	if transport == nil {
		transport = &http.Transport{DialContext: netx.GuardedDialer().DialContext, TLSHandshakeTimeout: config.ExternalHTTPTimeout, ResponseHeaderTimeout: config.ExternalHTTPTimeout}
	}
	client := &http.Client{Transport: transport, Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", errx.Validation("options.metadata_url is not a valid URL")
	}
	res, err := client.Do(req)
	if err != nil {
		return "", errx.Wrap(err, "the identity provider metadata could not be fetched", errx.TypeExternal)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", errx.External("the identity provider metadata could not be fetched")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, federation.MaxMetadata+1))
	if err != nil {
		return "", errx.Wrap(err, "the identity provider metadata could not be read", errx.TypeExternal)
	}
	if len(body) > federation.MaxMetadata {
		return "", errx.Validation("the identity provider metadata is larger than 512 KiB")
	}
	return string(body), nil
}

// ParseMetadata reads identity provider metadata: an EntityDescriptor, or
// the first one with an IDPSSODescriptor in an EntitiesDescriptor. It needs
// an HTTP-Redirect single sign-on service and a signing certificate.
func ParseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	invalid := errx.Validation("options.metadata_xml is not SAML identity provider metadata with an HTTP-Redirect SSO service and a signing certificate")
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, invalid
	}
	entity := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(data, entity); err != nil {
		entities := &saml.EntitiesDescriptor{}
		if xml.Unmarshal(data, entities) != nil {
			return nil, invalid
		}
		entity = nil
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				break
			}
		}
		if entity == nil {
			return nil, invalid
		}
	}
	if entity.EntityID == "" || len(entity.EntityID) > 1024 || len(entity.IDPSSODescriptors) == 0 {
		return nil, invalid
	}
	redirect, signing := false, false
	for _, d := range entity.IDPSSODescriptors {
		for _, s := range d.SingleSignOnServices {
			if s.Binding == saml.HTTPRedirectBinding && strings.HasPrefix(s.Location, "https://") {
				redirect = true
			}
		}
		for _, k := range d.KeyDescriptors {
			if (k.Use == "" || k.Use == "signing") && len(k.KeyInfo.X509Data.X509Certificates) > 0 {
				signing = true
			}
		}
	}
	if !redirect || !signing {
		return nil, invalid
	}
	return entity, nil
}

// serviceProvider builds the crewjam service provider of a connection.
func (p Provider) serviceProvider(ctx context.Context, c federation.Connection) (*saml.ServiceProvider, error) {
	entity, err := ParseMetadata([]byte(c.Options.MetadataXML))
	if err != nil {
		return nil, err
	}
	if entity.EntityID != c.Issuer {
		return nil, errx.Internal("SAML metadata does not match the connection issuer")
	}
	key, cert, err := p.key(ctx, c)
	if err != nil {
		return nil, err
	}
	endpoints := federation.SAMLServiceProvider(p.Issuer, c.Environment, c.ID)
	acs, _ := url.Parse(endpoints.ACS)
	metadata, _ := url.Parse(endpoints.Metadata)
	sp := &saml.ServiceProvider{EntityID: endpoints.EntityID, Key: key, Certificate: cert, AcsURL: *acs, MetadataURL: *metadata, IDPMetadata: entity, AuthnNameIDFormat: nameIDFormat(c.Options.NameIDFormat)}
	if c.Options.SignRequests {
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	}
	return sp, nil
}

func nameIDFormat(format string) saml.NameIDFormat {
	switch format {
	case federation.NameIDPersistent:
		return saml.PersistentNameIDFormat
	case federation.NameIDEmail:
		return saml.EmailAddressNameIDFormat
	case federation.NameIDTransient:
		return saml.TransientNameIDFormat
	}
	return saml.UnspecifiedNameIDFormat
}

// key is the environment's signing key and its self-signed certificate.
// The certificate is derived from the key alone (fixed validity, serial
// from the key ID; RSA PKCS #1 v1.5 signatures are deterministic), so every
// replica publishes the same one.
func (p Provider) key(ctx context.Context, c federation.Connection) (*rsa.PrivateKey, *x509.Certificate, error) {
	if p.Keys == nil {
		return nil, nil, errx.Internal("SAML signing keys not configured")
	}
	signer, err := p.Keys.Signer(ctx, c.Environment)
	if err != nil {
		return nil, nil, err
	}
	if p.certs != nil {
		if cert, ok := p.certs.Load(signer.ID); ok {
			return signer.Private, cert.(*x509.Certificate), nil
		}
	}
	cert, err := signer.Certificate()
	if err != nil {
		return nil, nil, err
	}
	if p.certs != nil {
		p.certs.Store(signer.ID, cert)
	}
	return signer.Private, cert, nil
}

// RequestID is the AuthnRequest ID for a login's nonce: the response must
// answer it (InResponseTo), which binds it to the state row.
func RequestID(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return "id-" + hex.EncodeToString(sum[:20])
}

// Authorize returns the identity provider's HTTP-Redirect URL with the
// AuthnRequest; RelayState is the state.
func (p Provider) Authorize(ctx context.Context, c federation.Connection, state, nonce, _ string) (string, error) {
	sp, err := p.serviceProvider(ctx, c)
	if err != nil {
		return "", err
	}
	location := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if location == "" {
		return "", errx.Business("the identity provider has no HTTP-Redirect SSO service")
	}
	req, err := sp.MakeAuthenticationRequest(location, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", errx.Wrap(err, "SAML request failed", errx.TypeInternal)
	}
	req.ID = RequestID(nonce)
	address, err := req.Redirect(url.QueryEscape(state), sp)
	if err != nil {
		return "", errx.Wrap(err, "SAML request failed", errx.TypeInternal)
	}
	return address.String(), nil
}

// Verify checks a base64 SAML response: signed by the identity provider
// (response or assertion), for this service provider (audience,
// destination, recipient), answering the request made with nonce, and
// within its validity window. Encrypted assertions are decrypted with the
// environment key.
func (p Provider) Verify(ctx context.Context, c federation.Connection, response, nonce, _ string) (claims federation.Claims, err error) {
	sp, err := p.serviceProvider(ctx, c)
	if err != nil {
		return claims, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(response), ""))
	if err != nil {
		return claims, errx.Unauthorized("invalid SAML response")
	}
	defer func() {
		// The library dereferences optional elements (Subject, Conditions)
		// of an assertion it has verified; a malformed one must not crash.
		if recover() != nil {
			claims, err = federation.Claims{}, errx.Unauthorized("invalid SAML response")
		}
	}()
	assertion, err := sp.ParseXMLResponse(raw, []string{RequestID(nonce)}, sp.AcsURL)
	if err != nil {
		return claims, errx.Wrap(err, "invalid SAML response", errx.TypeAuthorization)
	}
	return Claims(c, assertion)
}

// Claims maps a verified assertion to the identity federation uses.
func Claims(c federation.Connection, a *saml.Assertion) (federation.Claims, error) {
	if a.Subject == nil || a.Conditions == nil || a.ID == "" {
		return federation.Claims{}, errx.Unauthorized("invalid SAML response")
	}
	mapping := federation.AttributeMapping{}
	if c.Options.Attributes != nil {
		mapping = *c.Options.Attributes
	}
	var nameID saml.NameID
	if a.Subject.NameID != nil {
		nameID = *a.Subject.NameID
	}
	out := federation.Claims{Issuer: c.Issuer, Assertion: a.ID, AssertionExpires: a.Conditions.NotOnOrAfter.Add(saml.MaxClockSkew)}
	if out.AssertionExpires.Before(time.Now().Add(config.FederationStateTTL)) {
		out.AssertionExpires = time.Now().Add(config.FederationStateTTL)
	}
	if mapping.Subject != "" {
		out.Subject = attribute(a, mapping.Subject)
	} else if nameID.Format != string(saml.TransientNameIDFormat) {
		out.Subject = strings.TrimSpace(nameID.Value)
	}
	if out.Subject == "" || len(out.Subject) > 512 {
		return federation.Claims{}, errx.Unauthorized("the SAML assertion has no stable subject")
	}
	if mapping.Email != "" {
		out.Email = attribute(a, mapping.Email)
	} else {
		out.Email = attribute(a, emailAttributes...)
		if out.Email == "" && nameID.Format == string(saml.EmailAddressNameIDFormat) {
			out.Email = strings.TrimSpace(nameID.Value)
		}
	}
	if mapping.Name != "" {
		out.Name = attribute(a, mapping.Name)
	} else if out.Name = attribute(a, nameAttributes...); out.Name == "" {
		out.Name = strings.TrimSpace(attribute(a, givenNameAttributes...) + " " + attribute(a, surnameAttributes...))
	}
	return out, nil
}

var (
	emailAttributes     = []string{"email", "mail", "emailaddress", "urn:oid:0.9.2342.19200300.100.1.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "user.email"}
	nameAttributes      = []string{"displayName", "urn:oid:2.16.840.1.113730.3.1.241", "http://schemas.microsoft.com/identity/claims/displayname", "cn", "urn:oid:2.5.4.3", "fullName"}
	givenNameAttributes = []string{"givenName", "firstName", "urn:oid:2.5.4.42", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"}
	surnameAttributes   = []string{"sn", "surname", "lastName", "urn:oid:2.5.4.4", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"}
)

// attribute returns the first non-empty value of the first attribute whose
// Name or FriendlyName matches one of names (case-insensitively).
func attribute(a *saml.Assertion, names ...string) string {
	for _, name := range names {
		for _, statement := range a.AttributeStatements {
			for _, attr := range statement.Attributes {
				if !strings.EqualFold(attr.Name, name) && !strings.EqualFold(attr.FriendlyName, name) {
					continue
				}
				for _, v := range attr.Values {
					if s := strings.TrimSpace(v.Value); s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

// Metadata is the service provider metadata: entity ID, the HTTP-POST
// assertion consumer service, the requested NameID format and the
// certificate for encryption (and signing, when requests are signed).
func (p Provider) Metadata(ctx context.Context, c federation.Connection) ([]byte, error) {
	sp, err := p.serviceProvider(ctx, c)
	if err != nil {
		return nil, err
	}
	entity := sp.Metadata()
	for i := range entity.SPSSODescriptors {
		d := &entity.SPSSODescriptors[i]
		// Only HTTP-POST is served; the artifact binding is not.
		d.AssertionConsumerServices = d.AssertionConsumerServices[:1]
	}
	out, err := xml.MarshalIndent(entity, "", "  ")
	if err != nil {
		return nil, errx.Wrap(err, "SAML metadata failed", errx.TypeInternal)
	}
	return append([]byte(xml.Header), out...), nil
}

var _ federation.Provider = Provider{}
