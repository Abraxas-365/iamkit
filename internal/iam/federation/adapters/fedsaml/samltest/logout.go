package samltest

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// Message is a SAML logout message on its way to the service provider (or
// back): a GET to URL (HTTP-Redirect: the signed message is in the query) or
// a POST of Fields to URL (HTTP-POST).
type Message struct {
	URL    string
	Fields [][2]string
	// RawQuery is the query of a redirect URL, byte for byte.
	RawQuery string
	// RequestID is the ID of the LogoutRequest (or the InResponseTo of the
	// LogoutResponse) the message carries.
	RequestID string
}

// Post reports whether the message is an HTTP-POST form.
func (m Message) Post() bool { return len(m.Fields) > 0 }

// Field returns a POST field.
func (m Message) Field(name string) string {
	for _, f := range m.Fields {
		if f[0] == name {
			return f[1]
		}
	}
	return ""
}

// signer signs with the identity provider's key (crewjam's helpers take a
// service provider).
func (i *IdP) signer() *saml.ServiceProvider {
	return &saml.ServiceProvider{Key: i.idp.Key.(crypto.Signer), Certificate: i.idp.Certificate, SignatureMethod: dsig.RSASHA256SignatureMethod}
}

func id() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "id-" + hex.EncodeToString(b)
}

// sloOf returns the service provider's SingleLogoutService for a binding.
func (i *IdP) sloOf(serviceProvider string, post bool) (saml.Endpoint, *saml.EntityDescriptor, error) {
	binding := saml.HTTPRedirectBinding
	if post {
		binding = saml.HTTPPostBinding
	}
	metadata, ok := i.sps[serviceProvider]
	if !ok {
		return saml.Endpoint{}, nil, errors.New("samltest: unknown service provider")
	}
	for _, d := range metadata.SPSSODescriptors {
		for _, s := range d.SingleLogoutServices {
			if s.Binding == binding {
				return s, metadata, nil
			}
		}
	}
	return saml.Endpoint{}, nil, errors.New("samltest: the service provider publishes no SingleLogoutService for " + binding)
}

// Tamper changes a logout message the identity provider sends (tests of
// refusals).
type Tamper struct {
	// Unsigned drops the signature.
	Unsigned bool
	// Destination replaces the destination (before signing).
	Destination string
	// Issuer replaces the issuer (before signing).
	Issuer string
	// IssueInstant replaces the issue instant (before signing).
	IssueInstant time.Time
	// Other signs with another identity provider's key.
	Other *IdP
	// NoSessionIndex leaves the SessionIndex out.
	NoSessionIndex bool
	// ID fixes the request ID (replay tests).
	ID string
}

// LogoutRequest is the LogoutRequest this identity provider sends to the
// service provider (IdP-initiated logout) for user's session, in the
// redirect or POST binding.
func (i *IdP) LogoutRequest(serviceProvider string, user User, post bool, relayState string, tamper ...Tamper) (Message, error) {
	var t Tamper
	if len(tamper) > 0 {
		t = tamper[0]
	}
	endpoint, _, err := i.sloOf(serviceProvider, post)
	if err != nil {
		return Message{}, err
	}
	index := user.SessionIndex
	if index == "" {
		index = "session"
	}
	now := time.Now().UTC()
	if !t.IssueInstant.IsZero() {
		now = t.IssueInstant
	}
	expires := now.Add(5 * time.Minute)
	req := &saml.LogoutRequest{
		ID: id(), Version: "2.0", IssueInstant: now, NotOnOrAfter: &expires, Destination: endpoint.Location,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: i.EntityID()},
		NameID: &saml.NameID{Format: user.NameIDFormat, Value: user.NameID},
	}
	if t.ID != "" {
		req.ID = t.ID
	}
	if t.Destination != "" {
		req.Destination = t.Destination
	}
	if t.Issuer != "" {
		req.Issuer.Value = t.Issuer
	}
	if !t.NoSessionIndex {
		req.SessionIndex = &saml.SessionIndex{Value: index}
	}
	signer := i.signer()
	if t.Other != nil {
		signer = t.Other.signer()
	}
	return encode(signer, req.Destination, post, "SAMLRequest", req.ID, relayState, t.Unsigned, req.Element, func() error { return signer.SignLogoutRequest(req) })
}

// encode serializes and signs el for the binding.
func encode(signer *saml.ServiceProvider, location string, post bool, parameter, requestID, relayState string, unsigned bool, element func() *etree.Element, sign func() error) (Message, error) {
	if post {
		if !unsigned {
			if err := sign(); err != nil {
				return Message{}, err
			}
		}
		doc := etree.NewDocument()
		doc.SetRoot(element())
		raw, err := doc.WriteToBytes()
		if err != nil {
			return Message{}, err
		}
		out := Message{URL: location, RequestID: requestID, Fields: [][2]string{{parameter, base64.StdEncoding.EncodeToString(raw)}}}
		if relayState != "" {
			out.Fields = append(out.Fields, [2]string{"RelayState", relayState})
		}
		return out, nil
	}
	doc := etree.NewDocument()
	doc.SetRoot(element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return Message{}, err
	}
	var deflated bytes.Buffer
	w, _ := flate.NewWriter(&deflated, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	query := parameter + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes()))
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if !unsigned {
		query += "&SigAlg=" + url.QueryEscape(signer.SignatureMethod)
		context, err := saml.GetSigningContext(signer)
		if err != nil {
			return Message{}, err
		}
		sig, err := context.SignString(query)
		if err != nil {
			return Message{}, err
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return Message{URL: location + "?" + query, RawQuery: query, RequestID: requestID}, nil
}

// Logout is a LogoutRequest of a service provider as the identity provider
// understood it.
type Logout struct {
	ID           string
	NameID       string
	SessionIndex string
	Destination  string
	RelayState   string
}

// AnswerLogout checks the service provider's signed LogoutRequest (the
// redirect URL, or the POST fields) and returns it with the signed
// LogoutResponse to send back, in the binding the request used.
func (i *IdP) AnswerLogout(serviceProvider string, request Message) (Logout, Message, error) {
	post := request.Post()
	endpoint, metadata, err := i.sloOf(serviceProvider, post)
	if err != nil {
		return Logout{}, Message{}, err
	}
	certs, err := signingCerts(metadata)
	if err != nil {
		return Logout{}, Message{}, err
	}
	var raw []byte
	var relay string
	if post {
		relay = request.Field("RelayState")
		if raw, err = base64.StdEncoding.DecodeString(request.Field("SAMLRequest")); err == nil {
			err = verifyDocument(certs, raw)
		}
	} else {
		raw, relay, err = verifyQuery(certs, request.URL)
	}
	if err != nil {
		return Logout{}, Message{}, err
	}
	var parsed saml.LogoutRequest
	if err = xml.Unmarshal(raw, &parsed); err != nil {
		return Logout{}, Message{}, err
	}
	out := Logout{ID: parsed.ID, Destination: parsed.Destination, RelayState: relay}
	if parsed.NameID != nil {
		out.NameID = parsed.NameID.Value
	}
	if parsed.SessionIndex != nil {
		out.SessionIndex = parsed.SessionIndex.Value
	}
	location := endpoint.ResponseLocation
	if location == "" {
		location = endpoint.Location
	}
	response := &saml.LogoutResponse{
		ID: id(), InResponseTo: parsed.ID, Version: "2.0", IssueInstant: time.Now().UTC(), Destination: location,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: i.EntityID()},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	signer := i.signer()
	answer, err := encode(signer, location, post, "SAMLResponse", parsed.ID, relay, false, response.Element, func() error { return signer.SignLogoutResponse(response) })
	return out, answer, err
}

func signingCerts(metadata *saml.EntityDescriptor) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, d := range metadata.SPSSODescriptors {
		for _, k := range d.KeyDescriptors {
			if k.Use != "signing" {
				continue
			}
			for _, c := range k.KeyInfo.X509Data.X509Certificates {
				raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Data), ""))
				if err != nil {
					return nil, err
				}
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return nil, err
				}
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("samltest: the service provider publishes no signing certificate")
	}
	return certs, nil
}

func verifyDocument(certs []*x509.Certificate, raw []byte) error {
	last := errors.New("samltest: no certificate")
	for _, cert := range certs {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(raw); err != nil {
			return err
		}
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		ctx.IdAttribute = "ID"
		if _, last = ctx.Validate(doc.Root()); last == nil {
			return nil
		}
	}
	return last
}

func verifyQuery(certs []*x509.Certificate, address string) ([]byte, string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, "", err
	}
	params := map[string]string{}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(pair, "=")
		params[k] = v
	}
	signed := "SAMLRequest=" + params["SAMLRequest"]
	if r, ok := params["RelayState"]; ok {
		signed += "&RelayState=" + r
	}
	signed += "&SigAlg=" + params["SigAlg"]
	sig, err := unescapeBase64(params["Signature"])
	if err != nil {
		return nil, "", err
	}
	verified := false
	for _, cert := range certs {
		if cert.CheckSignature(x509.SHA256WithRSA, []byte(signed), sig) == nil {
			verified = true
		}
	}
	if !verified {
		return nil, "", errors.New("samltest: the LogoutRequest signature is invalid")
	}
	deflated, err := unescapeBase64(params["SAMLRequest"])
	if err != nil {
		return nil, "", err
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	relay, _ := url.QueryUnescape(params["RelayState"])
	return raw, relay, err
}

func unescapeBase64(escaped string) ([]byte, error) {
	v, err := url.QueryUnescape(escaped)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(v)
}
