package fedsaml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML single logout: IAMKit is the service provider. Inbound messages
// (the identity provider's LogoutRequest and its LogoutResponse) are only
// accepted when signed by a certificate of the connection's metadata;
// outbound ones are always signed with the environment key.

const (
	protocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	// logoutWindow is how long after its IssueInstant a LogoutRequest is
	// accepted (besides the clock skew), and so how long its ID is kept
	// against replays.
	logoutWindow = 5 * time.Minute
	// maxInflated bounds the XML of a deflated HTTP-Redirect message.
	maxInflated = 1 << 20
)

var _ federation.LogoutProtocol = Provider{}

// logoutService finds the SingleLogoutService of identity provider
// metadata: HTTP-Redirect preferred, else HTTP-POST; HTTPS only.
func logoutService(entity *saml.EntityDescriptor) (federation.LogoutService, bool) {
	var post *federation.LogoutService
	for _, d := range entity.IDPSSODescriptors {
		for _, s := range d.SingleLogoutServices {
			if !strings.HasPrefix(s.Location, "https://") || (s.ResponseLocation != "" && !strings.HasPrefix(s.ResponseLocation, "https://")) {
				continue
			}
			out := federation.LogoutService{Location: s.Location, Binding: s.Binding, ResponseLocation: s.ResponseLocation}
			switch s.Binding {
			case saml.HTTPRedirectBinding:
				return out, true
			case saml.HTTPPostBinding:
				if post == nil {
					post = &out
				}
			}
		}
	}
	if post != nil {
		return *post, true
	}
	return federation.LogoutService{}, false
}

// LogoutService is the identity provider's SingleLogoutService.
func (Provider) LogoutService(c federation.Connection) (federation.LogoutService, bool, error) {
	entity, err := ParseMetadata([]byte(c.Options.MetadataXML))
	if err != nil {
		return federation.LogoutService{}, false, err
	}
	out, ok := logoutService(entity)
	return out, ok, nil
}

// idpCerts are the signing certificates of the identity provider metadata.
func idpCerts(entity *saml.EntityDescriptor) []*x509.Certificate {
	var out []*x509.Certificate
	now := time.Now()
	for _, d := range entity.IDPSSODescriptors {
		for _, k := range d.KeyDescriptors {
			if k.Use != "" && k.Use != "signing" {
				continue
			}
			for _, data := range k.KeyInfo.X509Data.X509Certificates {
				raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data.Data), ""))
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(raw)
				if err != nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
					continue
				}
				out = append(out, cert)
			}
		}
	}
	return out
}

func invalidLogout() error { return errx.Unauthorized("invalid SAML logout message") }

// rawParams splits a raw query string without decoding the values; a
// repeated parameter (parameter pollution) is refused.
func rawParams(query string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(key)
		if err != nil {
			return nil, invalidLogout()
		}
		if _, dup := out[key]; dup {
			return nil, invalidLogout()
		}
		out[key] = value
	}
	return out, nil
}

var redirectAlgorithms = map[string]x509.SignatureAlgorithm{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": x509.SHA256WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": x509.SHA384WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": x509.SHA512WithRSA,
}

// inflate reads a deflated message, bounded.
func inflate(data []byte) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(data)), maxInflated+1))
	if err != nil || len(out) > maxInflated {
		return nil, invalidLogout()
	}
	return out, nil
}

// queryValue decodes a base64 query parameter ('+' survives unescaped
// senders).
func queryValue(raw string) ([]byte, error) {
	v, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, invalidLogout()
	}
	out, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.Join(strings.Fields(v), "+"), " ", "+"))
	if err != nil {
		return nil, invalidLogout()
	}
	return out, nil
}

// verifiedMessage returns the XML of the message the identity provider
// sent, after checking its signature: the query signature of HTTP-Redirect
// (over the raw query, with a certificate of the metadata) or the enveloped
// XML signature of HTTP-POST. An unsigned message is refused.
func verifiedMessage(entity *saml.EntityDescriptor, m federation.LogoutMessage, parameter, element string) ([]byte, error) {
	certs := idpCerts(entity)
	if len(certs) == 0 {
		return nil, invalidLogout()
	}
	if m.Redirect {
		return verifyRedirect(certs, m, parameter)
	}
	value := m.SAMLRequest
	if parameter == "SAMLResponse" {
		value = m.SAMLResponse
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
	if err != nil {
		return nil, invalidLogout()
	}
	return verifyEnveloped(certs, raw, element)
}

func verifyRedirect(certs []*x509.Certificate, m federation.LogoutMessage, parameter string) ([]byte, error) {
	params, err := rawParams(m.RawQuery)
	if err != nil {
		return nil, err
	}
	message, signature, alg := params[parameter], params["Signature"], params["SigAlg"]
	if message == "" || signature == "" || alg == "" {
		return nil, invalidLogout()
	}
	algorithm, ok := func() (x509.SignatureAlgorithm, bool) {
		v, err := url.QueryUnescape(alg)
		a, ok := redirectAlgorithms[v]
		return a, ok && err == nil
	}()
	if !ok {
		return nil, invalidLogout()
	}
	sig, err := queryValue(signature)
	if err != nil {
		return nil, err
	}
	payload := parameter + "=" + message
	if relay, ok := params["RelayState"]; ok {
		payload += "&RelayState=" + relay
	}
	payload += "&SigAlg=" + alg
	verified := false
	for _, cert := range certs {
		if cert.CheckSignature(algorithm, []byte(payload), sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, invalidLogout()
	}
	deflated, err := queryValue(message)
	if err != nil {
		return nil, err
	}
	raw, err := inflate(deflated)
	if err != nil {
		return nil, err
	}
	if xrv.Validate(bytes.NewReader(raw)) != nil {
		return nil, invalidLogout()
	}
	return raw, nil
}

// verifyEnveloped checks the XML signature of the document element, a
// protocol element named element, against each certificate; it returns the
// signed element as the signature covers it.
func verifyEnveloped(certs []*x509.Certificate, raw []byte, element string) ([]byte, error) {
	if len(raw) > maxInflated || xrv.Validate(bytes.NewReader(raw)) != nil {
		return nil, invalidLogout()
	}
	for _, cert := range certs {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
			return nil, invalidLogout()
		}
		el := doc.Root()
		if el.Tag != element || el.NamespaceURI() != protocolNS || usesSHA1(el) {
			return nil, invalidLogout()
		}
		if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
			if sig := el.FindElement("./Signature"); sig != nil {
				if keyInfo := sig.FindElement("KeyInfo"); keyInfo != nil {
					sig.RemoveChild(keyInfo)
				}
			}
		}
		validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		validation.IdAttribute = "ID"
		// Validate checks that the signature's reference is the root
		// element itself (its ID); only the element it verified is read
		// back, never the unverified bytes.
		if signed, err := validation.Validate(el); err == nil && signed != nil {
			covered := etree.NewDocument()
			covered.SetRoot(signed)
			out, err := covered.WriteToBytes()
			if err != nil {
				return nil, invalidLogout()
			}
			return out, nil
		}
	}
	return nil, invalidLogout()
}

// SHA-1 signature and digest algorithms, refused in enveloped signatures
// (the HTTP-Redirect binding accepts SHA-256 and stronger only).
const (
	sha1Signature = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sha1ECDSA     = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	sha1Digest    = "http://www.w3.org/2000/09/xmldsig#sha1"
)

func usesSHA1(el *etree.Element) bool {
	if el.Tag == "SignatureMethod" || el.Tag == "DigestMethod" {
		if algorithm := el.SelectAttrValue("Algorithm", ""); algorithm == sha1Signature || algorithm == sha1ECDSA || algorithm == sha1Digest {
			return true
		}
	}
	for _, child := range el.ChildElements() {
		if usesSHA1(child) {
			return true
		}
	}
	return false
}

type issuerXML struct {
	Value string `xml:",chardata"`
}

type logoutRequestXML struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	NotOnOrAfter string    `xml:"NotOnOrAfter,attr"`
	Destination  string    `xml:"Destination,attr"`
	Issuer       issuerXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       *struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

type statusCodeXML struct {
	Value string         `xml:"Value,attr"`
	Inner *statusCodeXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type logoutResponseXML struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string    `xml:"ID,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	Issuer       issuerXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       struct {
		Code statusCodeXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
}

// metadataFor parses the connection's metadata and checks it is the
// identity provider the connection names.
func metadataFor(c federation.Connection) (*saml.EntityDescriptor, error) {
	entity, err := ParseMetadata([]byte(c.Options.MetadataXML))
	if err != nil {
		return nil, err
	}
	if entity.EntityID != c.Issuer {
		return nil, errx.Internal("SAML metadata does not match the connection issuer")
	}
	return entity, nil
}

// VerifyLogoutRequest checks an inbound LogoutRequest: signed by the
// identity provider, from its entity, to this connection's SLO URL, version
// 2.0 and within its validity.
func (p Provider) VerifyLogoutRequest(_ context.Context, c federation.Connection, m federation.LogoutMessage) (federation.LogoutRequest, error) {
	entity, err := metadataFor(c)
	if err != nil {
		return federation.LogoutRequest{}, err
	}
	raw, err := verifiedMessage(entity, m, "SAMLRequest", "LogoutRequest")
	if err != nil {
		return federation.LogoutRequest{}, err
	}
	var req logoutRequestXML
	if err = xml.Unmarshal(raw, &req); err != nil {
		return federation.LogoutRequest{}, invalidLogout()
	}
	endpoints := federation.SAMLServiceProvider(p.Issuer, c.Environment, c.ID)
	issued, err := parseTime(req.IssueInstant)
	if err != nil || req.ID == "" || len(req.ID) > 256 || req.Version != "2.0" || strings.TrimSpace(req.Issuer.Value) != entity.EntityID || req.Destination != endpoints.SLO {
		return federation.LogoutRequest{}, invalidLogout()
	}
	now := time.Now()
	valid := issued.Add(logoutWindow)
	if req.NotOnOrAfter != "" {
		until, err := parseTime(req.NotOnOrAfter)
		if err != nil {
			return federation.LogoutRequest{}, invalidLogout()
		}
		if until.Before(valid) {
			valid = until
		}
	}
	if issued.After(now.Add(saml.MaxClockSkew)) || now.After(valid.Add(saml.MaxClockSkew)) {
		return federation.LogoutRequest{}, invalidLogout()
	}
	if req.NameID == nil || strings.TrimSpace(req.NameID.Value) == "" || len(req.NameID.Value) > 1024 {
		return federation.LogoutRequest{}, invalidLogout()
	}
	out := federation.LogoutRequest{ID: req.ID, Issuer: entity.EntityID, NameID: strings.TrimSpace(req.NameID.Value), NameIDFormat: req.NameID.Format, NotOnOrAfter: valid, RelayState: m.RelayState}
	for _, index := range req.SessionIndex {
		if index = strings.TrimSpace(index); index != "" && len(index) <= 1024 {
			out.SessionIndexes = append(out.SessionIndexes, index)
		}
		if len(out.SessionIndexes) > 100 {
			return federation.LogoutRequest{}, invalidLogout()
		}
	}
	return out, nil
}

// signed builds the outbound message for service: the XML signed in
// place (HTTP-POST) or deflated into the query and signed over it
// (HTTP-Redirect).
func signed(sp *saml.ServiceProvider, location, binding, parameter string, element func() *etree.Element, relay string, sign func() error) (federation.Outbound, error) {
	if binding == saml.HTTPPostBinding {
		if err := sign(); err != nil {
			return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
		}
		doc := etree.NewDocument()
		doc.SetRoot(element())
		raw, err := doc.WriteToBytes()
		if err != nil {
			return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
		}
		fields := [][2]string{{parameter, base64.StdEncoding.EncodeToString(raw)}}
		if relay != "" {
			fields = append(fields, [2]string{"RelayState", relay})
		}
		return federation.Outbound{URL: location, Fields: fields}, nil
	}
	doc := etree.NewDocument()
	doc.SetRoot(element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
	}
	var deflated bytes.Buffer
	writer, _ := flate.NewWriter(&deflated, flate.BestCompression)
	if _, err = writer.Write(raw); err == nil {
		err = writer.Close()
	}
	if err != nil {
		return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
	}
	query := parameter + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes()))
	if relay != "" {
		query += "&RelayState=" + url.QueryEscape(relay)
	}
	query += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)
	context, err := saml.GetSigningContext(sp)
	if err != nil {
		return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
	}
	signature, err := context.SignString(query)
	if err != nil {
		return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
	}
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
	target, err := url.Parse(location)
	if err != nil {
		return federation.Outbound{}, errx.Wrap(err, "SAML logout failed", errx.TypeInternal)
	}
	if target.RawQuery != "" {
		query = target.RawQuery + "&" + query
	}
	target.RawQuery = query
	return federation.Outbound{URL: target.String()}, nil
}

// signingProvider is the service provider set up to sign logout messages.
func (p Provider) signingProvider(ctx context.Context, c federation.Connection) (*saml.ServiceProvider, error) {
	sp, err := p.serviceProvider(ctx, c)
	if err != nil {
		return nil, err
	}
	sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	return sp, nil
}

func randomID() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "id-" + hex.EncodeToString(b)
}

// LogoutResponse signs the answer to an identity provider's request.
func (p Provider) LogoutResponse(ctx context.Context, c federation.Connection, service federation.LogoutService, request federation.LogoutRequest, status string) (federation.Outbound, error) {
	sp, err := p.signingProvider(ctx, c)
	if err != nil {
		return federation.Outbound{}, err
	}
	code := saml.StatusCode{Value: federation.StatusSuccess}
	switch status {
	case federation.StatusPartialLogout:
		code.StatusCode = &saml.StatusCode{Value: federation.StatusPartialLogout}
	case federation.StatusRequester, federation.StatusResponder:
		code.Value = status
	}
	response := &saml.LogoutResponse{
		ID: randomID(), InResponseTo: request.ID, Version: "2.0", IssueInstant: time.Now().UTC(), Destination: service.Response(),
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: sp.EntityID},
		Status: saml.Status{StatusCode: code},
	}
	return signed(sp, service.Response(), service.Binding, "SAMLResponse", response.Element, request.RelayState, func() error {
		return sp.SignLogoutResponse(response)
	})
}

// LogoutRequest signs an SP-initiated LogoutRequest.
func (p Provider) LogoutRequest(ctx context.Context, c federation.Connection, service federation.LogoutService, link authentication.FederationLink, relayState string) (federation.Outbound, string, error) {
	sp, err := p.signingProvider(ctx, c)
	if err != nil {
		return federation.Outbound{}, "", err
	}
	now := time.Now().UTC()
	expires := now.Add(logoutWindow)
	request := &saml.LogoutRequest{
		ID: randomID(), Version: "2.0", IssueInstant: now, NotOnOrAfter: &expires, Destination: service.Location,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: sp.EntityID},
		NameID: &saml.NameID{Format: link.NameIDFormat, Value: link.NameID},
	}
	if link.SessionIndex != "" {
		request.SessionIndex = &saml.SessionIndex{Value: link.SessionIndex}
	}
	out, err := signed(sp, service.Location, service.Binding, "SAMLRequest", request.Element, relayState, func() error {
		return sp.SignLogoutRequest(request)
	})
	return out, request.ID, err
}

// VerifyLogoutResponse checks the identity provider's LogoutResponse to
// the request requestID.
func (p Provider) VerifyLogoutResponse(_ context.Context, c federation.Connection, m federation.LogoutMessage, requestID string) (bool, error) {
	entity, err := metadataFor(c)
	if err != nil {
		return false, err
	}
	raw, err := verifiedMessage(entity, m, "SAMLResponse", "LogoutResponse")
	if err != nil {
		return false, err
	}
	var res logoutResponseXML
	if err = xml.Unmarshal(raw, &res); err != nil {
		return false, invalidLogout()
	}
	endpoints := federation.SAMLServiceProvider(p.Issuer, c.Environment, c.ID)
	issued, err := parseTime(res.IssueInstant)
	if err != nil || res.Version != "2.0" || requestID == "" || res.InResponseTo != requestID || strings.TrimSpace(res.Issuer.Value) != entity.EntityID || res.Destination != endpoints.SLO {
		return false, invalidLogout()
	}
	now := time.Now()
	if issued.After(now.Add(saml.MaxClockSkew)) || now.After(issued.Add(logoutWindow+saml.MaxClockSkew)) {
		return false, invalidLogout()
	}
	return res.Status.Code.Value == federation.StatusSuccess, nil
}

// LogoutResponseID reads the InResponseTo of a LogoutResponse without
// verifying it.
func (Provider) LogoutResponseID(m federation.LogoutMessage) (string, error) {
	var raw []byte
	var err error
	if m.Redirect {
		params, perr := rawParams(m.RawQuery)
		if perr != nil {
			return "", perr
		}
		var deflated []byte
		if deflated, err = queryValue(params["SAMLResponse"]); err == nil {
			raw, err = inflate(deflated)
		}
	} else {
		raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(m.SAMLResponse), ""))
	}
	if err != nil || len(raw) > maxInflated || xrv.Validate(bytes.NewReader(raw)) != nil {
		return "", invalidLogout()
	}
	var res logoutResponseXML
	if xml.Unmarshal(raw, &res) != nil || res.InResponseTo == "" {
		return "", invalidLogout()
	}
	return res.InResponseTo, nil
}
