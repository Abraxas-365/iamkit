package samltest

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// Single logout for the service provider double: it signs LogoutRequests
// with its own key (generated at runtime; Certificate is what an
// application registers), receives SOAP back-channel LogoutRequests from
// the identity provider and verifies their signatures, and verifies the
// signed LogoutResponses.

// Logout is a LogoutRequest the identity provider delivered.
type Logout struct {
	ID           string
	NameID       string
	SessionIndex string
	Destination  string
}

// keys is the signing key and certificate (generated on first use).
func (s *SP) keys() (*rsa.PrivateKey, *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		s.key, s.cert = key, selfSigned(key, s.sp.EntityID)
	}
	return s.key, s.cert
}

func selfSigned(key *rsa.PrivateKey, name string) *x509.Certificate {
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

// Certificate is the PEM certificate the application registers.
func (s *SP) Certificate() string {
	_, cert := s.keys()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// Impostor returns a service provider with the same entity ID and another
// key (generated on first use): its signatures must be refused.
func (s *SP) Impostor() *SP {
	return &SP{sp: s.sp}
}

func (s *SP) idpSLO(binding string) (string, error) {
	if s.sp.IDPMetadata == nil || len(s.sp.IDPMetadata.IDPSSODescriptors) == 0 {
		return "", errors.New("no identity provider metadata")
	}
	for _, e := range s.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices {
		if e.Binding == binding {
			return e.Location, nil
		}
	}
	return "", errors.New("identity provider metadata lists no " + binding + " SingleLogoutService")
}

func (s *SP) idpCertificate() (*x509.Certificate, error) {
	if s.sp.IDPMetadata == nil || len(s.sp.IDPMetadata.IDPSSODescriptors) == 0 {
		return nil, errors.New("no identity provider metadata")
	}
	for _, k := range s.sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors {
		for _, c := range k.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Data), ""))
			if err != nil {
				return nil, err
			}
			return x509.ParseCertificate(der)
		}
	}
	return nil, errors.New("identity provider metadata has no certificate")
}

// LogoutOptions shape a LogoutRequest.
type LogoutOptions struct {
	NameID       string
	SessionIndex string
	RelayState   string
	// Issuer overrides the entity ID.
	Issuer string
	// Destination overrides the identity provider's SLO location.
	Destination string
	// Unsigned leaves the signature out.
	Unsigned bool
	// IssuedAt overrides now.
	IssuedAt time.Time
	// SHA1 signs with RSA-SHA1.
	SHA1 bool
}

func (s *SP) logoutRequest(o LogoutOptions, binding string) (*saml.LogoutRequest, error) {
	destination := o.Destination
	if destination == "" {
		var err error
		if destination, err = s.idpSLO(binding); err != nil {
			return nil, err
		}
	}
	issuer := o.Issuer
	if issuer == "" {
		issuer = s.sp.EntityID
	}
	issued := o.IssuedAt
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	request := &saml.LogoutRequest{
		ID:           fmt.Sprintf("id-%x", b),
		Version:      "2.0",
		IssueInstant: issued,
		Destination:  destination,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer},
		NameID:       &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: o.NameID},
	}
	if o.SessionIndex != "" {
		request.SessionIndex = &saml.SessionIndex{Value: o.SessionIndex}
	}
	return request, nil
}

// LogoutRedirect is the HTTP-Redirect binding URL of a signed (RSA-SHA256
// over the query) LogoutRequest, and the request ID.
func (s *SP) LogoutRedirect(o LogoutOptions) (string, string, error) {
	request, err := s.logoutRequest(o, saml.HTTPRedirectBinding)
	if err != nil {
		return "", "", err
	}
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", "", err
	}
	var deflated bytes.Buffer
	w, _ := flate.NewWriter(&deflated, flate.DefaultCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes()))
	if o.RelayState != "" {
		query += "&RelayState=" + url.QueryEscape(o.RelayState)
	}
	algorithm, hash := dsig.RSASHA256SignatureMethod, crypto.SHA256
	if o.SHA1 {
		algorithm, hash = "http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1
	}
	query += "&SigAlg=" + url.QueryEscape(algorithm)
	if !o.Unsigned {
		key, _ := s.keys()
		h := hash.New()
		h.Write([]byte(query))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
		if err != nil {
			return "", "", err
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return request.Destination + "?" + query, request.ID, nil
}

// LogoutPost is the HTTP-POST binding SAMLRequest form value (enveloped
// XML signature) and the request ID.
func (s *SP) LogoutPost(o LogoutOptions) (string, string, error) {
	request, err := s.logoutRequest(o, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}
	if !o.Unsigned {
		key, cert := s.keys()
		sc, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
		if err != nil {
			return "", "", err
		}
		sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		method := dsig.RSASHA256SignatureMethod
		if o.SHA1 {
			method = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		}
		if err := sc.SetSignatureMethod(method); err != nil {
			return "", "", err
		}
		signed, err := sc.SignEnveloped(request.Element())
		if err != nil {
			return "", "", err
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		raw, err := doc.WriteToBytes()
		if err != nil {
			return "", "", err
		}
		return base64.StdEncoding.EncodeToString(raw), request.ID, nil
	}
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(raw), request.ID, nil
}

// LogoutResponse is a verified LogoutResponse.
type LogoutResponse struct {
	InResponseTo string
	Status       string
	RelayState   string
	Destination  string
}

// VerifyLogoutRedirect checks the signed LogoutResponse in the redirect
// the identity provider answered with (the Location header).
func (s *SP) VerifyLogoutRedirect(location string) (LogoutResponse, error) {
	cert, err := s.idpCertificate()
	if err != nil {
		return LogoutResponse{}, err
	}
	u, err := url.Parse(location)
	if err != nil {
		return LogoutResponse{}, err
	}
	q := u.Query()
	signed := "SAMLResponse=" + url.QueryEscape(q.Get("SAMLResponse"))
	if _, ok := q["RelayState"]; ok {
		signed += "&RelayState=" + url.QueryEscape(q.Get("RelayState"))
	}
	signed += "&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))
	if q.Get("SigAlg") != dsig.RSASHA256SignatureMethod {
		return LogoutResponse{}, errors.New("unexpected SigAlg " + q.Get("SigAlg"))
	}
	signature, err := base64.StdEncoding.DecodeString(q.Get("Signature"))
	if err != nil {
		return LogoutResponse{}, err
	}
	digest := sha256sum(signed)
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest, signature); err != nil {
		return LogoutResponse{}, errors.New("bad response signature")
	}
	compressed, err := base64.StdEncoding.DecodeString(q.Get("SAMLResponse"))
	if err != nil {
		return LogoutResponse{}, err
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		return LogoutResponse{}, err
	}
	out, err := s.readResponse(raw)
	out.RelayState = q.Get("RelayState")
	return out, err
}

// VerifyLogoutPost checks the signed LogoutResponse in a posted
// SAMLResponse form value.
func (s *SP) VerifyLogoutPost(samlResponse string) (LogoutResponse, error) {
	cert, err := s.idpCertificate()
	if err != nil {
		return LogoutResponse{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return LogoutResponse{}, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return LogoutResponse{}, err
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	validation.IdAttribute = "ID"
	if _, err := validation.Validate(doc.Root()); err != nil {
		return LogoutResponse{}, err
	}
	return s.readResponse(raw)
}

func (s *SP) readResponse(raw []byte) (LogoutResponse, error) {
	var parsed saml.LogoutResponse
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return LogoutResponse{}, err
	}
	if parsed.Issuer == nil || parsed.Issuer.Value != s.sp.IDPMetadata.EntityID {
		return LogoutResponse{}, errors.New("response issuer is not the identity provider")
	}
	return LogoutResponse{InResponseTo: parsed.InResponseTo, Status: parsed.Status.StatusCode.Value, Destination: parsed.Destination}, nil
}

func sha256sum(s string) []byte {
	h := crypto.SHA256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

// Backchannel is an application endpoint (HTTPS, self-signed: dial it with
// Client().Transport) for SOAP LogoutRequests.
type Backchannel struct {
	*httptest.Server
	mu       sync.Mutex
	received []Logout
	// Status is what the endpoint answers with ("" = Success); HTTPStatus
	// overrides the HTTP code (0 = 200).
	Status     string
	HTTPStatus int
	failures   int
}

// FailNext makes the next n requests answer HTTP 500.
func (b *Backchannel) FailNext(n int) { b.mu.Lock(); b.failures = n; b.mu.Unlock() }

// Received are the verified LogoutRequests so far.
func (b *Backchannel) Received() []Logout {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Logout(nil), b.received...)
}

// Backchannel starts an endpoint that verifies the identity provider's
// signature on each SOAP LogoutRequest (against the trusted metadata)
// and answers with a SOAP LogoutResponse. Close it when done.
func (s *SP) Backchannel() *Backchannel {
	b := &Backchannel{}
	b.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		b.mu.Lock()
		if b.failures > 0 {
			b.failures--
			b.mu.Unlock()
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		b.mu.Unlock()
		logout, err := s.readSOAP(r, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.received = append(b.received, logout)
		status, code := b.Status, b.HTTPStatus
		b.mu.Unlock()
		if status == "" {
			status = saml.StatusSuccess
		}
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		if code != 0 {
			w.WriteHeader(code)
		}
		fmt.Fprintf(w, `<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body><samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-r" Version="2.0" InResponseTo=%q><samlp:Status><samlp:StatusCode Value=%q/></samlp:Status></samlp:LogoutResponse></soap-env:Body></soap-env:Envelope>`, logout.ID, status)
	}))
	return b
}

func (s *SP) readSOAP(r *http.Request, body []byte) (Logout, error) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/xml") {
		return Logout{}, errors.New("content type is not text/xml")
	}
	cert, err := s.idpCertificate()
	if err != nil {
		return Logout{}, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return Logout{}, err
	}
	envelope := doc.Root()
	if envelope == nil || envelope.Tag != "Envelope" {
		return Logout{}, errors.New("not a SOAP envelope")
	}
	soapBody := envelope.FindElement("./Body")
	if soapBody == nil || soapBody.FindElement("./LogoutRequest") == nil {
		return Logout{}, errors.New("no LogoutRequest in the SOAP body")
	}
	element := soapBody.FindElement("./LogoutRequest")
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	validation.IdAttribute = "ID"
	verified, err := validation.Validate(element)
	if err != nil {
		return Logout{}, errors.New("bad LogoutRequest signature: " + err.Error())
	}
	check := etree.NewDocument()
	check.SetRoot(verified)
	raw, err := check.WriteToBytes()
	if err != nil {
		return Logout{}, err
	}
	var parsed saml.LogoutRequest
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return Logout{}, err
	}
	if parsed.Issuer == nil || parsed.Issuer.Value != s.sp.IDPMetadata.EntityID {
		return Logout{}, errors.New("issuer is not the identity provider")
	}
	if parsed.NotOnOrAfter != nil && time.Now().After(*parsed.NotOnOrAfter) {
		return Logout{}, errors.New("request expired")
	}
	out := Logout{ID: parsed.ID, Destination: parsed.Destination}
	if parsed.NameID != nil {
		out.NameID = parsed.NameID.Value
	}
	if parsed.SessionIndex != nil {
		out.SessionIndex = parsed.SessionIndex.Value
	}
	return out, nil
}
