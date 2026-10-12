package samlxml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	_ "crypto/sha256" // register the hashes redirect signatures use
	_ "crypto/sha512"
)

// Single logout. Every inbound LogoutRequest must be signed with the
// certificate registered for the service provider: HTTP-Redirect requests
// carry a query-string signature (SigAlg + Signature over the raw
// SAMLRequest[&RelayState]&SigAlg query), HTTP-POST requests an enveloped
// XML signature that references the request element. SHA-1 signatures and
// digests are refused. A certificate outside its validity period refuses
// every request (the registered certificate must be renewed with the
// application's).

var _ samlidp.LogoutProtocol = Protocol{}

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsSOAP      = "http://schemas.xmlsoap.org/soap/envelope/"
	entityName  = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	// maxSessionIndexes bounds the SessionIndex elements of a request.
	maxSessionIndexes = 10
	// backchannelValidity is how long an application may accept a
	// back-channel LogoutRequest.
	backchannelValidity = 5 * time.Minute
)

// logoutXML is the part of a LogoutRequest IAMKit reads.
type logoutXML struct {
	XMLName      xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string            `xml:"ID,attr"`
	IssueInstant saml.RelaxedTime  `xml:"IssueInstant,attr"`
	NotOnOrAfter *saml.RelaxedTime `xml:"NotOnOrAfter,attr"`
	Destination  string            `xml:"Destination,attr"`
	Issuer       string            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       string            `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex []string          `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

func invalidLogout() error { return errx.Validation("SAMLRequest is not a valid LogoutRequest") }

// logoutBytes is the request XML as the message carries it.
func logoutBytes(m samlidp.LogoutMessage) ([]byte, error) {
	if m.SAMLRequest == "" || len(m.SAMLRequest) > samlidp.MaxLogoutMessage {
		return nil, errx.Validation("SAMLRequest is required")
	}
	encoded := m.SAMLRequest
	if !m.Redirect {
		encoded = strings.NewReplacer("\r", "", "\n", "", " ", "", "\t", "").Replace(encoded)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, invalidLogout()
	}
	if m.Redirect {
		raw, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), maxRequest+1))
		if err != nil {
			return nil, invalidLogout()
		}
	}
	if len(raw) > maxRequest {
		return nil, invalidLogout()
	}
	return raw, nil
}

// parseLogout reads a LogoutRequest document.
func parseLogout(raw []byte) (samlidp.LogoutRequest, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return samlidp.LogoutRequest{}, invalidLogout()
	}
	var request logoutXML
	if err := xml.Unmarshal(raw, &request); err != nil {
		return samlidp.LogoutRequest{}, invalidLogout()
	}
	if len(request.SessionIndex) > maxSessionIndexes {
		return samlidp.LogoutRequest{}, invalidLogout()
	}
	out := samlidp.LogoutRequest{ID: request.ID, Issuer: strings.TrimSpace(request.Issuer), Destination: request.Destination, NameID: strings.TrimSpace(request.NameID), IssueInstant: time.Time(request.IssueInstant)}
	if request.NotOnOrAfter != nil {
		out.NotOnOrAfter = time.Time(*request.NotOnOrAfter)
	}
	for _, index := range request.SessionIndex {
		if index = strings.TrimSpace(index); index != "" {
			out.SessionIndexes = append(out.SessionIndexes, index)
		}
	}
	return out, nil
}

// DecodeLogout reads the LogoutRequest; nothing in it is trusted until
// VerifyLogout.
func (p Protocol) DecodeLogout(m samlidp.LogoutMessage) (samlidp.LogoutRequest, error) {
	raw, err := logoutBytes(m)
	if err != nil {
		return samlidp.LogoutRequest{}, err
	}
	out, err := parseLogout(raw)
	if err != nil {
		return samlidp.LogoutRequest{}, err
	}
	if out.Issuer == "" {
		return samlidp.LogoutRequest{}, errx.Validation("SAML request issuer is required")
	}
	out.RelayState = m.RelayState
	return out, nil
}

func refused() error {
	return errx.Unauthorized("the LogoutRequest signature is missing or invalid")
}

// VerifyLogout checks the signature against the provider's certificate.
func (p Protocol) VerifyLogout(m samlidp.LogoutMessage, sp samlidp.ServiceProvider) error {
	cert, err := samlidp.ParseCertificate(sp.Certificate)
	if err != nil {
		return refused()
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return refused()
	}
	if m.Redirect {
		return verifyRedirect(m, cert)
	}
	return verifyPost(m, cert)
}

// redirectAlgorithms are the accepted query signature algorithms.
var redirectAlgorithms = map[string]crypto.Hash{
	dsig.RSASHA256SignatureMethod:   crypto.SHA256,
	dsig.RSASHA384SignatureMethod:   crypto.SHA384,
	dsig.RSASHA512SignatureMethod:   crypto.SHA512,
	dsig.ECDSASHA256SignatureMethod: crypto.SHA256,
	dsig.ECDSASHA384SignatureMethod: crypto.SHA384,
	dsig.ECDSASHA512SignatureMethod: crypto.SHA512,
}

func verifyRedirect(m samlidp.LogoutMessage, cert *x509.Certificate) error {
	params := map[string]string{}
	for _, part := range strings.Split(m.RawQuery, "&") {
		key, value, _ := strings.Cut(part, "=")
		switch key {
		case "SAMLRequest", "RelayState", "SigAlg", "Signature":
			if _, dup := params[key]; dup {
				return refused()
			}
			params[key] = value
		}
	}
	request, err := url.QueryUnescape(params["SAMLRequest"])
	if err != nil || request != m.SAMLRequest {
		return refused()
	}
	relay, hasRelay := params["RelayState"]
	if unescaped, err := url.QueryUnescape(relay); err != nil || unescaped != m.RelayState || (!hasRelay && m.RelayState != "") {
		return refused()
	}
	algorithm, err := url.QueryUnescape(params["SigAlg"])
	hash, known := redirectAlgorithms[algorithm]
	if err != nil || !known || !hash.Available() {
		return refused()
	}
	encoded, err := url.QueryUnescape(params["Signature"])
	if err != nil || encoded == "" {
		return refused()
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return refused()
	}
	signed := "SAMLRequest=" + params["SAMLRequest"]
	if hasRelay {
		signed += "&RelayState=" + relay
	}
	signed += "&SigAlg=" + params["SigAlg"]
	h := hash.New()
	h.Write([]byte(signed))
	digest := h.Sum(nil)
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if !strings.Contains(algorithm, "rsa-") || rsa.VerifyPKCS1v15(key, hash, digest, signature) != nil {
			return refused()
		}
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		if !strings.Contains(algorithm, "ecdsa-") || len(signature) != 2*size ||
			!ecdsa.Verify(key, digest, new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])) {
			return refused()
		}
	default:
		return refused()
	}
	return nil
}

const (
	sha1Signature = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sha1ECDSA     = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	sha1Digest    = "http://www.w3.org/2000/09/xmldsig#sha1"
)

func verifyPost(m samlidp.LogoutMessage, cert *x509.Certificate) error {
	raw, err := logoutBytes(m)
	if err != nil {
		return refused()
	}
	decoded, err := parseLogout(raw)
	if err != nil {
		return refused()
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return refused()
	}
	if usesSHA1(doc.Root()) {
		return refused()
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	validation.IdAttribute = "ID"
	verified, err := validation.Validate(doc.Root())
	if err != nil {
		return refused()
	}
	// Only what the signature covers counts: the verified element must say
	// what the unverified document said (signature wrapping).
	check := etree.NewDocument()
	check.SetRoot(verified)
	covered, err := check.WriteToBytes()
	if err != nil {
		return refused()
	}
	coveredRequest, err := parseLogout(covered)
	if err != nil || !sameLogout(coveredRequest, decoded) {
		return refused()
	}
	return nil
}

func sameLogout(a, b samlidp.LogoutRequest) bool {
	return a.ID == b.ID && a.Issuer == b.Issuer && a.Destination == b.Destination && a.NameID == b.NameID &&
		a.IssueInstant.Equal(b.IssueInstant) && a.NotOnOrAfter.Equal(b.NotOnOrAfter) && slices.Equal(a.SessionIndexes, b.SessionIndexes)
}

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

func randomID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", errx.Wrap(err, "generate SAML message id", errx.TypeInternal)
	}
	return "id-" + hex.EncodeToString(b), nil
}

// signature signs el (enveloped) with the environment key and returns the
// Signature element for the caller to place.
func signature(idp *saml.IdentityProvider, el *etree.Element) (*etree.Element, error) {
	signer, ok := idp.Key.(crypto.Signer)
	if !ok {
		return nil, errx.Internal("SAML signing key unsupported")
	}
	sc, err := dsig.NewSigningContext(signer, [][]byte{idp.Certificate.Raw})
	if err != nil {
		return nil, errx.Wrap(err, "SAML signing failed", errx.TypeInternal)
	}
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, errx.Wrap(err, "SAML signing failed", errx.TypeInternal)
	}
	signed, err := sc.SignEnveloped(el)
	if err != nil {
		return nil, errx.Wrap(err, "SAML signing failed", errx.TypeInternal)
	}
	sig, ok := signed.Child[len(signed.Child)-1].(*etree.Element)
	if !ok {
		return nil, errx.Internal("SAML signing failed")
	}
	return sig, nil
}

// LogoutResponse answers a verified request at the provider's slo_url:
// HTTP-POST (enveloped XML signature) or HTTP-Redirect (query signature,
// RSA-SHA256).
func (p Protocol) LogoutResponse(ctx context.Context, environment identity.EnvironmentID, sp samlidp.ServiceProvider, request samlidp.LogoutRequest, status string) (samlidp.LogoutAnswer, error) {
	idp, err := p.provider(ctx, environment)
	if err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	id, err := randomID()
	if err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	response := &saml.LogoutResponse{
		ID:           id,
		InResponseTo: request.ID,
		Version:      "2.0",
		IssueInstant: saml.TimeNow(),
		Destination:  sp.SLOURL,
		Issuer:       &saml.Issuer{Format: entityName, Value: idp.MetadataURL.String()},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: status}},
	}
	answer := samlidp.LogoutAnswer{Environment: environment, URL: sp.SLOURL}
	if sp.SLOBinding == samlidp.SLOBindingPOST {
		sig, err := signature(idp, response.Element())
		if err != nil {
			return samlidp.LogoutAnswer{}, err
		}
		response.Signature = sig
		doc := etree.NewDocument()
		doc.SetRoot(response.Element())
		xmlBytes, err := doc.WriteToBytes()
		if err != nil {
			return samlidp.LogoutAnswer{}, errx.Wrap(err, "SAML response failed", errx.TypeInternal)
		}
		answer.Fields = [][2]string{{"SAMLResponse", base64.StdEncoding.EncodeToString(xmlBytes)}}
		if request.RelayState != "" {
			answer.Fields = append(answer.Fields, [2]string{"RelayState", request.RelayState})
		}
		return answer, nil
	}
	doc := etree.NewDocument()
	doc.SetRoot(response.Element())
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return samlidp.LogoutAnswer{}, errx.Wrap(err, "SAML response failed", errx.TypeInternal)
	}
	var deflated bytes.Buffer
	writer, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return samlidp.LogoutAnswer{}, errx.Wrap(err, "SAML response failed", errx.TypeInternal)
	}
	if _, err := writer.Write(xmlBytes); err != nil {
		return samlidp.LogoutAnswer{}, errx.Wrap(err, "SAML response failed", errx.TypeInternal)
	}
	if err := writer.Close(); err != nil {
		return samlidp.LogoutAnswer{}, errx.Wrap(err, "SAML response failed", errx.TypeInternal)
	}
	signed := "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes()))
	if request.RelayState != "" {
		signed += "&RelayState=" + url.QueryEscape(request.RelayState)
	}
	signed += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	key, ok := idp.Key.(crypto.Signer)
	if !ok {
		return samlidp.LogoutAnswer{}, errx.Internal("SAML signing key unsupported")
	}
	digest := crypto.SHA256.New()
	digest.Write([]byte(signed))
	sig, err := key.Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
	if err != nil {
		return samlidp.LogoutAnswer{}, errx.Wrap(err, "SAML signing failed", errx.TypeInternal)
	}
	signed += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	target, err := url.Parse(sp.SLOURL)
	if err != nil {
		return samlidp.LogoutAnswer{}, errx.Validation("slo_url is invalid")
	}
	if target.RawQuery != "" {
		target.RawQuery += "&"
	}
	target.RawQuery += signed
	answer.URL = target.String()
	return answer, nil
}

// BackchannelLogout is the signed LogoutRequest for the notification in a
// SOAP 1.1 envelope. Its SessionIndex is the session id, as assertions
// carry it (AuthnStatement SessionIndex).
func (p Protocol) BackchannelLogout(ctx context.Context, n samlidp.LogoutNotification) ([]byte, error) {
	idp, err := p.provider(ctx, n.Environment)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	now := saml.TimeNow()
	notAfter := now.Add(backchannelValidity)
	request := &saml.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: now,
		NotOnOrAfter: &notAfter,
		Destination:  n.ServiceProvider.SLOSOAPURL,
		Issuer:       &saml.Issuer{Format: entityName, Value: idp.MetadataURL.String()},
		NameID: &saml.NameID{
			Format:          nameIDFormat(n.ServiceProvider.NameIDFormat),
			Value:           n.NameID,
			NameQualifier:   idp.MetadataURL.String(),
			SPNameQualifier: n.ServiceProvider.EntityID,
		},
		SessionIndex: &saml.SessionIndex{Value: n.Session.String()},
	}
	sig, err := signature(idp, request.Element())
	if err != nil {
		return nil, err
	}
	request.Signature = sig
	doc := etree.NewDocument()
	envelope := doc.CreateElement("soap-env:Envelope")
	envelope.CreateAttr("xmlns:soap-env", nsSOAP)
	envelope.CreateElement("soap-env:Body").AddChild(request.Element())
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, errx.Wrap(err, "SAML logout request failed", errx.TypeInternal)
	}
	return out, nil
}
