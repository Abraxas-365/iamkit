package samlxml

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// maxSOAPResponse bounds the answer read from an application.
const maxSOAPResponse = 64 << 10

// statusUnknownPrincipal: the application has no such session any more;
// there is nothing left to end, so the notification counts as delivered.
const statusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

// Sender posts SOAP LogoutRequests (samlidp.LogoutSender). It follows no
// redirects.
type Sender struct{ client *http.Client }

var _ samlidp.LogoutSender = (*Sender)(nil)

// GuardedTransport dials only public addresses, ignoring proxies.
func GuardedTransport() http.RoundTripper {
	return &http.Transport{DialContext: netx.GuardedDialer().DialContext, TLSHandshakeTimeout: config.ExternalHTTPTimeout, ResponseHeaderTimeout: config.ExternalHTTPTimeout, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true}
}

// NewSender dials through transport (nil: GuardedTransport).
func NewSender(transport http.RoundTripper) *Sender {
	if transport == nil {
		transport = GuardedTransport()
	}
	return &Sender{client: &http.Client{Transport: telemetry.Transport(transport), Timeout: samlidp.LogoutTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type soapStatus struct {
	Body struct {
		Response struct {
			Status struct {
				Code struct {
					Value  string `xml:"Value,attr"`
					Nested struct {
						Value string `xml:"Value,attr"`
					} `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
				} `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
			} `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
}

func (s *Sender) Send(ctx context.Context, target string, envelope []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(envelope))
	if err != nil {
		return errx.Validation("invalid back-channel logout URL")
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"http://www.oasis-open.org/committees/security"`)
	req.Header.Set("Cache-Control", "no-store")
	res, err := s.client.Do(req)
	if err != nil {
		return errx.External("SAML logout request failed: " + netx.Reason(err))
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxSOAPResponse))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errx.External("SAML logout answered HTTP " + strconv.Itoa(res.StatusCode))
	}
	var answer soapStatus
	if err := xml.Unmarshal(body, &answer); err != nil {
		return errx.External("SAML logout answer is not a SOAP LogoutResponse")
	}
	code := answer.Body.Response.Status.Code
	switch {
	case code.Value == samlidp.StatusSuccess, code.Nested.Value == statusUnknownPrincipal:
		return nil
	case code.Value == "":
		return errx.External("SAML logout answer has no status")
	}
	return errx.External("SAML logout refused: " + code.Value)
}
