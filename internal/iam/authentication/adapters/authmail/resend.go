package authmail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/mail"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// ResendEndpoint is Resend's send-email API.
const ResendEndpoint = "https://api.resend.com/emails"

// Resend sends rendered email through the Resend API.
type Resend struct {
	APIKey string
	// Endpoint defaults to ResendEndpoint (tests point it elsewhere).
	Endpoint string
	// Transport defaults to GuardedResendTransport; the deployment-wide
	// provider may use http.DefaultTransport.
	Transport http.RoundTripper
}

var _ authentication.Mailer = Resend{}

// GuardedResendTransport dials only public addresses, for API endpoints an
// environment operator could influence. Environment proxies are ignored
// because they would hide the destination from the check. The transport is
// shared by every environment so idle connections are reused, not leaked
// per send.
func GuardedResendTransport() http.RoundTripper { return guardedHTTP() }

// guardedHTTP is the shared guarded transport for environment Resend and
// webhook endpoints.
var guardedHTTP = sync.OnceValue(func() http.RoundTripper {
	return &http.Transport{
		DialContext:           netx.GuardedDialer().DialContext,
		TLSHandshakeTimeout:   config.ExternalHTTPTimeout,
		ResponseHeaderTimeout: config.ExternalHTTPTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
	}
})

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text"`
	ReplyTo string   `json:"reply_to,omitempty"`
}

// resendAuthErrors are Resend error names that mean the key itself is bad
// (401, or 403 for an inactive or suspended key). Other 403s, such as an
// unverified sending domain, are rejections of the request.
var resendAuthErrors = map[string]bool{
	"missing_api_key": true, "invalid_api_key": true, "restricted_api_key": true, "suspended_api_key": true,
}

func (r Resend) Deliver(ctx context.Context, email authentication.Email) error {
	endpoint, transport := r.Endpoint, r.Transport
	if endpoint == "" {
		endpoint = ResendEndpoint
	}
	if transport == nil {
		transport = GuardedResendTransport()
	}
	body, err := json.Marshal(resendRequest{
		From: sender(email), To: []string{email.To}, Subject: email.Subject,
		HTML: email.HTML, Text: email.Text, ReplyTo: email.ReplyTo,
	})
	if err != nil {
		return errx.Wrap(err, "prepare email", errx.TypeInternal)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errx.Wrap(err, "prepare email", errx.TypeInternal)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.APIKey)
	req.Header.Set("User-Agent", "IAMKit")
	client := http.Client{Transport: telemetry.Transport(transport), Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return networkFailure(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	var answer struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &answer)
	if res.StatusCode == http.StatusUnauthorized || resendAuthErrors[answer.Name] {
		return authentication.DeliveryFailure(errx.External("resend: "+answer.Name), authentication.CodeProviderAuth)
	}
	return authentication.ProviderRejected(res.StatusCode)
}

// sender is the From header value: "Name <address>" with the name quoted or
// encoded as needed, or the bare address.
func sender(email authentication.Email) string {
	if email.FromName == "" {
		return email.From
	}
	return (&mail.Address{Name: email.FromName, Address: email.From}).String()
}
