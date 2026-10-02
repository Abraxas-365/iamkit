// Package authsms sends text messages through Twilio or the customer's
// webhook. Environment endpoints are dialed through netx.GuardedDialer
// (public addresses only) unless a test transport replaces it.
package authsms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// Guarded is the shared transport for environment SMS endpoints: public
// addresses only.
var Guarded = sync.OnceValue(func() http.RoundTripper {
	return &http.Transport{
		DialContext:           netx.GuardedDialer().DialContext,
		TLSHandshakeTimeout:   config.ExternalHTTPTimeout,
		ResponseHeaderTimeout: config.ExternalHTTPTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
	}
})

// TwilioAPI is Twilio's REST API base.
const TwilioAPI = "https://api.twilio.com"

// Twilio sends through the Messages API with the account's SID and auth
// token, from a number or a messaging service.
type Twilio struct {
	AccountSID, AuthToken     string
	From, MessagingServiceSID string
	// Endpoint replaces TwilioAPI (tests); Transport defaults to Guarded.
	Endpoint  string
	Transport http.RoundTripper
}

func (t Twilio) SendSMS(ctx context.Context, m authentication.SMS) error {
	endpoint := t.Endpoint
	if endpoint == "" {
		endpoint = TwilioAPI
	}
	form := url.Values{"To": {m.Phone}, "Body": {m.Body}}
	if t.MessagingServiceSID != "" {
		form.Set("MessagingServiceSid", t.MessagingServiceSID)
	} else {
		form.Set("From", t.From)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(endpoint, "/")+"/2010-04-01/Accounts/"+url.PathEscape(t.AccountSID)+"/Messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return errx.Wrap(err, "prepare SMS", errx.TypeInternal)
	}
	req.SetBasicAuth(t.AccountSID, t.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := do(t.Transport, req)
	if err != nil {
		return failure(err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	switch {
	case res.StatusCode == 401 || res.StatusCode == 403:
		e := errx.External("SMS provider rejected the credentials").WithDetail("status", res.StatusCode)
		e.Code = authentication.CodeSMSProviderAuth
		return e
	case res.StatusCode < 200 || res.StatusCode >= 300:
		return authentication.SMSRejected(res.StatusCode)
	}
	return nil
}

// Webhook posts the message as JSON ({phone, purpose, code, body}) to the
// customer's HTTPS endpoint, with the token as bearer and a Standard
// Webhooks signature (webhook-id, webhook-timestamp, webhook-signature).
type Webhook struct {
	URL, Token string
	Transport  http.RoundTripper
}

func (w Webhook) SendSMS(ctx context.Context, m authentication.SMS) error {
	if !authentication.SecureURL(w.URL) {
		return errx.Validation("SMS webhook must use HTTPS (HTTP allowed only on loopback)")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return errx.Wrap(err, "prepare SMS", errx.TypeInternal)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", w.URL, bytes.NewReader(body))
	if err != nil {
		return errx.Wrap(err, "prepare SMS", errx.TypeInternal)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.Token)
	id, err := messageID()
	if err != nil {
		return errx.Wrap(err, "prepare SMS", errx.TypeInternal)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", Sign(w.Token, id, timestamp, body))
	res, err := do(w.Transport, req)
	if err != nil {
		return failure(err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return authentication.SMSRejected(res.StatusCode)
	}
	return nil
}

// Sign is the Standard Webhooks signature of body (same scheme as the
// email webhook).
func Sign(secret, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func messageID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "msg_" + hex.EncodeToString(b), nil
}

func do(transport http.RoundTripper, req *http.Request) (*http.Response, error) {
	if transport == nil {
		transport = Guarded()
	}
	client := http.Client{Transport: telemetry.Transport(transport), Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client.Do(req)
}

func failure(err error) error {
	code := authentication.CodeSMSProviderUnreachable
	var timeout net.Error
	switch {
	case errors.Is(err, netx.ErrNotPublic):
		code = authentication.CodeWebhookAddress
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()):
		code = authentication.CodeSMSProviderTimeout
	}
	e := errx.Wrap(err, "SMS delivery failed", errx.TypeExternal)
	e.Code = code
	return e
}

// Factory builds the sender of an environment's configuration; transport
// nil uses Guarded, twilioEndpoint "" uses TwilioAPI.
func Factory(transport http.RoundTripper, twilioEndpoint string) func(cfg authentication.SMSConfig, secret string) (authentication.SMSDelivery, error) {
	return func(cfg authentication.SMSConfig, secret string) (authentication.SMSDelivery, error) {
		switch cfg.Provider {
		case authentication.SMSProviderTwilio:
			return Twilio{AccountSID: cfg.AccountSID, AuthToken: secret, From: cfg.FromNumber, MessagingServiceSID: cfg.MessagingServiceSID, Endpoint: twilioEndpoint, Transport: transport}, nil
		case authentication.SMSProviderWebhook:
			return Webhook{URL: cfg.WebhookURL, Token: secret, Transport: transport}, nil
		}
		return nil, errx.Internal("unknown SMS provider " + cfg.Provider)
	}
}
