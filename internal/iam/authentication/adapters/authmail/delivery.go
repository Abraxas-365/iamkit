package authmail

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
	"net/http"
	"strconv"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/netx"
)

// WebhookDelivery delegates mail delivery to a trusted HTTPS service (HTTP
// only on loopback). It sends
// no management credentials and refuses redirects. The service receives the
// recipient, purpose and one-time code or invitation token, and must treat
// them as secrets.
//
// With a token, requests carry it as a bearer token and are also signed per
// the Standard Webhooks specification (webhook-id, webhook-timestamp,
// webhook-signature: v1 HMAC-SHA256 keyed with the token bytes), so a
// receiver can reject forged or replayed calls.
type WebhookDelivery struct {
	URL, Token string
	// Transport defaults to the guarded transport (public addresses only),
	// for URLs an environment operator chose; the deployment-wide webhook
	// uses http.DefaultTransport.
	Transport http.RoundTripper
}

func (d WebhookDelivery) Validate() error {
	if !authentication.SecureURL(d.URL) {
		return errx.Validation("email webhook must use HTTPS (HTTP allowed only on loopback)")
	}
	return nil
}
func (d WebhookDelivery) Send(ctx context.Context, m authentication.Message) error {
	if err := d.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return errx.Wrap(err, "prepare email delivery", errx.TypeInternal)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.URL, bytes.NewReader(body))
	if err != nil {
		return errx.Wrap(err, "prepare email delivery", errx.TypeInternal)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.Token)
	if d.Token != "" {
		id, err := webhookID()
		if err != nil {
			return errx.Wrap(err, "prepare email delivery", errx.TypeInternal)
		}
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("webhook-id", id)
		req.Header.Set("webhook-timestamp", timestamp)
		req.Header.Set("webhook-signature", SignWebhook(d.Token, id, timestamp, body))
	}
	transport := d.Transport
	if transport == nil {
		transport = guardedHTTP()
	}
	client := http.Client{Transport: transport, Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		code := authentication.CodeDeliveryUnreachable
		switch {
		case errors.Is(err, netx.ErrNotPublic):
			code = authentication.CodeWebhookAddress
		case timedOut(err):
			code = authentication.CodeDeliveryTimeout
		}
		return authentication.DeliveryFailure(err, code)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return authentication.DeliveryRejected(res.StatusCode)
	}
	return nil
}

// SignWebhook is the Standard Webhooks signature header value for body:
// "v1," + base64(HMAC-SHA256(secret, id + "." + timestamp + "." + body)).
// The key is the token's bytes as-is (Standard Webhooks libraries accept it
// as base64(token), or as a raw secret where supported).
func SignWebhook(secret, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// webhookID is a unique message ID, the idempotency key a receiver can
// deduplicate on.
func webhookID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "msg_" + hex.EncodeToString(b), nil
}
