package authmail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
)

// WebhookDelivery delegates mail delivery to a trusted HTTPS service. It sends
// no management credentials and refuses redirects. The service receives the
// recipient, purpose and one-time code, and must treat them as secrets.
type WebhookDelivery struct{ URL, Token string }

func (d WebhookDelivery) Validate() error {
	u, err := url.Parse(d.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errx.Validation("email webhook must use HTTPS")
	}
	return nil
}
func (d WebhookDelivery) Send(ctx context.Context, email, purpose, code string) error {
	if err := d.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"email": email, "purpose": purpose, "code": code})
	if err != nil {
		return errx.Wrap(err, "prepare email delivery", errx.TypeInternal)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.URL, bytes.NewReader(body))
	if err != nil {
		return errx.Wrap(err, "prepare email delivery", errx.TypeInternal)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.Token)
	client := http.Client{Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return errx.Wrap(err, "email delivery failed", errx.TypeExternal)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errx.External("email delivery rejected")
	}
	return nil
}
