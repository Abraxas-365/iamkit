package authmail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// WebhookDelivery delegates mail delivery to a trusted HTTPS service (HTTP
// only on loopback). It sends
// no management credentials and refuses redirects. The service receives the
// recipient, purpose and one-time code or invitation token, and must treat
// them as secrets.
type WebhookDelivery struct{ URL, Token string }

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
	client := http.Client{Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e := errx.Wrap(err, "email delivery failed", errx.TypeExternal)
		e.Code = authentication.CodeDeliveryUnreachable
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			e.Code = authentication.CodeDeliveryTimeout
		}
		return e
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return authentication.DeliveryRejected(res.StatusCode)
	}
	return nil
}
