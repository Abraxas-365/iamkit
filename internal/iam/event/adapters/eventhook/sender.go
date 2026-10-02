// Package eventhook posts event webhooks signed per Standard Webhooks
// (https://www.standardwebhooks.com): webhook-id, webhook-timestamp and
// webhook-signature "v1,<base64 HMAC-SHA256>" over id.timestamp.body, the
// key being the base64 part of the subscription's whsec_ secret. It dials
// operator-supplied URLs through the guarded transport (public addresses
// only) unless a test replaces it.
package eventhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// Sender posts webhooks; a nil Transport uses the guarded one.
type Sender struct {
	Transport http.RoundTripper
	now       func() time.Time
}

var _ event.Sender = Sender{}

var guarded = sync.OnceValue(func() http.RoundTripper {
	return &http.Transport{
		DialContext:           netx.GuardedDialer().DialContext,
		TLSHandshakeTimeout:   config.ExternalHTTPTimeout,
		ResponseHeaderTimeout: config.ExternalHTTPTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
	}
})

// Body is the JSON a webhook carries: the event as the log serves it, its
// data replaced by {"truncated": true} past config.EventWebhookMaxPayload.
func Body(e event.Event) ([]byte, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(body) <= config.EventWebhookMaxPayload {
		return body, nil
	}
	e.Data = json.RawMessage(`{"truncated":true}`)
	return json.Marshal(e)
}

func (s Sender) Send(ctx context.Context, m event.Outbound) event.Outcome {
	body, err := Body(m.Event)
	if err != nil {
		return event.Outcome{Error: "encode event: " + err.Error()}
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	timestamp := strconv.FormatInt(now().Unix(), 10)
	signature, err := Sign(m.Secrets, m.ID, timestamp, body)
	if err != nil {
		return event.Outcome{Error: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(body))
	if err != nil {
		return event.Outcome{Error: "invalid URL"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IAMKit-Webhooks/1")
	req.Header.Set("webhook-id", m.ID)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", signature)
	transport := s.Transport
	if transport == nil {
		transport = guarded()
	}
	client := http.Client{Transport: telemetry.Transport(transport), Timeout: config.ExternalHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return event.Outcome{Error: reason(err)}
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	out := event.Outcome{Status: res.StatusCode}
	if !out.OK() {
		out.Error = "endpoint answered " + strconv.Itoa(res.StatusCode)
	}
	return out
}

// reason is a short, operator-facing cause (no internal addresses).
func reason(err error) string {
	var timeout interface{ Timeout() bool }
	switch {
	case errors.Is(err, netx.ErrNotPublic):
		return "the URL does not resolve to a public address"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timed out"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "host not found"
	}
	return "endpoint unreachable"
}

// Sign is the webhook-signature header: one "v1,<signature>" per secret,
// space-separated (several during a rotation's overlap).
func Sign(secrets []string, id, timestamp string, body []byte) (string, error) {
	parts := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		key, err := Key(secret)
		if err != nil {
			return "", err
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id + "." + timestamp + "."))
		mac.Write(body)
		parts = append(parts, "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	return strings.Join(parts, " "), nil
}

// Key decodes a whsec_ secret into its HMAC key.
func Key(secret string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, event.SecretPrefix))
	if err != nil || len(key) == 0 {
		return nil, errx.Internal("malformed webhook secret")
	}
	return key, nil
}

// Secrets generates whsec_ secrets with 32 random bytes.
type Secrets struct{}

var _ event.Secrets = Secrets{}

func (Secrets) Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errx.Wrap(err, "secret generation failed", errx.TypeInternal)
	}
	return event.SecretPrefix + base64.StdEncoding.EncodeToString(b), nil
}
