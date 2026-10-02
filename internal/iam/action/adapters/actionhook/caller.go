// Package actionhook calls action targets: a POST signed per Standard
// Webhooks (webhook-id, webhook-timestamp, webhook-signature "v1,<base64
// HMAC-SHA256>" over id.timestamp.body; key = base64 part of the whsec_
// secret, one signature per live secret), bounded by the target's timeout
// and config.ActionMaxResponse. It dials operator-supplied URLs through the
// guarded transport (public addresses only) unless a test replaces it.
package actionhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// Caller posts hooks; a nil Transport uses the guarded one.
type Caller struct {
	Transport http.RoundTripper
}

var _ action.Caller = Caller{}

var guarded = sync.OnceValue(func() http.RoundTripper {
	return &http.Transport{
		DialContext:           netx.GuardedDialer().DialContext,
		TLSHandshakeTimeout:   config.ActionMaxTimeout,
		ResponseHeaderTimeout: config.ActionMaxTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
	}
})

func (c Caller) Call(ctx context.Context, m action.Outbound) action.Answer {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature, err := Sign(m.Secrets, m.ID, timestamp, m.Body)
	if err != nil {
		return action.Answer{Error: "the target secret is malformed"}
	}
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(m.Body))
	if err != nil {
		return action.Answer{Error: "invalid URL"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IAMKit-Actions/1")
	req.Header.Set("webhook-id", m.ID)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", signature)
	transport := c.Transport
	if transport == nil {
		transport = guarded()
	}
	client := http.Client{Transport: telemetry.Transport(transport),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return action.Answer{Error: reason(err)}
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, config.ActionMaxResponse+1))
	if err != nil {
		return action.Answer{Status: res.StatusCode, Error: reason(err)}
	}
	if len(body) > config.ActionMaxResponse {
		return action.Answer{Status: res.StatusCode, Error: "the response is larger than 64 KiB"}
	}
	return action.Answer{Status: res.StatusCode, Body: body}
}

// reason is a short, operator-facing cause (no internal addresses).
func reason(err error) string {
	var timeout interface{ Timeout() bool }
	switch {
	case errors.Is(err, netx.ErrNotPublic):
		return "the URL does not resolve to a public address"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return "timed out"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "host not found"
	}
	return "endpoint unreachable"
}

// Sign is the webhook-signature header: one "v1,<signature>" per secret.
func Sign(secrets []string, id, timestamp string, body []byte) (string, error) {
	parts := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, action.SecretPrefix))
		if err != nil || len(key) == 0 {
			return "", errx.Internal("malformed action secret")
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id + "." + timestamp + "."))
		mac.Write(body)
		parts = append(parts, "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	return strings.Join(parts, " "), nil
}

// Secrets generates whsec_ secrets with 32 random bytes.
type Secrets struct{}

var _ action.Secrets = Secrets{}

func (Secrets) Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errx.Wrap(err, "secret generation failed", errx.TypeInternal)
	}
	return action.SecretPrefix + base64.StdEncoding.EncodeToString(b), nil
}
