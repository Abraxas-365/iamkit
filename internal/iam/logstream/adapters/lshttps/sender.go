// Package lshttps sends log stream batches to an HTTPS endpoint signed per
// Standard Webhooks (https://www.standardwebhooks.com): webhook-id,
// webhook-timestamp and webhook-signature "v1,<base64 HMAC-SHA256>" over
// id.timestamp.body, one signature per live secret (the current one and,
// during a rotation's overlap, the previous one). The body is a JSON array
// of the batch's record payloads.
package lshttps

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/netx"
)

// Sender posts signed batches; a nil Transport uses the guarded one.
type Sender struct {
	Transport http.RoundTripper
	now       func() time.Time
}

var _ logstream.Sender = Sender{}

// MessageID is the webhook-id: stable across a batch's retries.
func MessageID(b logstream.Outbound) string {
	if b.Test {
		return "msg_ls_test_" + strconv.FormatInt(b.At.UnixNano(), 36)
	}
	return "msg_ls_" + strconv.FormatInt(b.Batch, 10)
}

func (s Sender) Send(ctx context.Context, b logstream.Outbound) logstream.Outcome {
	payloads := b.Payloads()
	if payloads == nil {
		payloads = []json.RawMessage{}
	}
	body, err := json.Marshal(payloads)
	if err != nil {
		return logstream.OutcomeOf(0, "encode batch")
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	timestamp := strconv.FormatInt(now().Unix(), 10)
	id := MessageID(b)
	signature, err := Sign(b.Secrets, id, timestamp, body)
	if err != nil {
		return logstream.OutcomeOf(0, "the signing secret is malformed")
	}
	req, err := http.NewRequest(http.MethodPost, b.Config.URL, bytes.NewReader(body))
	if err != nil {
		return logstream.OutcomeOf(0, "invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IAMKit-LogStreams/1")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", signature)
	status, text := netx.Do(ctx, s.Transport, req, config.LogStreamTimeout)
	return logstream.OutcomeOf(status, text)
}

// Sign is the webhook-signature header: one "v1,<signature>" per secret,
// space-separated.
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
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, logstream.SecretPrefix))
	if err != nil || len(key) == 0 {
		return nil, errx.Internal("malformed signing secret")
	}
	return key, nil
}

// Secrets generates whsec_ secrets with 32 random bytes.
type Secrets struct{}

var _ logstream.Secrets = Secrets{}

func (Secrets) Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errx.Wrap(err, "secret generation failed", errx.TypeInternal)
	}
	return logstream.SecretPrefix + base64.StdEncoding.EncodeToString(b), nil
}
