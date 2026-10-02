// Package webhook verifies IAMKit event webhooks on the receiving side.
//
// IAMKit signs every request per Standard Webhooks
// (https://www.standardwebhooks.com): headers webhook-id,
// webhook-timestamp and webhook-signature ("v1,<base64 HMAC-SHA256>" of
// id.timestamp.body, several space-separated while a secret rotation
// overlaps). Any Standard Webhooks library works; this one has no
// dependencies:
//
//	func handle(w http.ResponseWriter, r *http.Request) {
//		event, err := webhook.Verify(secret, r)
//		if err != nil {
//			http.Error(w, "bad signature", http.StatusUnauthorized)
//			return
//		}
//		// Deliveries are at least once: dedupe on r.Header.Get("webhook-id")
//		// or event.ID.
//		w.WriteHeader(http.StatusNoContent)
//	}
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Tolerance is how far webhook-timestamp may be from now.
const Tolerance = 5 * time.Minute

// MaxBody caps the request body read by Verify.
const MaxBody = 1 << 20

// Event is the JSON body of an event webhook (an entry of the event log).
// Data is {"truncated": true} when the original exceeded 64 KiB: read the
// event log for it. Test events have type "webhook.test".
type Event struct {
	ID             int64           `json:"id"`
	EnvironmentID  string          `json:"environment_id"`
	Type           string          `json:"type"`
	Actor          Party           `json:"actor"`
	Subject        Party           `json:"subject"`
	OrganizationID string          `json:"organization_id,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at"`
}

// Party is an event's actor or subject.
type Party struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

var (
	// ErrSignature means no signature matched the secret.
	ErrSignature = errors.New("webhook: signature mismatch")
	// ErrTimestamp means the timestamp is missing or outside Tolerance.
	ErrTimestamp = errors.New("webhook: timestamp outside tolerance")
	// ErrSecret means the secret is not a whsec_ secret.
	ErrSecret = errors.New("webhook: malformed secret")
)

// Verify reads r's body, checks its signature against secret (whsec_…)
// and decodes the event.
func Verify(secret string, r *http.Request) (Event, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody))
	if err != nil {
		return Event{}, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := VerifyBody(secret, r.Header, body, time.Now()); err != nil {
		return Event{}, err
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil {
		return Event{}, err
	}
	return e, nil
}

// VerifyBody checks the signature headers of body at now.
func VerifyBody(secret string, header http.Header, body []byte, now time.Time) error {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) == 0 {
		return ErrSecret
	}
	id, timestamp := header.Get("webhook-id"), header.Get("webhook-timestamp")
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || math.Abs(now.Sub(time.Unix(unix, 0)).Seconds()) > Tolerance.Seconds() {
		return ErrTimestamp
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, sig := range strings.Fields(header.Get("webhook-signature")) {
		version, value, ok := strings.Cut(sig, ",")
		if !ok || version != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(value)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return ErrSignature
}
