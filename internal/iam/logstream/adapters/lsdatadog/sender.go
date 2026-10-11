// Package lsdatadog sends log stream batches to Datadog's HTTP log intake
// (POST https://http-intake.logs.<site>/api/v2/logs, DD-API-KEY header).
package lsdatadog

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/netx"
)

// Sender posts to Datadog; a nil Transport uses the guarded one.
type Sender struct {
	Transport http.RoundTripper
	// URL overrides the intake URL (tests).
	URL string
}

var _ logstream.Sender = Sender{}

// Source is the ddsource of every log.
const Source = "iamkit"

// Body is the JSON array Datadog receives: each record's payload fields
// plus ddsource, ddtags, service and a short message (the event type or
// audit action).
func Body(c logstream.Config, payloads []json.RawMessage) ([]byte, error) {
	entries := make([]map[string]any, 0, len(payloads))
	for _, p := range payloads {
		entry := map[string]any{}
		if err := json.Unmarshal(p, &entry); err != nil {
			return nil, err
		}
		message, _ := entry["type"].(string)
		if message == "" {
			message, _ = entry["action"].(string)
		}
		entry["message"] = message
		entry["ddsource"] = Source
		if c.Service != "" {
			entry["service"] = c.Service
		}
		if len(c.Tags) > 0 {
			entry["ddtags"] = strings.Join(c.Tags, ",")
		}
		entries = append(entries, entry)
	}
	return json.Marshal(entries)
}

func (s Sender) Send(ctx context.Context, b logstream.Outbound) logstream.Outcome {
	if len(b.Secrets) == 0 {
		return logstream.OutcomeOf(0, "the API key is missing")
	}
	body, err := Body(b.Config, b.Payloads())
	if err != nil {
		return logstream.OutcomeOf(0, "encode batch")
	}
	url := s.URL
	if url == "" {
		url = b.Config.IntakeURL()
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return logstream.OutcomeOf(0, "invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IAMKit-LogStreams/1")
	req.Header.Set("DD-API-KEY", b.Secrets[0])
	status, text := netx.Do(ctx, s.Transport, req, config.LogStreamTimeout)
	return logstream.OutcomeOf(status, text)
}
