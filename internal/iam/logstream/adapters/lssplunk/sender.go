// Package lssplunk sends log stream batches to a Splunk HTTP Event
// Collector (POST <url>/services/collector/event, "Authorization: Splunk
// <token>", concatenated JSON event objects).
package lssplunk

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

// Sender posts to Splunk; a nil Transport uses the guarded one.
type Sender struct {
	Transport http.RoundTripper
}

var _ logstream.Sender = Sender{}

// DefaultSource is the HEC source when the stream sets none.
const DefaultSource = "iamkit"

type hecEvent struct {
	Time       float64         `json:"time"`
	Event      json.RawMessage `json:"event"`
	Index      string          `json:"index,omitempty"`
	Source     string          `json:"source,omitempty"`
	SourceType string          `json:"sourcetype,omitempty"`
}

// Body is the HEC payload: one JSON object per record, concatenated.
func Body(c logstream.Config, records []logstream.Record, payloads []json.RawMessage) ([]byte, error) {
	source := c.Source
	if source == "" {
		source = DefaultSource
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i, p := range payloads {
		at := records[i].At
		if err := enc.Encode(hecEvent{Time: float64(at.UnixMilli()) / 1000, Event: p, Index: c.Index, Source: source, SourceType: c.SourceType}); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// EventURL is the collector endpoint of the configured URL.
func EventURL(base string) string {
	return strings.TrimSuffix(base, "/") + "/services/collector/event"
}

func (s Sender) Send(ctx context.Context, b logstream.Outbound) logstream.Outcome {
	if len(b.Secrets) == 0 {
		return logstream.OutcomeOf(0, "the HEC token is missing")
	}
	body, err := Body(b.Config, b.Records, b.Payloads())
	if err != nil {
		return logstream.OutcomeOf(0, "encode batch")
	}
	req, err := http.NewRequest(http.MethodPost, EventURL(b.Config.URL), bytes.NewReader(body))
	if err != nil {
		return logstream.OutcomeOf(0, "invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IAMKit-LogStreams/1")
	req.Header.Set("Authorization", "Splunk "+b.Secrets[0])
	status, text := netx.Do(ctx, s.Transport, req, config.LogStreamTimeout)
	return logstream.OutcomeOf(status, text)
}
