package logstream

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// RecordPruned is the last_error of a queued record that was deleted by
// its retention job before it could be sent.
const RecordPruned = "the record no longer exists"

// BacklogExpired is the last_error of a record that waited on a disabled
// stream past the delivery retention.
const BacklogExpired = "the stream was disabled for too long"

// SecretPrefix starts a generated https signing secret (Standard Webhooks:
// the rest is the base64 HMAC key).
const SecretPrefix = "whsec_"

// ObjectContentType and ObjectEncoding describe an s3 batch object.
const (
	ObjectContentType = "application/x-ndjson"
	ObjectEncoding    = "gzip"
)

// Delivery is one record queued for one stream.
type Delivery struct {
	ID     int64                `json:"id"`
	Stream identity.LogStreamID `json:"stream_id"`
	Source string               `json:"source"`
	// Seq is the record's id in its source (events.id, or the audit log
	// sequence).
	Seq int64 `json:"seq"`
	// Batch groups the records sent together: the id of the batch's first
	// delivery; unset while the record waits for its first attempt.
	Batch          *int64     `json:"batch,omitempty"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	NextAttemptAt  *time.Time `json:"next_attempt_at,omitempty"`
	ResponseStatus *int       `json:"response_status,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	QueuedAt       time.Time  `json:"queued_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// DeliveryFilter narrows a stream's delivery log; zero matches all.
type DeliveryFilter struct {
	Status string
}

func (f DeliveryFilter) Validate() error {
	switch f.Status {
	case "", DeliveryPending, DeliveryDelivered, DeliveryFailed:
		return nil
	}
	return errx.Validation("status must be pending, delivered or failed")
}

// Record is one event or audit log event ready to send.
type Record struct {
	Source string
	Seq    int64
	// At is when it happened (events.created_at, audit occurred_at).
	At time.Time
	// Fields is the record's JSON object without source, environment_id
	// and occurred_at.
	Fields json.RawMessage
}

// Payload is the JSON object a destination receives for the record:
//
//	{"source":"events","environment_id":"…","occurred_at":"…", …fields}
func (r Record) Payload(environment identity.EnvironmentID) json.RawMessage {
	head, _ := json.Marshal(struct {
		Source      string `json:"source"`
		Environment string `json:"environment_id"`
		OccurredAt  string `json:"occurred_at"`
	}{r.Source, environment.String(), r.At.UTC().Format(time.RFC3339Nano)})
	fields := strings.TrimSpace(string(r.Fields))
	if len(fields) < 2 || fields[0] != '{' || fields == "{}" {
		return head
	}
	return json.RawMessage(string(head[:len(head)-1]) + "," + fields[1:])
}

// Batch is a claimed batch ready to send: a stream's oldest pending
// records, sent together and, on failure, retried as the same set.
type Batch struct {
	Stream      identity.LogStreamID
	Environment identity.EnvironmentID
	Destination string
	Config      Config
	// Sealed are the stream's sealed secrets: the current one, then the
	// previous one while it still signs (https).
	Sealed []string
	// ID is the batch's first delivery id, stable across retries.
	ID int64
	// At is when the batch's first record was queued (the s3 key's hour).
	At time.Time
	// Rows are the deliveries being sent (records pruned meanwhile were
	// already marked failed).
	Rows         []int64
	Attempts     int
	FirstAttempt time.Time
	Records      []Record
}

// Outbound is a batch with opened secrets, for a Sender.
type Outbound struct {
	Stream      identity.LogStreamID
	Environment identity.EnvironmentID
	Destination string
	Config      Config
	// Secrets: the API key, HEC token or secret access key; for https the
	// whsec_ secrets that sign.
	Secrets []string
	// Batch is stable across retries (webhook-id, object name).
	Batch   int64
	At      time.Time
	Records []Record
	// Test names the object of a test delivery (s3) so it never collides
	// with a batch.
	Test bool
}

// Payloads is every record's payload, in order.
func (o Outbound) Payloads() []json.RawMessage {
	out := make([]json.RawMessage, len(o.Records))
	for i, r := range o.Records {
		out[i] = r.Payload(o.Environment)
	}
	return out
}

// Outcome is what a destination answered.
type Outcome struct {
	// Status is the HTTP status, 0 when no response arrived.
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

// OK reports a delivered batch: a 2xx answer (or, for s3, a stored object,
// which has no status) without error.
func (o Outcome) OK() bool {
	return o.Error == "" && (o.Status == 0 || (o.Status >= 200 && o.Status < 300))
}

// OutcomeOf truncates an error text to what the delivery log keeps.
func OutcomeOf(status int, text string) Outcome {
	if len(text) > MaxError {
		text = strings.ToValidUTF8(text[:MaxError], "") + "…"
	}
	return Outcome{Status: status, Error: text}
}

// MaxError caps a delivery's last_error.
const MaxError = 300

// ObjectKey is where an s3 batch lands:
//
//	<prefix>/<yyyy>/<mm>/<dd>/<HH>/<stream>-<batch>.ndjson.gz
//
// in UTC at the hour its first record was queued. Retrying a batch writes
// the same key, so a second Put is a Conflict and counts as delivered.
func ObjectKey(prefix string, stream identity.LogStreamID, batch int64, at time.Time) string {
	return objectKey(prefix, stream, fmt.Sprint(batch), at)
}

// TestObjectKey is the key of a test delivery's object (distinct per call).
func TestObjectKey(prefix string, stream identity.LogStreamID, at time.Time) string {
	return objectKey(prefix, stream, fmt.Sprintf("test-%d", at.UnixNano()), at)
}

func objectKey(prefix string, stream identity.LogStreamID, name string, at time.Time) string {
	at = at.UTC()
	key := fmt.Sprintf("%04d/%02d/%02d/%02d/%s-%s.ndjson.gz", at.Year(), int(at.Month()), at.Day(), at.Hour(), stream, name)
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

// TestRecord is the synthetic record a test delivery sends.
func TestRecord(stream Stream, now time.Time) Record {
	source := stream.Sources[0]
	fields := fmt.Sprintf(`{"id":0,"type":"log_stream.test","actor":{"kind":"system"},"subject":{"kind":"log_stream","id":%q},"data":{}}`, stream.ID.String())
	if source == SourceAuditLogs {
		org := ""
		if stream.Organization != nil {
			org = stream.Organization.String()
		}
		fields = fmt.Sprintf(`{"id":"00000000-0000-0000-0000-000000000000","action":"log_stream.test","version":1,"organization_id":%q,"actor":{"type":"system","id":"iamkit"},"targets":[],"context":{},"metadata":{}}`, org)
	}
	return Record{Source: source, At: now.UTC(), Fields: json.RawMessage(fields)}
}
