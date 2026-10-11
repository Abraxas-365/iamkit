package iamclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/internal/transport"
)

// ── App audit logs ──
//
// The audit log holds events an environment's own applications emit about
// what their users did (invoice.paid, …): customer data, separate from
// IAMKit's event log (Events). An action must be registered
// (CreateAuditLogAction) before events can name it.

// AuditLogParty is the actor or a target of an audit log event.
type AuditLogParty struct {
	Type     string          `json:"type"`
	ID       string          `json:"id"`
	Name     string          `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// AuditLogContext is where the action came from.
type AuditLogContext struct {
	Location  string `json:"location,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// AuditLogInput is an event as an application emits it.
type AuditLogInput struct {
	OrganizationID string    `json:"organization_id"`
	Action         string    `json:"action"`
	OccurredAt     time.Time `json:"occurred_at"`
	// Version is optional; when given it must be the action's current one.
	Version  *int            `json:"version,omitempty"`
	Actor    AuditLogParty   `json:"actor"`
	Targets  []AuditLogParty `json:"targets"`
	Context  AuditLogContext `json:"context"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// AuditLogEvent is a stored event. Seq orders the log and is the paging
// cursor; ID is the public identifier.
type AuditLogEvent struct {
	Seq            int64           `json:"seq"`
	ID             string          `json:"id"`
	EnvironmentID  string          `json:"environment_id"`
	OrganizationID string          `json:"organization_id"`
	Action         string          `json:"action"`
	Version        int             `json:"version"`
	OccurredAt     time.Time       `json:"occurred_at"`
	Actor          AuditLogParty   `json:"actor"`
	Targets        []AuditLogParty `json:"targets"`
	Context        AuditLogContext `json:"context"`
	Metadata       json.RawMessage `json:"metadata"`
	CreatedAt      time.Time       `json:"created_at"`
}

// AuditLogReceipt answers an accepted event; a replay of an idempotent
// request answers the same receipt.
type AuditLogReceipt struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditLogFilter narrows the audit log. Set After (0 = the beginning) to
// read oldest first as a feed; otherwise events come newest first below
// Before (0 = the newest). OrganizationID is ignored by the organization
// administration routes (always the caller's organization).
type AuditLogFilter struct {
	Actions        []string
	ActorID        string
	ActorType      string
	TargetID       string
	TargetType     string
	OrganizationID string
	OccurredAfter  *time.Time
	OccurredBefore *time.Time
	After          *int64
	Before         int64
	// Limit is the page size of the list (export ignores it; at most 200).
	Limit int
}

// AuditLogPage is one page of events. With AuditLogFilter.After, pass Next
// as the next After (it stays put when nothing new arrived); otherwise
// pass it as Before, 0 meaning no older events.
type AuditLogPage struct {
	Items []AuditLogEvent `json:"items"`
	Next  int64           `json:"next"`
}

// Query encodes the filter as query parameters.
func (f AuditLogFilter) Query() url.Values {
	q := url.Values{}
	if len(f.Actions) > 0 {
		q["action"] = f.Actions
	}
	set := func(key, value string) {
		if value != "" {
			q[key] = []string{value}
		}
	}
	set("actor_id", f.ActorID)
	set("actor_type", f.ActorType)
	set("target_id", f.TargetID)
	set("target_type", f.TargetType)
	set("organization_id", f.OrganizationID)
	if f.OccurredAfter != nil {
		set("occurred_after", f.OccurredAfter.UTC().Format(time.RFC3339Nano))
	}
	if f.OccurredBefore != nil {
		set("occurred_before", f.OccurredBefore.UTC().Format(time.RFC3339Nano))
	}
	if f.After != nil {
		set("after", strconv.FormatInt(*f.After, 10))
	}
	if f.Before > 0 {
		set("before", strconv.FormatInt(f.Before, 10))
	}
	if f.Limit > 0 {
		set("limit", strconv.Itoa(f.Limit))
	}
	return q
}

// Export formats of ExportAuditLogs.
const (
	AuditLogFormatNDJSON = "ndjson"
	AuditLogFormatCSV    = "csv"
)

// ExportQuery is Query for an export: no page size, plus the format
// ("" = ndjson).
func (f AuditLogFilter) ExportQuery(format string) url.Values {
	f.Limit = 0
	q := f.Query()
	if format != "" {
		q.Set("format", format)
	}
	return q
}

// AuditLogAction is a registered action: the rules its events follow.
type AuditLogAction struct {
	ID            string         `json:"id"`
	EnvironmentID string         `json:"environment_id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	TargetTypes   []string       `json:"target_types"`
	Schema        AuditLogSchema `json:"schema"`
	// Version grows with every change of the target types or schemas.
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditLogSchema holds the optional JSON Schemas (draft 2020-12) of an
// action: the event's metadata, its actor's, and each target type's.
type AuditLogSchema struct {
	Metadata json.RawMessage            `json:"metadata,omitempty"`
	Actor    json.RawMessage            `json:"actor,omitempty"`
	Targets  map[string]json.RawMessage `json:"targets,omitempty"`
}

// AuditLogActionInput registers an action (name like "invoice.paid").
type AuditLogActionInput struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	TargetTypes []string       `json:"target_types"`
	Schema      AuditLogSchema `json:"schema"`
}

// AuditLogActionPatch updates an action; nil fields stay unchanged.
type AuditLogActionPatch struct {
	Description *string         `json:"description,omitempty"`
	TargetTypes *[]string       `json:"target_types,omitempty"`
	Schema      *AuditLogSchema `json:"schema,omitempty"`
}

// ── Log streams ──

// LogStreamConfig is a destination's configuration: Site/Service/Tags
// (datadog), URL/Index/Source/SourceType (splunk, https), Bucket/Region/
// Prefix/Endpoint/PathStyle/AccessKeyID (s3).
type LogStreamConfig struct {
	Site        string   `json:"site,omitempty"`
	Service     string   `json:"service,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	URL         string   `json:"url,omitempty"`
	Index       string   `json:"index,omitempty"`
	Source      string   `json:"source,omitempty"`
	SourceType  string   `json:"sourcetype,omitempty"`
	Bucket      string   `json:"bucket,omitempty"`
	Region      string   `json:"region,omitempty"`
	Prefix      string   `json:"prefix,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"`
	PathStyle   bool     `json:"path_style,omitempty"`
	AccessKeyID string   `json:"access_key_id,omitempty"`
}

// LogStream is a configured destination. The secret is never returned.
type LogStream struct {
	ID             string `json:"id"`
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id,omitempty"`
	Name           string `json:"name"`
	// Destination is datadog, splunk, s3 or https.
	Destination string          `json:"destination"`
	Config      LogStreamConfig `json:"config"`
	// Sources are events and/or audit_logs (an organization's stream
	// carries audit_logs only).
	Sources                 []string   `json:"sources"`
	SecretSet               bool       `json:"secret_set"`
	Active                  bool       `json:"active"`
	DisabledReason          string     `json:"disabled_reason,omitempty"`
	FailingSince            *time.Time `json:"failing_since,omitempty"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	Pending                 int        `json:"pending"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

// LogStreamInput creates a stream. Secret is the API key (datadog), HEC
// token (splunk) or secret access key (s3); https streams get a generated
// signing secret and refuse one. Sources default to both (organization
// streams: audit_logs). OrganizationID makes an environment-level create
// an organization's stream.
type LogStreamInput struct {
	OrganizationID string          `json:"organization_id,omitempty"`
	Name           string          `json:"name"`
	Destination    string          `json:"destination"`
	Config         LogStreamConfig `json:"config"`
	Sources        []string        `json:"sources,omitempty"`
	Secret         string          `json:"secret,omitempty"`
}

// LogStreamPatch updates a stream; nil fields stay unchanged. Config
// replaces the whole configuration; Active false pauses, true resumes.
type LogStreamPatch struct {
	Name    *string          `json:"name,omitempty"`
	Config  *LogStreamConfig `json:"config,omitempty"`
	Sources *[]string        `json:"sources,omitempty"`
	Secret  *string          `json:"secret,omitempty"`
	Active  *bool            `json:"active,omitempty"`
}

// LogStreamSecret answers a create or a rotation: the https signing
// secret is shown only now (empty for other destinations).
type LogStreamSecret struct {
	ID     string `json:"id"`
	Secret string `json:"secret,omitempty"`
}

// LogStreamTest is the outcome of a test record.
type LogStreamTest struct {
	Delivered bool   `json:"delivered"`
	Status    int    `json:"status"`
	Error     string `json:"error,omitempty"`
}

// LogStreamDelivery is one record sent (or being sent) to a stream.
type LogStreamDelivery struct {
	ID     int64  `json:"id"`
	Stream string `json:"stream_id"`
	// Source is events or audit_logs; Seq the record's id in it.
	Source         string     `json:"source"`
	Seq            int64      `json:"seq"`
	Batch          *int64     `json:"batch,omitempty"`
	Status         string     `json:"status"` // pending, delivered or failed
	Attempts       int        `json:"attempts"`
	NextAttemptAt  *time.Time `json:"next_attempt_at,omitempty"`
	ResponseStatus *int       `json:"response_status,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	QueuedAt       time.Time  `json:"queued_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// ── Management methods ──

// CreateAuditLogEvent emits one event. idempotencyKey (at most 255
// characters, "" for none) makes a retry answer the first receipt; the
// same key with another event is 409 IDEMPOTENCY_KEY_REUSED.
func (e Environment) CreateAuditLogEvent(ctx context.Context, event AuditLogInput, idempotencyKey string) (AuditLogReceipt, error) {
	var out AuditLogReceipt
	var headers []transport.Header
	if idempotencyKey != "" {
		headers = []transport.Header{{Key: "Idempotency-Key", Value: idempotencyKey}}
	}
	if event.Targets == nil {
		event.Targets = []AuditLogParty{}
	}
	err := e.client.doWith(ctx, "POST", e.path("audit-logs/events"), nil, headers, event, &out)
	return out, err
}

// AuditLogEvents reads one page of the audit log.
func (e Environment) AuditLogEvents(ctx context.Context, filter AuditLogFilter) (AuditLogPage, error) {
	var out AuditLogPage
	err := e.client.do(ctx, "GET", e.path("audit-logs/events"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []AuditLogEvent{}
	}
	return out, err
}

func (e Environment) AuditLogEvent(ctx context.Context, id string) (AuditLogEvent, error) {
	var out AuditLogEvent
	err := e.operation(ctx, "GET", []string{"audit-logs", "events", id}, nil, &out)
	return out, err
}

// ExportAuditLogEvents streams the matching events oldest first as
// AuditLogFormatNDJSON (default) or AuditLogFormatCSV. The caller closes
// the reader.
func (e Environment) ExportAuditLogEvents(ctx context.Context, filter AuditLogFilter, format string) (io.ReadCloser, error) {
	if !strings.HasPrefix(e.client.key, "ik_mgmt_") {
		return nil, fmt.Errorf("management credential required")
	}
	path := "/management/v1" + e.path("audit-logs/events/export") + "?" + filter.ExportQuery(format).Encode()
	return transport.Stream(e.client.http, ctx, e.client.baseURL+path, []transport.Header{{Key: "X-API-Key", Value: e.client.key}})
}

// DecodeAuditLogEvents reads an NDJSON export, calling fn per event.
func DecodeAuditLogEvents(r io.Reader, fn func(AuditLogEvent) error) error {
	dec := json.NewDecoder(r)
	for {
		var ev AuditLogEvent
		if err := dec.Decode(&ev); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
}

func (e Environment) AuditLogActions(ctx context.Context) ([]AuditLogAction, error) {
	var out struct {
		Items []AuditLogAction `json:"items"`
	}
	err := e.client.do(ctx, "GET", e.path("audit-logs/actions"), nil, nil, &out)
	if out.Items == nil {
		out.Items = []AuditLogAction{}
	}
	return out.Items, err
}

func (e Environment) AuditLogAction(ctx context.Context, id string) (AuditLogAction, error) {
	var out AuditLogAction
	err := e.operation(ctx, "GET", []string{"audit-logs", "actions", id}, nil, &out)
	return out, err
}

func (e Environment) CreateAuditLogAction(ctx context.Context, input AuditLogActionInput) (AuditLogAction, error) {
	var out AuditLogAction
	if input.TargetTypes == nil {
		input.TargetTypes = []string{}
	}
	err := e.client.do(ctx, "POST", e.path("audit-logs/actions"), nil, input, &out)
	return out, err
}

// UpdateAuditLogAction changes the description, target types or schemas;
// a change of the last two bumps the version.
func (e Environment) UpdateAuditLogAction(ctx context.Context, id string, patch AuditLogActionPatch) (AuditLogAction, error) {
	var out AuditLogAction
	err := e.operation(ctx, "PATCH", []string{"audit-logs", "actions", id}, patch, &out)
	return out, err
}

// DeleteAuditLogAction removes the action; emitted events keep its name.
func (e Environment) DeleteAuditLogAction(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"audit-logs", "actions", id}, nil, nil)
}

func (e Environment) LogStreams(ctx context.Context) ([]LogStream, error) {
	var out struct {
		Items []LogStream `json:"items"`
	}
	err := e.client.do(ctx, "GET", e.path("log-streams"), nil, nil, &out)
	if out.Items == nil {
		out.Items = []LogStream{}
	}
	return out.Items, err
}

func (e Environment) LogStream(ctx context.Context, id string) (LogStream, error) {
	var out LogStream
	err := e.operation(ctx, "GET", []string{"log-streams", id}, nil, &out)
	return out, err
}

// CreateLogStream registers a stream; an https stream's signing secret is
// in the answer, once.
func (e Environment) CreateLogStream(ctx context.Context, input LogStreamInput) (LogStreamSecret, error) {
	var out LogStreamSecret
	err := e.client.do(ctx, "POST", e.path("log-streams"), nil, input, &out)
	return out, err
}

func (e Environment) UpdateLogStream(ctx context.Context, id string, patch LogStreamPatch) (LogStream, error) {
	var out LogStream
	err := e.operation(ctx, "PATCH", []string{"log-streams", id}, patch, &out)
	return out, err
}

func (e Environment) DeleteLogStream(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"log-streams", id}, nil, nil)
}

// TestLogStream sends one synthetic record to the destination now.
func (e Environment) TestLogStream(ctx context.Context, id string) (LogStreamTest, error) {
	var out LogStreamTest
	err := e.operation(ctx, "POST", []string{"log-streams", id, "test"}, map[string]any{}, &out)
	return out, err
}

// EnableLogStream resumes a paused or failing stream.
func (e Environment) EnableLogStream(ctx context.Context, id string) (LogStream, error) {
	var out LogStream
	err := e.operation(ctx, "POST", []string{"log-streams", id, "enable"}, map[string]any{}, &out)
	return out, err
}

// RotateLogStreamSecret replaces an https stream's signing secret; the
// previous one keeps signing for 24 hours.
func (e Environment) RotateLogStreamSecret(ctx context.Context, id string) (LogStreamSecret, error) {
	var out LogStreamSecret
	err := e.operation(ctx, "POST", []string{"log-streams", id, "rotate-secret"}, map[string]any{}, &out)
	return out, err
}

// LogStreamDeliveries reads the first page of a stream's delivery log,
// newest first; status is pending, delivered, failed or "" for all.
func (e Environment) LogStreamDeliveries(ctx context.Context, id, status string) ([]LogStreamDelivery, error) {
	if err := safeSegment(id); err != nil {
		return nil, err
	}
	var query url.Values
	if status != "" {
		query = url.Values{"status": {status}}
	}
	var out struct {
		Items []LogStreamDelivery `json:"items"`
	}
	err := e.client.do(ctx, "GET", e.path("log-streams/"+id+"/deliveries"), query, nil, &out)
	if out.Items == nil {
		out.Items = []LogStreamDelivery{}
	}
	return out.Items, err
}

// RetryLogStreamDelivery queues a failed delivery's batch again.
func (e Environment) RetryLogStreamDelivery(ctx context.Context, id string, delivery int64) error {
	return e.operation(ctx, "POST", []string{"log-streams", id, "deliveries", strconv.FormatInt(delivery, 10), "retry"}, map[string]any{}, nil)
}
