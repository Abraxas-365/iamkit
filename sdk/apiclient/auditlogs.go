package apiclient

import (
	"context"
	"io"
	"net/url"
	"strconv"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/Abraxas-365/iamkit/sdk/iamclient"
	"github.com/Abraxas-365/iamkit/sdk/internal/transport"
)

// App audit logs and log streams (see iamclient for the types). Reads need
// iam:audit-logs:read, emitting iam:audit-logs:write, changes to actions
// and streams iam:audit-logs:manage.

// CreateAuditLogEvent emits one event. idempotencyKey (at most 255
// characters, "" for none) makes a retry answer the first receipt.
func (e Environment) CreateAuditLogEvent(ctx context.Context, event AuditLogInput, idempotencyKey string) (AuditLogReceipt, error) {
	var out AuditLogReceipt
	var headers []transport.Header
	if idempotencyKey != "" {
		headers = []transport.Header{{Key: "Idempotency-Key", Value: idempotencyKey}}
	}
	if event.Targets == nil {
		event.Targets = []AuditLogParty{}
	}
	err := e.client.doWith(ctx, "POST", e.path("audit-logs", "events"), nil, headers, event, &out)
	return out, err
}

// AuditLogEvents reads one page of the audit log (filters and cursor).
func (e Environment) AuditLogEvents(ctx context.Context, filter AuditLogFilter) (AuditLogPage, error) {
	return auditLogPage(ctx, e.client, e.path("audit-logs", "events"), filter)
}

func auditLogPage(ctx context.Context, c *Client, path string, filter AuditLogFilter) (AuditLogPage, error) {
	var out AuditLogPage
	err := c.do(ctx, "GET", path, filter.Query(), nil, &out)
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
// iamclient.AuditLogFormatNDJSON (default) or AuditLogFormatCSV. The
// caller closes the reader; DecodeAuditLogEvents reads NDJSON.
func (e Environment) ExportAuditLogEvents(ctx context.Context, filter AuditLogFilter, format string) (io.ReadCloser, error) {
	return exportAuditLogs(ctx, e.client, e.path("audit-logs", "events", "export"), filter, format)
}

func exportAuditLogs(ctx context.Context, c *Client, path string, filter AuditLogFilter, format string) (io.ReadCloser, error) {
	if c.token == "" {
		return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "bearer token required", HTTPStatus: 401}
	}
	return transport.Stream(c.http, ctx, c.baseURL+"/api/v1"+path+"?"+filter.ExportQuery(format).Encode(),
		[]transport.Header{{Key: "Authorization", Value: "Bearer " + c.token}})
}

// DecodeAuditLogEvents reads an NDJSON export, calling fn per event.
func DecodeAuditLogEvents(r io.Reader, fn func(AuditLogEvent) error) error {
	return iamclient.DecodeAuditLogEvents(r, fn)
}

func (e Environment) AuditLogActions(ctx context.Context) ([]AuditLogAction, error) {
	var out struct {
		Items []AuditLogAction `json:"items"`
	}
	err := e.client.Do(ctx, "GET", e.path("audit-logs", "actions"), nil, &out)
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
	err := e.client.Do(ctx, "POST", e.path("audit-logs", "actions"), input, &out)
	return out, err
}

// UpdateAuditLogAction changes the description, target types or schemas.
func (e Environment) UpdateAuditLogAction(ctx context.Context, id string, patch AuditLogActionPatch) (AuditLogAction, error) {
	var out AuditLogAction
	err := e.operation(ctx, "PATCH", []string{"audit-logs", "actions", id}, patch, &out)
	return out, err
}

func (e Environment) DeleteAuditLogAction(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"audit-logs", "actions", id}, nil, nil)
}

func (e Environment) LogStreams(ctx context.Context) ([]LogStream, error) {
	return logStreams(ctx, e.client, e.path("log-streams"))
}

func logStreams(ctx context.Context, c *Client, path string) ([]LogStream, error) {
	var out struct {
		Items []LogStream `json:"items"`
	}
	err := c.Do(ctx, "GET", path, nil, &out)
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
	err := e.client.Do(ctx, "POST", e.path("log-streams"), input, &out)
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

// RotateLogStreamSecret replaces an https stream's signing secret.
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
	return logStreamDeliveries(ctx, e.client, e.path("log-streams", id, "deliveries"), status)
}

func logStreamDeliveries(ctx context.Context, c *Client, path, status string) ([]LogStreamDelivery, error) {
	var query url.Values
	if status != "" {
		query = url.Values{"status": {status}}
	}
	return first[LogStreamDelivery](ctx, c, path, query)
}

// RetryLogStreamDelivery queues a failed delivery's batch again.
func (e Environment) RetryLogStreamDelivery(ctx context.Context, id string, delivery int64) error {
	return e.operation(ctx, "POST", []string{"log-streams", id, "deliveries", strconv.FormatInt(delivery, 10), "retry"}, map[string]any{}, nil)
}

// ── Organization administration ──
//
// An organization's administrators read their own organization's audit log
// (iam:org:audit:read) and manage its log streams (iam:org:log-streams:write;
// a setup link with the log_streams intent holds that, not the audit read).
// Streams carry audit_logs only; the organization is always the caller's.

// AuditLogEvents reads one page of the organization's audit log
// (OrganizationID of the filter is ignored).
func (a OrgAdmin) AuditLogEvents(ctx context.Context, filter AuditLogFilter) (AuditLogPage, error) {
	filter.OrganizationID = ""
	return auditLogPage(ctx, a.env.client, a.path("audit-logs"), filter)
}

// ExportAuditLogEvents streams the organization's events oldest first;
// the caller closes the reader.
func (a OrgAdmin) ExportAuditLogEvents(ctx context.Context, filter AuditLogFilter, format string) (io.ReadCloser, error) {
	filter.OrganizationID = ""
	return exportAuditLogs(ctx, a.env.client, a.path("audit-logs", "export"), filter, format)
}

func (a OrgAdmin) LogStreams(ctx context.Context) ([]LogStream, error) {
	return logStreams(ctx, a.env.client, a.path("log-streams"))
}

func (a OrgAdmin) stream(ctx context.Context, method string, input, output any, parts ...string) error {
	if err := safeSegment(parts[0]); err != nil {
		return err
	}
	return a.env.client.Do(ctx, method, a.path(append([]string{"log-streams"}, parts...)...), input, output)
}

func (a OrgAdmin) LogStream(ctx context.Context, id string) (LogStream, error) {
	var out LogStream
	err := a.stream(ctx, "GET", nil, &out, id)
	return out, err
}

// CreateLogStream registers a stream (sources are always audit_logs); an
// https stream's signing secret is in the answer, once.
func (a OrgAdmin) CreateLogStream(ctx context.Context, input LogStreamInput) (LogStreamSecret, error) {
	var out LogStreamSecret
	err := a.env.client.Do(ctx, "POST", a.path("log-streams"), input, &out)
	return out, err
}

func (a OrgAdmin) UpdateLogStream(ctx context.Context, id string, patch LogStreamPatch) (LogStream, error) {
	var out LogStream
	err := a.stream(ctx, "PATCH", patch, &out, id)
	return out, err
}

func (a OrgAdmin) DeleteLogStream(ctx context.Context, id string) error {
	return a.stream(ctx, "DELETE", nil, nil, id)
}

func (a OrgAdmin) TestLogStream(ctx context.Context, id string) (LogStreamTest, error) {
	var out LogStreamTest
	err := a.stream(ctx, "POST", map[string]any{}, &out, id, "test")
	return out, err
}

func (a OrgAdmin) EnableLogStream(ctx context.Context, id string) (LogStream, error) {
	var out LogStream
	err := a.stream(ctx, "POST", map[string]any{}, &out, id, "enable")
	return out, err
}

func (a OrgAdmin) RotateLogStreamSecret(ctx context.Context, id string) (LogStreamSecret, error) {
	var out LogStreamSecret
	err := a.stream(ctx, "POST", map[string]any{}, &out, id, "rotate-secret")
	return out, err
}

func (a OrgAdmin) LogStreamDeliveries(ctx context.Context, id, status string) ([]LogStreamDelivery, error) {
	if err := safeSegment(id); err != nil {
		return nil, err
	}
	return logStreamDeliveries(ctx, a.env.client, a.path("log-streams", id, "deliveries"), status)
}

func (a OrgAdmin) RetryLogStreamDelivery(ctx context.Context, id string, delivery int64) error {
	return a.stream(ctx, "POST", map[string]any{}, nil, id, "deliveries", strconv.FormatInt(delivery, 10), "retry")
}
