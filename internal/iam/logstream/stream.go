// Package logstream delivers IAMKit's event log and the applications' audit
// log events to a customer's SIEM or object storage: Datadog, Splunk (HEC),
// S3 (and S3-compatible servers) and a generic signed HTTPS endpoint.
//
// A stream's records are queued for it in the record's own transaction
// (triggers queue_log_stream_events / queue_log_stream_audit on the
// log_stream_deliveries outbox). A worker sends a stream's oldest pending
// rows as one batch, in order, at least once; retries, backoff and
// disabling follow the event webhooks (event.DeliveryRetryAfter,
// config.EventWebhook*).
package logstream

import (
	"strings"
	"time"
	"unicode"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Audit actions (event.Classify maps them to log_stream.* events).
const (
	ActionCreate         = "log_stream.create"
	ActionUpdate         = "log_stream.update"
	ActionDelete         = "log_stream.delete"
	ActionRotateSecret   = "log_stream.rotate_secret"
	ActionRetryDelivery  = "log_stream.retry_delivery"
	ActionDisableFailing = "log_stream.disable"
)

// Destinations.
const (
	DestinationDatadog = "datadog"
	DestinationSplunk  = "splunk"
	DestinationS3      = "s3"
	DestinationHTTPS   = "https"
)

// Destinations lists every destination.
var Destinations = []string{DestinationDatadog, DestinationSplunk, DestinationS3, DestinationHTTPS}

// Sources: IAMKit's own event log and the applications' audit log events.
const (
	SourceEvents    = "events"
	SourceAuditLogs = "audit_logs"
)

// Limits.
const (
	// MaxStreams caps an environment's own streams (organization_id NULL).
	MaxStreams = 10
	// MaxOrganizationStreams caps one organization's streams.
	MaxOrganizationStreams = 5
	// MaxSecret caps an API key, HEC token or secret access key.
	MaxSecret = 512
)

// DisabledFailing is the disabled_reason of a stream the worker turned off
// after failing for config.EventWebhookDisableAfter.
const DisabledFailing = "failing"

// Delivery statuses.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// Scope is the set of streams a caller may touch: every stream of an
// environment (operators), or only one organization's (an organization
// administrator). Every repository query filters by it in SQL.
type Scope struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	// Only restricts the scope to Organization. A zero Organization with
	// Only set matches nothing.
	Only bool
}

// EnvironmentScope is every stream of an environment.
func EnvironmentScope(environment identity.EnvironmentID) Scope {
	return Scope{Environment: environment}
}

// OrganizationScope is one organization's streams.
func OrganizationScope(environment identity.EnvironmentID, organization identity.OrganizationID) Scope {
	return Scope{Environment: environment, Organization: organization, Only: true}
}

// Mutation is an audited stream change.
type Mutation struct {
	Scope
	Actor  string
	Action string
	// Target is the stream id; the service fills it.
	Target string
}

// Stream is a configured destination.
type Stream struct {
	ID          identity.LogStreamID   `json:"id"`
	Environment identity.EnvironmentID `json:"environment_id"`
	// Organization is set for an organization's stream (audit logs of that
	// organization only), nil for an environment stream.
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	Name         string                   `json:"name"`
	Destination  string                   `json:"destination"`
	Config       Config                   `json:"config"`
	Sources      []string                 `json:"sources"`
	// SecretSet is always true: the secret is never returned.
	SecretSet bool `json:"secret_set"`
	Active    bool `json:"active"`
	// DisabledReason is "failing" when the worker turned it off.
	DisabledReason string `json:"disabled_reason,omitempty"`
	// FailingSince is the first failed attempt after the last success.
	FailingSince *time.Time `json:"failing_since,omitempty"`
	// PreviousSecretExpiresAt: after a rotation (https) the old secret also
	// signs until then.
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	// Pending counts queued deliveries.
	Pending   int       `json:"pending"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Create registers a stream. Secret is the API key (datadog), HEC token
// (splunk) or secret access key (s3), required; https streams get a
// generated signing secret instead and refuse one.
type Create struct {
	// Organization makes it an organization stream (operators only; an
	// organization-scoped create takes it from the scope).
	Organization identity.OrganizationID `json:"organization_id"`
	Name         string                  `json:"name"`
	Destination  string                  `json:"destination"`
	Config       Config                  `json:"config"`
	// Sources default to both for an environment stream and to audit_logs
	// for an organization stream.
	Sources []string `json:"sources"`
	Secret  string   `json:"secret"`
}

// Validate checks the fields that do not depend on the scope.
func (c Create) Validate() error {
	if err := validName(c.Name); err != nil {
		return err
	}
	if !validDestination(c.Destination) {
		return errx.Validation("destination must be datadog, splunk, s3 or https")
	}
	if err := c.Config.Validate(c.Destination); err != nil {
		return err
	}
	if c.Destination == DestinationHTTPS {
		if c.Secret != "" {
			return errx.Validation("https streams sign with a generated secret; secret is not accepted")
		}
	} else if err := validSecret(c.Secret); err != nil {
		return err
	}
	return nil
}

// Update changes the fields that are set; the destination never changes.
type Update struct {
	Name *string `json:"name"`
	// Config replaces the whole configuration.
	Config  *Config   `json:"config"`
	Sources *[]string `json:"sources"`
	// Secret replaces the API key, token or secret access key (not for
	// https: rotate the signing secret instead).
	Secret *string `json:"secret"`
	// Active false pauses the stream (no more queuing); true resumes it
	// and clears its failure.
	Active *bool `json:"active"`
}

func (u Update) Validate() error {
	if u.Name != nil {
		if err := validName(*u.Name); err != nil {
			return err
		}
	}
	if u.Secret != nil {
		if err := validSecret(*u.Secret); err != nil {
			return err
		}
	}
	return nil
}

// CheckSources validates sources against the stream's scope: an
// organization stream carries exactly audit_logs, an environment stream
// events and/or audit_logs.
func CheckSources(sources []string, organization bool) error {
	if len(sources) == 0 {
		return errx.Validation("sources must name events and/or audit_logs")
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if s != SourceEvents && s != SourceAuditLogs {
			return errx.Validation("sources must be events and/or audit_logs")
		}
		if seen[s] {
			return errx.Validation("sources must not repeat")
		}
		seen[s] = true
	}
	if organization && (len(sources) != 1 || sources[0] != SourceAuditLogs) {
		return errx.Validation("an organization stream carries audit_logs only")
	}
	return nil
}

// DefaultSources is what a stream carries when none are given.
func DefaultSources(organization bool) []string {
	if organization {
		return []string{SourceAuditLogs}
	}
	return []string{SourceEvents, SourceAuditLogs}
}

// Created is returned once: the new stream and, for https, its signing
// secret (shown only now, and on rotation).
type Created struct {
	ID     identity.LogStreamID `json:"id"`
	Secret string               `json:"secret,omitempty"`
}

// TestResult is the outcome of a test delivery.
type TestResult struct {
	Delivered bool `json:"delivered"`
	Outcome
}

func validDestination(d string) bool {
	for _, x := range Destinations {
		if x == d {
			return true
		}
	}
	return false
}

func validName(name string) error {
	if n := len([]rune(strings.TrimSpace(name))); n == 0 || n > 100 {
		return errx.Validation("name must be 1 to 100 characters")
	}
	return nil
}

func validSecret(secret string) error {
	if secret == "" {
		return errx.Validation("secret is required")
	}
	if len(secret) > MaxSecret {
		return errx.Validation("secret is too long")
	}
	for _, r := range secret {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errx.Validation("secret must not contain spaces or control characters")
		}
	}
	return nil
}
