package event

import (
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Event webhooks: an operator subscribes an HTTPS endpoint to event types.
// Every matching event is queued for it in the event's own transaction
// (trigger queue_event_deliveries, migration 046) and delivered at least
// once, in event order per subscription, signed per Standard Webhooks.

// Subscription audit actions (the console's activity log names them).
const (
	ActionWebhookCreate  = "webhook.create"
	ActionWebhookUpdate  = "webhook.update"
	ActionWebhookDelete  = "webhook.delete"
	ActionWebhookRotate  = "webhook.rotate_secret"
	ActionWebhookReplay  = "webhook.replay"
	ActionWebhookRetry   = "webhook.retry"
	ActionWebhookDisable = "webhook.disabled"
)

// TestType is the type of the synthetic event a test delivery sends; it
// never enters the log.
const TestType = "webhook.test"

// SecretPrefix starts every subscription secret (Standard Webhooks: the
// rest is the base64 HMAC key).
const SecretPrefix = "whsec_"

// Subscription limits.
const (
	MaxSubscriptions     = 25
	MaxSubscriptionTypes = 50
	// MaxReplay caps the events one replay queues.
	MaxReplay = 10000
)

// Delivery statuses.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// DisabledFailing is the disabled_reason of a subscription the worker
// turned off after failing for config.EventWebhookDisableAfter.
const DisabledFailing = "failing"

// Mutation is an audited subscription change.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

type Subscription struct {
	ID          identity.SubscriptionID `json:"id"`
	Environment identity.EnvironmentID  `json:"environment_id"`
	Name        string                  `json:"name"`
	URL         string                  `json:"url"`
	// Types are exact types (user.created) or families (user.*); empty
	// subscribes to every type.
	Types  []string `json:"types"`
	Active bool     `json:"active"`
	// DisabledReason is "failing" when the worker turned it off.
	DisabledReason string `json:"disabled_reason,omitempty"`
	// FailingSince is the first failed attempt after the last success.
	FailingSince *time.Time `json:"failing_since,omitempty"`
	// PreviousSecretExpiresAt: after a rotation the old secret also signs
	// until then.
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	// Pending counts queued deliveries.
	Pending   int       `json:"pending"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SubscriptionCreate registers an endpoint.
type SubscriptionCreate struct {
	Name  string   `json:"name"`
	URL   string   `json:"url"`
	Types []string `json:"types"`
}

func (c SubscriptionCreate) Validate() error {
	if err := validName(c.Name); err != nil {
		return err
	}
	if err := ValidEndpoint(c.URL); err != nil {
		return err
	}
	return validTypes(c.Types)
}

// SubscriptionUpdate changes the fields that are set. Active = true
// re-enables a disabled subscription (its queued deliveries resume).
type SubscriptionUpdate struct {
	Name   *string   `json:"name"`
	URL    *string   `json:"url"`
	Types  *[]string `json:"types"`
	Active *bool     `json:"active"`
}

func (u SubscriptionUpdate) Validate() error {
	if u.Name != nil {
		if err := validName(*u.Name); err != nil {
			return err
		}
	}
	if u.URL != nil {
		if err := ValidEndpoint(*u.URL); err != nil {
			return err
		}
	}
	if u.Types != nil {
		return validTypes(*u.Types)
	}
	return nil
}

// SubscriptionSecret is returned once, when a subscription is created or
// its secret rotated.
type SubscriptionSecret struct {
	ID     identity.SubscriptionID `json:"id"`
	Secret string                  `json:"secret"`
}

// Replay queues again the events from From (an event id, inclusive) that
// match the subscription.
type Replay struct {
	From int64 `json:"from"`
}

func (r Replay) Validate() error {
	if r.From <= 0 {
		return errx.Validation("from must be an event id")
	}
	return nil
}

// Delivery is one event queued for one subscription.
type Delivery struct {
	ID             int64                   `json:"id"`
	Subscription   identity.SubscriptionID `json:"subscription_id"`
	EventID        int64                   `json:"event_id"`
	EventType      string                  `json:"event_type"`
	Status         string                  `json:"status"`
	Attempts       int                     `json:"attempts"`
	NextAttemptAt  *time.Time              `json:"next_attempt_at,omitempty"`
	ResponseStatus *int                    `json:"response_status,omitempty"`
	LastError      string                  `json:"last_error,omitempty"`
	QueuedAt       time.Time               `json:"queued_at"`
	FinishedAt     *time.Time              `json:"finished_at,omitempty"`
}

// DeliveryFilter narrows a subscription's delivery log; zero matches all.
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

// Message is a claimed delivery ready to send.
type Message struct {
	Delivery     int64
	Subscription identity.SubscriptionID
	Environment  identity.EnvironmentID
	URL          string
	// Secrets are sealed: the current one, then the previous one while it
	// still signs.
	Secrets  []string
	Attempts int
	// FirstAttempt starts the retry window.
	FirstAttempt time.Time
	// Event is nil when it was pruned before delivery.
	Event *Event
}

// Outbound is a message with opened secrets (whsec_…), for the Sender.
type Outbound struct {
	// ID is the webhook-id header (msg_<delivery>), stable across retries.
	ID      string
	URL     string
	Secrets []string
	Event   Event
}

// Outcome is what an endpoint answered.
type Outcome struct {
	// Status is the HTTP status, 0 when no response arrived.
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

// OK reports a 2xx answer.
func (o Outcome) OK() bool { return o.Status >= 200 && o.Status < 300 && o.Error == "" }

// TestResult is the outcome of a test delivery.
type TestResult struct {
	Delivered bool `json:"delivered"`
	Outcome
}

// DeliveryRetryAfter is how long after its attempts-th failed try a
// delivery first tried at first waits: exponential from base up to
// ceiling, while the next attempt still falls within window of first; ok
// is false once it is given up.
func DeliveryRetryAfter(attempts int, first, now time.Time, base, ceiling, window time.Duration) (time.Duration, bool) {
	wait := base
	for i := 1; i < attempts && wait < ceiling; i++ {
		wait *= 2
	}
	wait = min(wait, ceiling)
	if now.Add(wait).After(first.Add(window)) {
		return 0, false
	}
	return wait, true
}

// ValidEndpoint accepts https URLs (http only on loopback, for local
// development) without credentials or fragments.
func ValidEndpoint(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return errx.Validation("url must be an https URL")
	}
	host := u.Hostname()
	if u.Scheme == "https" || (u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")) {
		return nil
	}
	return errx.Validation("url must be an https URL")
}

func validName(name string) error {
	if n := len([]rune(strings.TrimSpace(name))); n == 0 || n > 100 {
		return errx.Validation("name must be 1 to 100 characters")
	}
	return nil
}

func validTypes(types []string) error {
	if len(types) > MaxSubscriptionTypes {
		return errx.Validation("types may name at most 50 event types")
	}
	for _, t := range types {
		if !ValidType(t) && !(strings.HasSuffix(t, ".*") && ValidPrefix(strings.TrimSuffix(t, ".*"))) {
			return errx.Validation("types must be event types such as user.created or user.*")
		}
	}
	return nil
}
