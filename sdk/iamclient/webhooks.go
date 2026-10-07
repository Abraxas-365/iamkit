package iamclient

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// Webhook is an event webhook subscription. Types are event types or
// families ("user.*"); empty means every event.
type Webhook struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	URL            string   `json:"url"`
	Types          []string `json:"types"`
	Active         bool     `json:"active"`
	DisabledReason string   `json:"disabled_reason,omitempty"`
	// FailingSince is set while deliveries fail; after three days the
	// subscription is disabled with DisabledReason "failing".
	FailingSince            *time.Time `json:"failing_since,omitempty"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	Pending                 int        `json:"pending"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

// WebhookInput creates a subscription (all fields) or updates one (only
// non-nil fields; set Types to an empty slice for every event).
type WebhookInput struct {
	Name   *string  `json:"name,omitempty"`
	URL    *string  `json:"url,omitempty"`
	Types  []string `json:"types,omitempty"`
	Active *bool    `json:"active,omitempty"`
}

// WebhookSecret is returned once on create and rotation: verify requests
// with it (see package webhook).
type WebhookSecret struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// WebhookDelivery is one event sent (or being sent) to a subscription.
type WebhookDelivery struct {
	ID             int64      `json:"id"`
	EventID        int64      `json:"event_id"`
	EventType      string     `json:"event_type"`
	Status         string     `json:"status"` // pending, delivered or failed
	Attempts       int        `json:"attempts"`
	NextAttemptAt  *time.Time `json:"next_attempt_at,omitempty"`
	ResponseStatus *int       `json:"response_status,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	QueuedAt       time.Time  `json:"queued_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// WebhookTest is the outcome of a test event.
type WebhookTest struct {
	Delivered bool   `json:"delivered"`
	Status    int    `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (e Environment) Webhooks(ctx context.Context) ([]Webhook, error) {
	return list[Webhook](e, ctx, "webhooks")
}

func (e Environment) Webhook(ctx context.Context, id string) (Webhook, error) {
	var out Webhook
	err := e.operation(ctx, "GET", []string{"webhooks", id}, nil, &out)
	return out, err
}

func (e Environment) CreateWebhook(ctx context.Context, input WebhookInput) (WebhookSecret, error) {
	var out WebhookSecret
	if input.Types == nil {
		input.Types = []string{}
	}
	err := e.operation(ctx, "POST", []string{"webhooks"}, input, &out)
	return out, err
}

func (e Environment) UpdateWebhook(ctx context.Context, id string, input WebhookInput) (Webhook, error) {
	var out Webhook
	err := e.operation(ctx, "PATCH", []string{"webhooks", id}, input, &out)
	return out, err
}

func (e Environment) DeleteWebhook(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"webhooks", id}, nil, nil)
}

// RotateWebhookSecret returns a new secret; the previous one keeps
// signing for 24 hours.
func (e Environment) RotateWebhookSecret(ctx context.Context, id string) (WebhookSecret, error) {
	var out WebhookSecret
	err := e.operation(ctx, "POST", []string{"webhooks", id, "rotate-secret"}, map[string]any{}, &out)
	return out, err
}

// TestWebhook sends a webhook.test event now (never queued).
func (e Environment) TestWebhook(ctx context.Context, id string) (WebhookTest, error) {
	var out WebhookTest
	err := e.operation(ctx, "POST", []string{"webhooks", id, "test"}, map[string]any{}, &out)
	return out, err
}

// ReplayWebhook queues the subscription's events from event id from again
// (at most 10,000) and returns how many.
func (e Environment) ReplayWebhook(ctx context.Context, id string, from int64) (int, error) {
	var out struct {
		Queued int `json:"queued"`
	}
	err := e.operation(ctx, "POST", []string{"webhooks", id, "replay"}, map[string]any{"from": from}, &out)
	return out.Queued, err
}

// WebhookDeliveries lists a subscription's deliveries, newest first;
// status filters (pending, delivered, failed).
func (e Environment) WebhookDeliveries(ctx context.Context, id, status string) ([]WebhookDelivery, error) {
	if err := safeSegment(id); err != nil {
		return nil, err
	}
	var query url.Values
	if status != "" {
		query = url.Values{"status": {status}}
	}
	return first[WebhookDelivery](ctx, e.client, e.path("webhooks/"+id+"/deliveries"), query)
}

// RetryWebhookDelivery queues a failed delivery again.
func (e Environment) RetryWebhookDelivery(ctx context.Context, id string, delivery int64) error {
	return e.operation(ctx, "POST", []string{"webhooks", id, "deliveries", strconv.FormatInt(delivery, 10), "retry"}, map[string]any{}, nil)
}
