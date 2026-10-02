package apiclient

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// Webhook is an event webhook subscription (iam:webhooks:read). Types are
// event types or families ("user.*"); empty means every event.
type Webhook struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	URL                     string     `json:"url"`
	Types                   []string   `json:"types"`
	Active                  bool       `json:"active"`
	DisabledReason          string     `json:"disabled_reason,omitempty"`
	FailingSince            *time.Time `json:"failing_since,omitempty"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	Pending                 int        `json:"pending"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

// WebhookInput creates a subscription (all fields) or updates one (only
// non-nil fields).
type WebhookInput struct {
	Name   *string  `json:"name,omitempty"`
	URL    *string  `json:"url,omitempty"`
	Types  []string `json:"types,omitempty"`
	Active *bool    `json:"active,omitempty"`
}

// WebhookSecret is returned once on create and rotation.
type WebhookSecret struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// WebhookDelivery is one event sent (or being sent) to a subscription.
type WebhookDelivery struct {
	ID             int64      `json:"id"`
	EventID        int64      `json:"event_id"`
	EventType      string     `json:"event_type"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	NextAttemptAt  *time.Time `json:"next_attempt_at,omitempty"`
	ResponseStatus *int       `json:"response_status,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	QueuedAt       time.Time  `json:"queued_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

func (e Environment) Webhooks(ctx context.Context) ([]Webhook, error) {
	return list[Webhook](ctx, e.client, e.path("webhooks"), nil)
}

func (e Environment) Webhook(ctx context.Context, id string) (Webhook, error) {
	var out Webhook
	return out, e.client.Do(ctx, "GET", e.path("webhooks", url.PathEscape(id)), nil, &out)
}

// CreateWebhook needs iam:webhooks:write, like every change below.
func (e Environment) CreateWebhook(ctx context.Context, input WebhookInput) (WebhookSecret, error) {
	var out WebhookSecret
	if input.Types == nil {
		input.Types = []string{}
	}
	return out, e.client.Do(ctx, "POST", e.path("webhooks"), input, &out)
}

func (e Environment) UpdateWebhook(ctx context.Context, id string, input WebhookInput) (Webhook, error) {
	var out Webhook
	return out, e.client.Do(ctx, "PATCH", e.path("webhooks", url.PathEscape(id)), input, &out)
}

func (e Environment) DeleteWebhook(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("webhooks", url.PathEscape(id)), nil, nil)
}

func (e Environment) RotateWebhookSecret(ctx context.Context, id string) (WebhookSecret, error) {
	var out WebhookSecret
	return out, e.client.Do(ctx, "POST", e.path("webhooks", url.PathEscape(id), "rotate-secret"), map[string]any{}, &out)
}

// ReplayWebhook queues the subscription's events from event id from again.
func (e Environment) ReplayWebhook(ctx context.Context, id string, from int64) (int, error) {
	var out struct {
		Queued int `json:"queued"`
	}
	err := e.client.Do(ctx, "POST", e.path("webhooks", url.PathEscape(id), "replay"), map[string]any{"from": from}, &out)
	return out.Queued, err
}

// WebhookDeliveries lists a subscription's deliveries, newest first.
func (e Environment) WebhookDeliveries(ctx context.Context, id, status string) ([]WebhookDelivery, error) {
	var query url.Values
	if status != "" {
		query = url.Values{"status": {status}}
	}
	return list[WebhookDelivery](ctx, e.client, e.path("webhooks", url.PathEscape(id), "deliveries"), query)
}

func (e Environment) RetryWebhookDelivery(ctx context.Context, id string, delivery int64) error {
	return e.client.Do(ctx, "POST", e.path("webhooks", url.PathEscape(id), "deliveries", strconv.FormatInt(delivery, 10), "retry"), map[string]any{}, nil)
}
