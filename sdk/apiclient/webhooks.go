package apiclient

import (
	"context"
	"net/url"
	"strconv"
)

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
	return first[WebhookDelivery](ctx, e.client, e.path("webhooks", url.PathEscape(id), "deliveries"), query)
}

func (e Environment) RetryWebhookDelivery(ctx context.Context, id string, delivery int64) error {
	return e.client.Do(ctx, "POST", e.path("webhooks", url.PathEscape(id), "deliveries", strconv.FormatInt(delivery, 10), "retry"), map[string]any{}, nil)
}
