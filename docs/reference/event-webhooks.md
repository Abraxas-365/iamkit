# Event webhooks

An event webhook pushes entries of the [event log](events.md) to your HTTPS
endpoint as they happen. Nothing is sent until you add a subscription.

- **Per environment**, at most 25 subscriptions, each with a name, an
  endpoint URL and the event types it wants (exact types such as
  `user.created` or families such as `membership.*`; none = every event).
- **Queued in the same transaction** as the change: an event a subscription
  matches is never lost, even if IAMKit stops right after the write.
- **In order, at least once.** Each subscription receives its events one at
  a time, oldest first; a failing event holds back the next ones until it
  is delivered or given up. Deduplicate on `webhook-id` (or the event `id`).
- **Signed** per [Standard Webhooks](https://www.standardwebhooks.com) with a
  per-subscription secret, rotatable with a 24-hour overlap.
- Endpoints must use `https` (plain `http` only for `localhost`) and resolve
  to public addresses; private ranges are refused at delivery time
  (`IAMKIT_ALLOW_PRIVATE_DELIVERY` lifts this for development only).

## The request

```http
POST /iam/events HTTP/1.1
Content-Type: application/json
User-Agent: IAMKit-Webhooks/1
webhook-id: msg_1842
webhook-timestamp: 1759100000
webhook-signature: v1,Lw0nwnE0tZnN5c7Pu3ZG2v9uRb0SWVbiU8qxkMwj3Vw=

{"id":1842,"environment_id":"7ae0…","type":"user.created",
 "actor":{"kind":"operator","id":"3f1c…"},"subject":{"kind":"user","id":"33b4…"},
 "data":{"origin":"api"},"occurred_at":"2026-09-30T19:39:49Z"}
```

The body is the event exactly as `GET …/events` returns it. When it would
exceed 64 KiB, `data` is replaced by `{"truncated": true}`; read the full
event from the log by `id`. A test event has type `webhook.test`.

Answer any `2xx` within 10 seconds. Redirects are not followed and count as
failures.

## Verifying the signature

`webhook-signature` is `v1,` + base64 of HMAC-SHA256 over
`webhook-id + "." + webhook-timestamp + "." + raw body`. The key is the
base64 part of the subscription secret (after `whsec_`), as every Standard
Webhooks library expects. During a rotation the header carries one
space-separated `v1,` entry per secret; accept the request when any entry
matches. Reject timestamps more than five minutes from your clock.

With the Go SDK:

```go
import "github.com/Abraxas-365/iamkit/sdk/webhook"

func handle(w http.ResponseWriter, r *http.Request) {
	event, err := webhook.Verify(os.Getenv("IAMKIT_WEBHOOK_SECRET"), r)
	if err != nil {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	log.Printf("%s %s:%s", event.Type, event.Subject.Kind, event.Subject.ID)
	w.WriteHeader(http.StatusNoContent)
}
```

In other languages use a Standard Webhooks library (`standardwebhooks` on
npm and PyPI) with the `whsec_` secret as is.

## Retries, failures and disabling

| Situation | What happens |
| --- | --- |
| Non-`2xx`, timeout, unreachable | Retried with exponential backoff (15 s doubling, at most 1 h between tries) for 24 hours from the first try; the subscription shows `failing_since` |
| Still failing after 24 hours | The delivery is marked `failed` and the next event is tried; retry it from the console, CLI or API |
| Failing for 3 days | The subscription is disabled (`active: false`, `disabled_reason: "failing"`) and emits `webhook.disabled`; events keep queuing — re-enable it to resume where it stopped. A subscription an operator disables queues nothing until it is enabled again |
| A success | `failing_since` clears |

Finished deliveries are kept for 7 days. Events pruned from the log (see
[retention](events.md#retention)) before they could be sent are marked
`failed`.

## Secrets

The secret (`whsec_` + 32 random bytes, base64) is returned once when the
subscription is created and once per rotation; IAMKit stores it sealed with
`IAMKIT_ENCRYPTION_KEY`, so creating a subscription without that key
answers 422 `ENCRYPTION_KEY_REQUIRED`. Rotating returns a new secret and keeps
signing with the previous one too for 24 hours
(`previous_secret_expires_at`).

## API

Under `/management/v1/environments/:environment` (operators; viewers read
only) and `/api/v1/environments/:environment` (`iam:webhooks:read` to read,
`iam:webhooks:write` to change):

| Method and path | Purpose |
| --- | --- |
| `GET /webhooks` | List subscriptions (`{"items": [...]}`) |
| `POST /webhooks` | Create: `{"name", "url", "types": []}` → `201 {"id", "secret"}` |
| `GET /webhooks/:id` | One subscription, with `pending` (queued deliveries) |
| `PATCH /webhooks/:id` | Change `name`, `url`, `types` or `active` |
| `DELETE /webhooks/:id` | Delete it and its pending deliveries |
| `POST /webhooks/:id/rotate-secret` | New secret → `{"id", "secret"}` |
| `POST /webhooks/:id/test` | Send a `webhook.test` event now → `{"delivered", "status", "error"}` (not queued) |
| `POST /webhooks/:id/replay` | `{"from": <event id>}` queues the matching events from that id again (at most 10,000) → `202 {"queued"}` |
| `GET /webhooks/:id/deliveries` | Paginated delivery log, newest first; `status` = `pending`, `delivered` or `failed` |
| `POST /webhooks/:id/deliveries/:delivery/retry` | Queue a failed delivery again → `202` |

Changes are audited and recorded in the event log as `webhook.created`,
`webhook.updated`, `webhook.deleted`, `webhook.secret_rotated`,
`webhook.replayed`, `webhook.delivery_retried` and `webhook.disabled`.

## Console, CLI and SDK

The console lists subscriptions under **Monitoring → Webhooks**, with the
delivery log, test, rotation and replay on each subscription's page.

```sh
iam webhooks create --name CRM --url https://crm.example/iam --types "user.*,membership.created"
iam webhooks test WEBHOOK_ID
iam webhooks deliveries WEBHOOK_ID --status failed
iam webhooks retry WEBHOOK_ID DELIVERY_ID
iam webhooks replay WEBHOOK_ID --from 1800
iam webhooks rotate-secret WEBHOOK_ID
```

The Go SDK manages subscriptions with `iamclient` and `apiclient`
(`Webhooks`, `CreateWebhook`, `UpdateWebhook`, `DeleteWebhook`,
`RotateWebhookSecret`, `ReplayWebhook`, `WebhookDeliveries`,
`RetryWebhookDelivery`; `iamclient` also `TestWebhook`) and verifies them
with package `webhook`.

## Operations

Delivery runs as the `event_webhook` [background job](../operations/observability.md#background-jobs)
every 2 seconds on every replica, and again at once while a subscription's
delivery succeeds or is given up, so a backlog drains without waiting (rows are leased with `FOR UPDATE SKIP
LOCKED`); `event_webhook_maintenance` disables failing subscriptions and
prunes old deliveries every 10 minutes. `iamkit.worker.lag{job="event_webhook"}`
is how long the oldest due delivery has waited, and
`iamkit.webhook.deliveries{result}` counts attempts (`delivered`, `retried`, `failed`).
