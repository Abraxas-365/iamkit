# Email webhook contract

This applies to the `webhook` provider (the default). With `smtp` or `resend`,
IAMKit writes and sends the email itself; see [email delivery](../guides/email-delivery.md).

IAMKit sends an HTTPS POST to the configured URL:

```http
Content-Type: application/json
Authorization: Bearer DELIVERY_TOKEN
webhook-id: msg_4f3c9a0e8b7d6c5b4a39281706f5e4d3
webhook-timestamp: 1759100000
webhook-signature: v1,VEEvZkTVcUi4w4JKCoIp7uedyvVOqrYq7smmGouKvKU=

{"email":"alice@example.com","purpose":"login","code":"12345678"}
```

The `webhook-*` headers are sent only when a token is configured.

## Signature

Requests follow the [Standard Webhooks](https://www.standardwebhooks.com)
signing scheme: `webhook-signature` is `v1,` + base64 of
HMAC-SHA256 over `webhook-id + "." + webhook-timestamp + "." + raw body`, keyed
with the **bytes of the delivery token** (the same value as the bearer token).
To verify:

1. Recompute the HMAC over the raw request body (before JSON parsing) and
   compare it in constant time with each space-separated `v1,` entry.
2. Reject timestamps more than five minutes from your clock.
3. Treat `webhook-id` as an idempotency key: ignore an ID you already handled.

```js
import crypto from "node:crypto";
const signed = `${id}.${timestamp}.${rawBody}`;
const expected = "v1," + crypto.createHmac("sha256", token).update(signed).digest("base64");
```

Standard Webhooks libraries expect a base64 secret (optionally prefixed `whsec_`):
pass `whsec_` + base64(token). The bearer token is still sent, so receivers that
only check it keep working; prefer the signature, which also rejects replays.

Purposes: `login`, `password_reset`, `email_verification`. The code is secret,
single-use and valid for five minutes.

Test sends from the console (`POST …/delivery/test`) use purpose `test` with
only `email` and `purpose`: `{"email":"ops@example.com","purpose":"test"}`.
Accept or ignore them with a 2xx.

Invitations use purpose `invitation` and carry no code:

```json
{"email":"bob@example.com","purpose":"invitation","token":"ik_inv_…","link":"https://app.example.com/join?token=ik_inv_…","organization":"Acme","inviter":"owner@example.com","expires_at":"2026-10-03T12:00:00Z"}
```

`link` is present only when the environment's delivery config sets
`invitation_url`; otherwise build it from `token` yourself. The token is a
secret valid for seven days. `inviter` is the inviting operator's email (or
name) when known. Absent fields are omitted, so challenge payloads are unchanged. No environment/app/resource,
challenge ID or language is included (a requested `locale` is not forwarded). The webhook is a delivery adapter, not a general notification bus.

Any 2xx status is accepted; response bodies are not used. Other statuses fail.
Redirects are refused; timeout is 10 seconds. There is no asynchronous retry.
Build receiver authentication, redaction and
mail-provider retries within the code validity window. Do not invent a payload
field or retry guarantee in an integration.

The URL must have a host and no userinfo/fragment, and use HTTPS (HTTP only for
localhost/127.0.0.1). Environment webhooks are only connected to on public
addresses (private, loopback and link-local are refused after DNS resolution,
reported as `webhook address is not allowed`); only the global
`EMAIL_WEBHOOK_URL` may reach a private or local receiver, unless the
development-only
[`IAMKIT_ALLOW_PRIVATE_DELIVERY`](configuration.md#private-delivery-addresses-development-only)
is set (never in production). Use HTTPS for
deployments. Environment overrides take precedence over global
configuration; rotating the global token does not rotate those overrides. See
[delivery administration and fallback behavior](../guides/email-delivery.md).
Coordinate receiver/sender rotation and test the new value.

Source: `internal/iam/authentication/adapters/authmail/delivery.go`.
