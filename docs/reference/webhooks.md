# Email webhook contract

IAMKit sends an HTTPS POST to the configured URL:

```http
Content-Type: application/json
Authorization: Bearer DELIVERY_TOKEN

{"email":"alice@example.com","purpose":"login","code":"12345678"}
```

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
name) when known. Absent fields are omitted, so challenge payloads are unchanged. No environment/app/resource or challenge
ID is included. The webhook is a delivery adapter, not a general notification bus.

Any 2xx status is accepted; response bodies are not used. Other statuses fail.
Redirects are refused; timeout is 10 seconds. There is no asynchronous retry or
signed-event/idempotency header. Build receiver authentication, redaction and
mail-provider retries within the code validity window. Do not invent a payload
field or retry guarantee in an integration.

The URL must have a host and no userinfo/fragment. Global configuration requires
HTTPS; per-environment configuration also permits HTTP for localhost/127.0.0.1
for local testing. Use HTTPS for deployments. Outbound access and endpoint trust
are deployment responsibilities. Environment overrides take precedence over global
configuration; rotating the global token does not rotate those overrides. See
[delivery administration and fallback behavior](../guides/email-delivery.md).
Coordinate receiver/sender rotation and test the new value.

Source: `internal/iam/authentication/adapters/authmail/delivery.go`.
