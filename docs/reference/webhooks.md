# Email webhook contract

IAMKit sends an HTTPS POST to the configured URL:

```http
Content-Type: application/json
Authorization: Bearer DELIVERY_TOKEN

{"email":"alice@example.com","purpose":"login","code":"12345678"}
```

Purposes: `login`, `password_reset`, `email_verification`. The code is secret,
single-use and valid for five minutes. No environment/app/resource or challenge
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
