# Email delivery

IAMKit generates and verifies challenges; your trusted service delivers mail.
An environment-specific delivery configuration takes precedence over global
settings. To configure the **global fallback**, set `EMAIL_WEBHOOK_URL` and
`EMAIL_WEBHOOK_TOKEN` in the **container environment**, not just the Compose
interpolation file. Restart and verify using a controlled test mailbox.

```yaml
services:
  iamkit:
    environment:
      EMAIL_WEBHOOK_URL: ${EMAIL_WEBHOOK_URL:?Set trusted HTTPS endpoint}
      EMAIL_WEBHOOK_TOKEN: ${EMAIL_WEBHOOK_TOKEN:?Set delivery credential}
```

This is a Compose override fragment. Keep secrets in deployment storage and use
an explicit HTTPS endpoint you control. The payload/authentication contract is in
[webhooks](../reference/webhooks.md).

Your handler must authenticate the bearer token, validate the payload, choose a
safe template by purpose and deliver to the specified email. Treat codes as
secrets: suppress bodies in application, proxy, tracing and error logs. Do not
send management keys to the delivery service.

## Per-environment configuration

With management authority, use
`/management/v1/environments/ENV_UUID/delivery`:

- `GET`: configuration with `environment_id`, `webhook_url`, `has_token`,
  `created_at`, `updated_at`; never the token. Absent configuration returns 404.
- `PUT`: replace with `{"webhook_url":"https://mail.example.com/iamkit","webhook_token":"PRIVATE_DELIVERY_TOKEN"}`;
  both fields are required, success is 204. Use private request files, not tracked
  configuration or shell history. Endpoint changes control where challenge codes go.
- `DELETE`: 204; removes the override and **restores global fallback**, not
  necessarily disables delivery. Deleting an absent override returns 404.

The URL requires HTTPS (HTTP permitted only on localhost/127.0.0.1), without
userinfo or fragment. Restrict outbound network access and who may edit delivery
configuration. Persisted tokens are sensitive database contents; protect backups.
Scoped `/api/v1` delivery routes also exist but share the
[scoped API blockers](../reference/api/scoped-iam.md#deployment-blockers).

Rotating or unsetting the global configuration does not change environment
overrides. To stop delivery, remove affected overrides **and** disable global
fallback. A configuration lookup failure currently falls back to global delivery,
so do not depend on overrides alone for strict delivery isolation during DB errors.

The payload has no environment/application/resource IDs. Separate environment
endpoints can choose their own template, but cannot infer additional tenant or
application context from fields IAMKit does not send.
Delivery is synchronous with a 10-second timeout and no automatic retry queue.
A non-2xx response or network failure rejects delivery; do not return success
before your service has accepted responsibility for sending.

**Verify:** request OTP for an enabled test user, receive mail, complete once and
confirm replay fails. Simulate an unavailable webhook and verify no secret appears
in logs. Monitor delivery rejection/latency and mailbox provider failures separately.
