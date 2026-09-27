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
  `invitation_url`, `created_at`, `updated_at`; never the token. Absent configuration returns 404.
- `PUT`: replace with `{"webhook_url":"https://mail.example.com/iamkit","webhook_token":"PRIVATE_DELIVERY_TOKEN"}`;
  both fields are required, success is 204. Optional `invitation_url` (same URL
  rules) is your page that accepts [invitations](../reference/api/users-and-organizations.md#invitations);
  IAMKit appends `token=…` to it and sends the result as `link`. To use IAMKit's own accept page, set it to
  `https://IAMKIT_HOST/hosted/invite` ([hosted login](hosted-login.md#invitations)). Use private request files, not tracked
  configuration or shell history. Endpoint changes control where challenge codes go.
- `DELETE`: 204; removes the override and **restores global fallback**, not
  necessarily disables delivery. Deleting an absent override returns 404.
- `GET /delivery/status`: which webhook serves the environment and what happened
  last, without any URL or token:

  ```json
  {"source":"global","global_configured":true,"hosted_invitation_url":"https://IAMKIT_HOST/hosted/invite",
   "last_attempt":{"source":"global","purpose":"login","delivered":true,"latency_ms":84,"at":"2026-09-27T10:00:00Z"},
   "last_failure":{"source":"environment","purpose":"invitation","delivered":false,"status":503,"reason":"webhook rejected the request","latency_ms":0,"at":"2026-09-26T09:12:00Z"}}
  ```

  `source` is `environment` (this environment's webhook), `global`
  (`EMAIL_WEBHOOK_URL`) or `none` (nothing delivers). `last_attempt` is the
  latest delivery of any purpose; `last_failure` is the latest failed one and
  survives later successes. `reason` is one of `webhook rejected the request`
  (with `status`), `webhook did not respond in time`, `webhook could not be reached`,
  `no webhook configured`, `webhook URL is not allowed` or `delivery failed`. Both are
  `null` until the first delivery. Recording is best effort and never blocks delivery.
- `POST /delivery/test` with `{"email":"ops@example.com"}`: sends
  `{"email":"ops@example.com","purpose":"test"}` through the effective webhook and
  returns the attempt (200 whether or not the webhook accepted it; `delivered` says
  which). Owners/admins only, audited as `delivery.test`, and limited to five per
  minute per environment and client (429 beyond). Handle or ignore purpose `test`
  in your receiver. The console's **Notifications** page offers this as
  **Send test email**.

The URL requires HTTPS (HTTP permitted only on localhost/127.0.0.1), without
userinfo or fragment. Restrict outbound network access and who may edit delivery
configuration. Changes are audited as `delivery.update` and `delivery.delete`
(actor and environment; never the URL or token) — review them in **Audit events**.
Persisted tokens are sensitive database contents; protect backups.
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
Invitation mail is sent after the invitation is saved: a failed delivery is
reported as `delivery: "failed"` and does not undo the invitation.
A non-2xx response or network failure rejects delivery; do not return success
before your service has accepted responsibility for sending.

**Verify:** request OTP for an enabled test user, receive mail, complete once and
confirm replay fails. Simulate an unavailable webhook and verify no secret appears
in logs. Monitor delivery rejection/latency and mailbox provider failures separately.
