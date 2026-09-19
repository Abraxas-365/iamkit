# Service accounts

A service account authenticates a trusted worker/backend, not a browser user.
Create an application-resource binding first. Using management `X-API-Key`, POST
`/management/v1/environments/ENV_UUID/service-accounts`:

```json
{"name":"Invoice worker","application_id":"APP_UUID","resource_id":"RESOURCE_UUID","permissions":["invoices:read"],"expires_in":"24h"}
```

201 returns `{id,secret,expires_at}`. Store `secret` once in a secret manager.
Exchange it without placing it in URLs:

```sh
curl --fail --silent --show-error -X POST "$IAMKIT_URL/identity/v1/machine-token" \
  -H "Authorization: Bearer $SERVICE_SECRET"
```

The response contains an access JWT; there is no user refresh token. Use that JWT
on the intended API and enforce its audience/resource/permissions. Machine tokens
have no user organization/session. Renew access by exchanging the still-valid
service credential; rotate the credential before its expiry.

## Backend user provisioning

The built-in IAM resource is intended for selected administration through
`/api/v1`, using a dedicated app binding and explicit IAM permissions. However,
[current routing blockers](../reference/api/scoped-iam.md#deployment-blockers)
prevent relying on environment isolation and independent route permissions. Keep
that API restricted until corrected and regression-tested; do not expand grants
to work around unexpected permission errors. The onboarding example instead
uses a deliberately workspace-wide operator key on a trusted backend.

This differs from a machine token for Invoices API. A resource-bound business
token is not a management key and cannot call `/management/v1`. See
[scoped IAM routes](../reference/api/scoped-iam.md).

## Rotate and revoke

Issue a replacement, deploy it securely, prove successful exchange and intended
API access, then DELETE `/service-accounts/:id` for the predecessor. Read lists
with GET `/service-accounts`. Test denied exchange after revocation and current
state through introspection. Offline JWT consumers retain the expiry trade-off.
Do not give a signup frontend the ability to choose service-account permissions.
