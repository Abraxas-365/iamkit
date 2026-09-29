# Management API

Base: `/management/v1`. JSON requests use `Content-Type: application/json`.
Programmatic requests authenticate with **`X-API-Key: ik_mgmt_…`**, not a bearer
header. Alternatively, the console uses its Secure HttpOnly Strict
`__Host-iamkit-operator` cookie. Cookie mutations and login require
`X-IAMKit-Console: 1` and reject `Sec-Fetch-Site: cross-site`.

Keys resolve an active workspace operator. They are not application-scoped.
Environment routes additionally check that the environment belongs to that
workspace. Owner/admin can mutate environment data; viewer cannot.

## Workspace administration

| Method/path | Request | Success |
| --- | --- | --- |
| `POST /login` | `email`, `password`, optional `new_password`; console header, no existing credential | 200 principal + operator cookie. 403 `PASSWORD_CHANGE_REQUIRED` (only after the password matched) when the password was set for the operator (bootstrap); resend with `new_password` to replace it and sign in |
| `GET /me` | Authenticated | 200 `{operator_id,workspace_id,role,method,authenticated_at}`; `method` is `password`, `sso` or `key` |
| `GET /password` | Authenticated | 200 `{set,usable,fresh,mode}`: has a password; may use one here; may set one without `current_password` |
| `POST /password` | `password` (12–72 bytes), `current_password` | 204; updates own operator password. Proof: `current_password`, or a management key, or (no password set, or a single sign-on session) a sign-in within 5 minutes; else 403 `REAUTHENTICATION_REQUIRED`. Ends the operator's other console sessions; the calling one stays |
| `DELETE /sessions/current` | Authenticated | 204; invalidates/clears operator cookie |
| `POST /keys` | Optional `expires_in` | 201 credential result; capture secret once |
| `GET /keys` | Authenticated | 200 array |
| `DELETE /keys/:id` | Key UUID | 204 |
| `POST /operators` | `email`, `role`, optional `expires_in` | 201 delegated credential |
| `GET /operators` | Authenticated | 200 array |
| `DELETE /operators/:id` | Operator UUID | 204 |
| `POST /projects` | `name` | 201 `{id}` |
| `GET /projects` | Authenticated | 200 array |
| `POST /projects/:project/environments` | `name` | 201 `{id}` |
| `GET /projects/:project/environments` | Project UUID | 200 array |

Delegating/disabling operators requires owner authority; creating keys does not
upgrade the caller's role. Protect credential responses as secrets. The default
management credential lifetime is 24 hours; consult actual TTL validation before
selecting a custom value in [configuration](../configuration.md).

Example, from your trusted backend shell:

```sh
curl --fail --silent --show-error "$IAMKIT_URL/management/v1/projects" \
  -H "X-API-Key: $MGMT" -H 'Content-Type: application/json' \
  --data '{"name":"InvoiceCloud"}'
```

Save the returned `id`; do not select projects by arbitrary array position.

## Environment administration

Prefix: `/environments/:environment`. Use UUID identifiers from creation
responses. See [users/organizations](users-and-organizations.md),
[applications/authorization](applications-and-authorization.md) and
[integrations](integrations.md).

Delivery configuration uses `GET /delivery` (200 configuration or 404),
`PUT /delivery` (`provider` `webhook`|`smtp`|`resend` with that provider's fields;
204) and `DELETE /delivery` (204, or 404 if absent). Reads never return the webhook
token, SMTP password or Resend API key (`has_token`, `has_secret`); storing the latter
two requires `IAMKIT_ENCRYPTION_KEY` (422 without). `PUT`/`DELETE` are audited as
`delivery.update`/`delivery.delete`. Deletion restores global fallback.
`GET /delivery/status` reports the effective source (`environment`, `global`,
`none`), its `provider` and the latest attempt and failure; `POST /delivery/test` (`{"email"}`,
owner/admin, audited `delivery.test`, 5/min) sends a `test` message and returns
the attempt. `GET /delivery/preview?purpose=&locale=` renders a sample email
(`{subject,html,text}`), `POST /delivery/preview` the same with unsaved `template`
wording. Email wording: `GET /delivery/templates`, `GET|PUT|DELETE
/delivery/templates/:purpose/:locale` (audited `email_template.updated`/`.reset`).
See [email delivery](../../guides/email-delivery.md) for precedence, fields, wording and rotation.

The end-user [password policy](../../guides/password-policy.md) uses
`GET /password-policy` (200 policy; the default with `custom: false` when none is
saved), `PUT /password-policy` (the complete policy: `min_length`, `require_upper`,
`require_lower`, `require_digit`, `require_symbol`, `max_age_days`,
`lockout_threshold`, `lockout_minutes`, `breach_check`; 200 saved policy) and
`DELETE /password-policy` (204, back to the default), audited as
`password_policy.update`/`password_policy.delete`. An organization's additions
use `GET|PUT|DELETE /organizations/:id/password-policy` (`min_length`,
`require_*`, `max_age_days`, `breach_check`; 0/false keep the environment's;
404 for an unknown organization), audited as
`organization_password_policy.update`/`.delete`.

The [sign-in methods](../../guides/sign-in-methods.md) policy uses
`GET|PUT|DELETE /sign-in-policy` (`allow_password`, `allow_email_code`,
`allow_social`, `allow_password_reset`, `mfa_required`, `mfa_for_federated`,
`allow_signup`, `signup_organization_id`, `signup_group_id` — see
[sign-up](../../guides/signup-and-onboarding.md#self-service-sign-up);
`custom: false` for the default), audited as
`sign_in_policy.update`/`sign_in_policy.delete`.

Administrative inventories include `GET /sessions` (optional `user_id` filter), `DELETE /sessions/:id` and
`GET /audit-events` under this prefix. Sessions carry display labels
`user_name,user_email,organization_name,application_name,resource_name` and
audit events an `actor_label` (operator or end-user email; empty when unknown)
and a `target_label` (current name of the innermost entity in `target_id`, e.g.
the member for a membership path; empty when deleted or unnamed).
Session revocation affects online checks
and refresh; already issued JWTs require online checking to observe revocation
before expiry. These inventory endpoints return arrays, not the entity-list
pagination envelope. Do not assume a complete audit trail for every operation.

Failures use the [error contract](../errors-and-pagination.md): missing/expired
credentials → 401; insufficient authority → 403; unavailable environment → 404.
Console cookie errors often indicate HTTP instead of HTTPS or missing CSRF header.

Source: `internal/iam/management/adapters/mgmthttp/handler.go`,
`activity.go`, `mgmtsvc/control.go`, `internal/server/management.go`.
