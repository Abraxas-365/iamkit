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
| `POST /login` | `email`, `password`, optional `new_password`; console header, no existing credential | 200 principal + operator cookie. 403 `PASSWORD_CHANGE_REQUIRED` (only after the password matched) when the password was set for the operator (bootstrap); resend with `new_password` to replace it and sign in. 403 `PASSWORD_LOGIN_DISABLED` or `SSO_REQUIRED` under [operator single sign-on](../configuration.md#operator-single-sign-on) |
| `GET /login-options` | Unauthenticated | 200 `{password, password_mode, providers:[{id,name,type}]}`: what the console login page offers |
| `GET /sso/:provider/start` | Browser navigation | 302 to the provider; sets a binding cookie |
| `GET /sso/callback` | Provider redirect | 303 to `/` with the operator cookie, or to `/login?sso_error=expired\|not_authorized\|provider_unavailable\|cancelled\|failed` |
| `GET /me` | Authenticated | 200 `{operator_id,workspace_id,role,method,authenticated_at}`; `method` is `password`, `sso` or `key` |
| `GET /password` | Authenticated | 200 `{set,usable,fresh,mode}`: has a password; may use one here; may set one without `current_password` |
| `POST /password` | `password` (12–72 bytes), `current_password` | 204; updates own operator password. Proof: `current_password`, or a management key, or (no password set, or a single sign-on session) a sign-in within 5 minutes; else 403 `REAUTHENTICATION_REQUIRED`. Ends the operator's other console sessions; the calling one stays |
| `DELETE /sessions/current` | Authenticated | 204; invalidates/clears operator cookie |
| `GET /preferences` | Authenticated | 200 `{locale}`: the caller's console language, `null` follows the browser |
| `PUT /preferences` | `locale`: `en`, `es` or `null` | 200 the saved preferences |
| `POST /keys` | Optional `expires_in` | 201 credential result; capture secret once |
| `GET /keys` | Authenticated | 200 array |
| `DELETE /keys/:id` | Key UUID | 204 |
| `POST /operators` | `email`, `role` (`admin` or `viewer`), optional `expires_in`; owner | 201 delegated credential `{operator_id,key_id,secret,expires_at,reactivated}`. Again for an active member with the same role: a new key. For a disabled member (formerly 409): reactivates it with the role (`reactivated: true`) and nothing of before — earlier keys and sessions stay ended, emergency access is off, and its password and linked SSO identities are cleared. An operator still active in another workspace keeps them, since they are account-wide; reset the SSO link (`DELETE /operators/:id/identities`) if they must not carry over. An active member with another role → 409 `OPERATOR_EXISTS`; change the role instead |
| `GET /operators` | Authenticated | 200 array |
| `DELETE /operators/:id` | Operator UUID; owner | 204; disables a non-owner: revokes its keys and console sessions |
| `PUT /operators/:id/role` | `role`: `owner`, `admin` or `viewer`; owner | 204; applies to the operator's live keys and sessions at once, and demoting an owner ends the user impersonations it started. An owner may step down while another active owner remains; the last one → 409 `LAST_OWNER`. Disabled operators → 409 (invite them again) |
| `PUT /operators/:id/password-access` | `allowed` (boolean); owner | 204; grants or removes emergency password access (`break_glass` mode) |
| `GET /operators/:id/identities` | Owner, or the operator themself | 200 `{items:[{provider,issuer,email,created_at,last_login_at}]}`: linked single sign-on identities |
| `DELETE /operators/:id/identities` | Owner | 204; unlinks them, the next SSO sign-in links again by email |
| `POST /projects` | `name` | 201 `{id}` |
| `GET /projects` | Authenticated | 200 array |
| `POST /projects/:project/environments` | `name` | 201 `{id}` |
| `GET /projects/:project/environments` | Project UUID | 200 array |

Delegating, disabling and changing the role of operators requires owner
authority; creating keys does not upgrade the caller's role. Role changes and
reactivations are logged as `operator.role_changed` / `operator.reactivated`.
Protect credential responses as secrets. The default
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
`allow_social`, `allow_passkey` ([passkeys](../../guides/mfa.md#passkeys); omitted = keep),
`allow_password_reset`, `mfa_required`, `mfa_for_federated`,
`allowed_factors` (second-factor kinds, default `["totp","webauthn"]`;
omitted = keep — see [MFA](../../guides/mfa.md#allowed-factors)),
`allow_signup`, `signup_organization_id`, `signup_group_id`, `require_terms`
(omitted = keep) — see
[sign-up](../../guides/signup-and-onboarding.md#self-service-sign-up);
`custom: false` for the default), audited as
`sign_in_policy.update`/`sign_in_policy.delete`.

The [organization admin portal](../../guides/organization-administration.md#hosted-portal)
uses `GET|PUT|DELETE /org-admin-portal` (`enabled`, `client_id`,
`application_id`, `url`; `PUT` takes an empty body and is idempotent;
`DELETE` ends the portal's sessions), audited as
`org_admin_portal.enabled`/`.disabled`. Its OAuth client lists with
`system: "org_admin"`; `PATCH`/`DELETE` on it answer 409.

The SMS provider for [email and SMS second factors](../../guides/mfa.md#sms-provider)
uses `GET|PUT|DELETE /sms` (`provider` `twilio` with `account_sid`,
`auth_token`, `from_number` or `messaging_service_sid`; or `webhook` with
`webhook_url`, `webhook_token`; secrets never returned, omitted = keep),
`GET /sms/status` and `POST /sms/test` (`{"phone"}`, E.164, rate limited),
audited `sms.update`/`sms.delete`/`sms.test`.

### Signing keys

[Environment signing keys](../../guides/signing-keys.md) use `GET /signing-keys`
(page of keys, active first: `kid,environment_id,alg,state,created_at,
activated_at,retire_after,retired_at,public_jwk`; `public_jwk` omitted once
retired), `GET /signing-keys/:kid`, `POST /signing-keys` (201 `next` key; 422
`ENCRYPTION_KEY_REQUIRED` without `IAMKIT_ENCRYPTION_KEY`),
`POST /signing-keys/:kid/activate` (200; the previous active key becomes
`retiring` with `retire_after` 20 minutes ahead; 409 for a retired key) and
`POST /signing-keys/:kid/retire` (optional `{"force":true}`; 200; 409
`KEY_IN_USE` for the active key, or a retiring key before `retire_after`
without `force`). Writes need owner/admin and are audited
`signing_key.create`/`.activate`/`.retire`. A `kid` of another environment is 404.

### Features

[Feature flags](../../guides/feature-flags.md): `GET /features`
(`{"items":[…]}` of `name,description,scope,default,deployment,environment,
enabled,updated_at`; `deployment`/`environment` are `null` when unset),
`GET /features/:name` (404 `UNKNOWN_FEATURE`), `PUT /features/:name`
(`{"enabled":bool}`; 400 for a `deployment`-scoped feature) and
`DELETE /features/:name` (removes the override; 200 with the feature).
Writes need owner/admin and are audited `feature.updated`/`feature.reset`.

### Usage and limits

[Usage and limits](../../guides/usage-limits.md): `GET /limits`
(`{deployment, environment, effective, updated_at}`, maps of limit name to
value; a missing name is unlimited), `PUT /limits` (a map of limit name to a
number or `null`; replaces the environment's limits; workspace owners only,
403 otherwise; audited `limits.updated`) and `GET /usage?days=` (1–366,
default 30: `days`, `totals`, `now`). Creates past a total limit answer 422
`QUOTA_EXCEEDED`; rate limits answer 429 `QUOTA_EXCEEDED`.

### Actions

[Actions](../../guides/actions.md#api): `GET /action-conditions`,
`…/action-targets` (CRUD; create and `POST /:id/rotate-secret` return the
`whsec_` secret once; `POST /:id/test`), `GET /action-executions`,
`PUT`/`DELETE /action-executions/:condition` (`{"targets":[…]}` in call
order) and `GET /action-calls` (7-day call log). Writes need owner/admin and
are audited `action_target.*`/`action_execution.*`. Management API only.

Administrative inventories include `GET /sessions` (optional `user_id`, `organization_id` and `application_id` filters, combinable; newest first, each with
`authenticated_at`), `DELETE /sessions/:id` and
`GET /audit-events` under this prefix, plus `GET /events`, the typed
[event log](../events.md) (cursor-paged by event id; `GET /events/export`
streams it as NDJSON, and `GET /<users|organizations|applications|oauth-clients|roles|resources>/:id/history`
is one entity's [change history](../events.md#change-history)), and `…/webhooks`,
[event webhook](../event-webhooks.md) subscriptions with their delivery log. Sessions carry display labels
`user_name,user_email,organization_name,application_name,resource_name` and
audit events an `actor_label` (operator or end-user email; empty when unknown)
and a `target_label` (current name of the innermost entity in `target_id`, e.g.
the member for a membership path; empty when deleted or unnamed), its
`actor_kind` (`operator`, `user`, `service_account` or `system`) and the
`organization_id` its target lies in (null when none).
`GET /logout-deliveries` and `POST /logout-deliveries/:id/retry` expose
[back-channel logout](oauth-oidc.md) deliveries (a revoked session of a client
with a `backchannel_logout_uri` queues one). Session revocation affects online checks
and refresh; already issued JWTs require online checking to observe revocation
before expiry. These inventory endpoints return arrays, not the entity-list
pagination envelope. Do not assume a complete audit trail for every operation.

Failures use the [error contract](../errors-and-pagination.md): missing/expired
credentials → 401; insufficient authority → 403; unavailable environment → 404.
Console cookie errors often indicate HTTP instead of HTTPS or missing CSRF header.

Source: `internal/iam/management/adapters/mgmthttp/handler.go`,
`activity.go`, `mgmtsvc/control.go`, `internal/server/management.go`.
