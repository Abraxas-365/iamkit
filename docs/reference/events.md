# Event log

Every change in an environment — and every sign-in — is recorded as a typed
event in the same database transaction as the change itself. The log is the
source for activity views, integrations that poll for changes and, later,
webhook subscriptions. It sits beside the audit trail (`GET …/audit-events`),
which keeps the raw action text and target path of each management call.

## Reading the log

```http
GET /management/v1/environments/ENVIRONMENT_ID/events?type=user.*&limit=50
X-API-Key: ik_mgmt_…
```

The same route is served as `GET /api/v1/environments/ENVIRONMENT_ID/events`
to tokens holding `iam:events:read` (see [scoped IAM](api/scoped-iam.md)).

| Parameter | Meaning |
| --- | --- |
| `type` | Exact types (`user.created`) or families (`user.*`), comma-separated or repeated; at most 20 |
| `subject` | Only events about this subject id |
| `organization_id` | Only events in this organization |
| `after` | Oldest first, events with an id greater than this one (`0` = from the beginning) |
| `before` | Newest first, events with an id smaller than this one |
| `limit` | Page size, default 50, at most 200 |

`after` and `before` cannot be combined. Without either the newest events come
first. The response is not the offset envelope of other lists — the log only
grows, so it pages by event id:

```json
{
  "items": [
    {
      "id": 1042,
      "environment_id": "…",
      "type": "user.created",
      "actor": { "kind": "operator", "id": "…" },
      "subject": { "kind": "user", "id": "…" },
      "organization_id": "…",
      "data": { "origin": "api" },
      "occurred_at": "2026-09-30T14:36:53.12Z"
    }
  ],
  "next": 1042
}
```

`next` is the cursor of the following page. With `after`, pass it as `after`
again: it is the newest id returned, or the cursor you sent when nothing new
arrived, so a poller can loop forever on `after=next`. Without `after`, pass it
as `before`; `0` means the log is exhausted.

Event ids increase with commit order within a transaction but transactions
commit concurrently, so a poller that must not miss events should re-read a
short window (for example the last few seconds) behind its cursor and ignore
ids it has already processed.

## Actors

| `actor.kind` | Who |
| --- | --- |
| `operator` | A workspace operator (console or management key) |
| `user` | An end user acting on themself (sign-in, sign-up, self-service, organization administration) |
| `service_account` | A service account through `/api/v1` or token exchange |
| `directory` | A SCIM provisioning credential (`actor.id` = the credential) |
| `system` | IAMKit itself (expiry, background jobs); `actor.id` is empty |

## Types

Types are `<subject>.<verb>`. The catalog lives in
`internal/iam/event/catalog.go`; the main families:

| Family | Types |
| --- | --- |
| `user.*` | `created` (`data.origin`: `api`, `signup`, `invitation`, `federation`, `scim`), `updated`, `deactivated`, `reactivated`, `deleted`, `locked`, `unlocked`, `signed_up`, `provisioned` / `deprovisioned` (SCIM; `data.mode` `claimed`, `reactivated` or `adopted`), `profile_updated`, `profile_synced`, `metadata_set`, `metadata_deleted`, `phone_verified`, `phone_removed`, `access_token_created`, `access_token_revoked`, `key_added`, `key_removed` |
| `organization.*`, `membership.*` | `organization.created`/`updated`/`metadata_*`; `membership.created`/`updated`/`removed` (subject = the user, `data.organization_id`; a SCIM change of the membership's `active` or display name is `membership.updated` with `data.changes`, actor `directory`) |
| `group.*`, `domain.*`, `org_unit.*`, `position.*` | Organization structure |
| `application.*`, `oauth_client.*`, `resource.*`, `role.*`, `grant.*`, `group_role.*`, `resource_grant.*` | Applications, clients, resources and access (`application.resource_linked`, `role.created` (`data.resource_id`), `role.assigned` (subject = the user, `data.organization_id`, `role_id`), `group_role.assigned` (subject = the group), `grant.updated`, `resource_grant.updated`/`deleted` (subject = the grant, `data.resource_id`, `granted_organization_id`, `role_ids` — `null` = every role; `organization_id` = the owner organization when its administrator made the change), …) |
| `service_account.*`, `connection.*`, `identity.*`, `provisioning_*` | Machine credentials, federation, SCIM |
| `session.*`, `login.*` | `session.created` (every sign-in; `data.amr`, `data.user_id`, application and client), `session.revoked`, `login.failed` (wrong password; `data.failures`, `data.locked`) |
| `mfa.*` | `enrolled`, `removed`, `reset`, `locked`, `recovery_used`, `recovery_regenerated`, `clone_detected` |
| `webhook.*` | `created`, `updated`, `deleted`, `secret_rotated`, `replayed`, `delivery_retried`, `disabled` (by IAMKit after three days of failures; actor `system`) |
| `action.*`, `action_target.*`, `action_execution.*` | [Actions](../guides/actions.md): `action.failed` (a target failed or was skipped; subject = the target, `data.condition`, `outcome`, `error`, `interrupted`; actor `system`), `action_target.created`/`updated`/`deleted`/`secret_rotated`, `action_execution.updated`/`deleted` (subject = the condition) |
| Settings | `branding.*`, `sign_in_options.*`, `password_policy.*`, `sign_in_policy.*`, `delivery.*`, `email_template.*`, `sign_in_texts.*`, `sms.*`, `signing_key.*`, `saml_service_provider.*`, `feature.*` (`updated`: `data.enabled`; `reset`; subject = the feature name), `limits.updated` (`data.limits`: the environment's limits) |

`data` never contains secrets, password hashes or codes. Unknown fields may be
added to `data` at any time; new types may be added to a family.

## Change history

Updates of users, organizations, applications, OAuth clients, roles and
resources carry what changed as `data.changes`, `{"field": [old, new]}`:

```json
{
  "type": "user.updated",
  "subject": { "kind": "user", "id": "…" },
  "data": {
    "changes": {
      "name": ["Al", "Alice"],
      "metadata.plan": [null, "pro"]
    }
  }
}
```

- JSON object columns are compared per key (`metadata.plan`, `profile.department`);
  a key that appears or disappears has `null` on the missing side.
- Several updates of one row in a transaction collapse to the first old and the
  last new value; an update that changes nothing records nothing.
- Never recorded: password and secret hashes, key sets, lock counters, sign-in
  timestamps and bookkeeping columns (`id`, `environment_id`, `created_at`,
  `updated_at`, `version`, `password_changed_at`).
- One transaction records the changes of at most 100 rows (bulk updates such as
  an organization's deletion clearing its users' home organization); later
  rows' events have no `changes`.

The changes are captured by database triggers in the transaction of the
update (migration 047), so every path that updates these tables (console, API,
SCIM, federation profile refresh) records them without extra code.

### Per-entity history

`GET …/environments/:environment/<collection>/:id/history` lists one entity's
events newest first, in the log's envelope (`before`, `limit` ≤ 200 and `type`
filters; `after` is refused). Collections: `users`, `organizations`,
`applications`, `oauth-clients`, `roles`, `resources`. On `/api/v1` it needs
`iam:events:read` and the collection's read permission (`iam:users:read`,
`iam:orgs:read`, `iam:apps:read`, `iam:roles:read`, `iam:resources:read`;
OAuth clients are management-only). The console shows it as the **History**
section of the user, organization, application, OAuth client and resource
pages.

### Export

`GET …/environments/:environment/events/export` streams the matching events
oldest first as NDJSON (`application/x-ndjson`, one event per line, same
fields as the log) for archiving past the retention. It takes the log's
filters (`type`, `subject`, `organization_id`) and `after` (default the
beginning); `before` is refused. To archive incrementally, remember the last
exported `id` and pass it as `after` next time. On `/api/v1` it needs
`iam:events:read`.

## Webhooks

To have events pushed to you instead of polling, add an
[event webhook](event-webhooks.md) subscription.

## Retention

Events older than `IAMKIT_EVENT_RETENTION` (a Go duration, default `2160h` =
90 days, at least `1h`) are deleted hourly by the `event_prune`
[background job](../operations/observability.md#background-jobs). Export what
you need to keep longer with [export](#export).

## CLI

```sh
iam events list --type user.* --type login.failed
iam events list --after 0 --limit 200   # read the log as a feed
iam events history users 33b4…          # one entity's history with its changes
iam events export --file events.ndjson  # archive (resume with --after <last id>)
```
