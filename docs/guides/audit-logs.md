# App audit logs

An app audit log records what **your application's users did** — `invoice.paid`,
`document.shared`, `member.removed` — so you can show it to your customers per
organization. It is separate from IAMKit's own [event log](../reference/events.md),
which records what happened *inside IAMKit*: app events never enter that log,
have their own retention and have their own permissions.

Events are immutable: there is no route to change or delete one. They leave only
when they pass the retention.

## Register an action first

An event must name a registered **action**, per environment. Registering gives:

- `name` — dotted lowercase words, at most 100 characters (`invoice.paid`).
- `target_types` — the types of target the action accepts (at most 20, such as
  `invoice` or `credit_note`).
- `schema` — optional JSON Schemas (draft 2020-12, no remote `$ref`) for the
  event's `metadata`, for the actor's metadata (`actor`) and for the metadata of
  each target type (`targets.<type>`); each at most 16 KiB.

```http
POST /management/v1/environments/{environment}/audit-logs/actions
{
  "name": "invoice.paid",
  "description": "An invoice was paid",
  "target_types": ["invoice"],
  "schema": {
    "metadata": {"type": "object", "required": ["amount"],
                 "properties": {"amount": {"type": "number", "minimum": 0}}}
  }
}
```

An environment holds at most 500 actions. Every change of the target types or
the schemas raises the action's `version` (a new description does not). Events
record the version they were validated with and are never re-validated. Deleting
an action keeps its events, with their action name.

## Emit an event

```http
POST /management/v1/environments/{environment}/audit-logs/events
Idempotency-Key: pay-7f3a
{
  "organization_id": "…",
  "action": "invoice.paid",
  "occurred_at": "2026-05-01T12:00:00Z",
  "actor":   {"type": "user", "id": "u-ana", "name": "Ana"},
  "targets": [{"type": "invoice", "id": "inv-1"}],
  "context": {"location": "PE", "user_agent": "Mozilla/5.0"},
  "metadata": {"amount": 10, "currency": "USD"}
}
```

The answer is `201 {"id", "created_at"}`. `version` is optional: when given it must
be the action's current one (422 `AUDIT_ACTION_VERSION`).

| Rule | Refusal |
| --- | --- |
| The action is registered | 422 `UNKNOWN_AUDIT_ACTION` |
| The organization exists in the environment | 422 `UNKNOWN_ORGANIZATION` |
| `occurred_at` is at most 5 minutes ahead and within the retention | 400 |
| Every target `type` is one of the action's `target_types` | 422 `AUDIT_TARGET_TYPE` |
| `metadata`, the actor's and each target's metadata match the action's schemas | 422 `AUDIT_SCHEMA_VIOLATION` |
| Fields have the shape below | 400 |
| The body is at most 64 KiB | 413 |
| The environment's `audit_events_per_minute` [limit](platform/usage-limits.md) has room | 429 `QUOTA_EXCEEDED` |

Limits: at most 50 targets; `type`, `id` and `name` at most 255 characters, no
control characters; `context.location` at most 255 and `context.user_agent` at
most 1024; every metadata object has at most 50 keys (each at most 40
characters) with string (at most 500 characters), number (at most 32 characters
and 10^15 in magnitude) or boolean values — no nesting.

### Idempotency

Send an `Idempotency-Key` (at most 255 characters) so a retry never records an
event twice. The key is bound to the SHA-256 of the **canonical request** (member
order, whitespace, key order and time zone do not matter):

- the same key and request again answers `201` with the **original** event's id
  and `created_at` and records nothing (it costs no quota);
- the same key with a different request is 409 `IDEMPOTENCY_KEY_REUSED`;
- concurrent first uses of a key record one event.

There is no expiry of its own: a key answers for as long as its event exists, so
it frees up when the [retention](#retention) prunes the event. Use unique keys
per logical event (an order id, a UUID).

## Read the log

`GET …/audit-logs/events` pages by cursor, never by offset: `{"items", "next"}`.
Without `after` it reads newest first and `next` is the `before` of the following
page (`0` when the log is exhausted); with `after` (`0` = the beginning) it reads
oldest first, a feed, and `next` is the `after` to continue with. `limit` defaults
to 50, at most 200. A feed reader should stay a few seconds behind the newest
event: an event whose emit committed late can carry a lower `seq` than one
already read, and `after` would skip it. The log streams below have no such gap.

| Filter | Matches |
| --- | --- |
| `organization_id` | one organization |
| `action` | exact action names; repeat it or comma-separate |
| `actor_id`, `actor_type` | the actor |
| `target_id`, `target_type` | one target having all the given members |
| `occurred_after`, `occurred_before` | RFC 3339, inclusive |

`GET …/audit-logs/events/{id}` reads one event.

## Export

`GET …/audit-logs/events/export?format=ndjson|csv` streams every matching event,
oldest first (`after` continues a previous export; the filters above apply).
NDJSON is one event per line. CSV has the columns `id`, `occurred_at`,
`organization_id`, `action`, `version`, `actor_type`, `actor_id`, `actor_name`,
`targets` (JSON), `location`, `user_agent`, `metadata` (JSON); a cell that starts
with `=`, `+`, `-` or `@` gets a leading `'` so spreadsheets do not run it.

## Permissions

The management routes are for operators. On `/api/v1/environments/{environment}/audit-logs/…`
a token needs:

| Permission | Allows |
| --- | --- |
| `iam:audit-logs:read` | list, read and export events; list and read actions |
| `iam:audit-logs:write` | emit events |
| `iam:audit-logs:manage` | create, change and delete actions (their schemas) |

Changes to actions are recorded in IAMKit's event log (`audit_log_action.created`,
`.updated`, `.deleted`).

## Organization administrators

An organization's own administrators read and export **their organization's**
events, and nobody else's, under
`/api/v1/environments/{environment}/organizations/{organization}/admin`:

| Route | Permission |
| --- | --- |
| `GET /audit-logs` | `iam:org:audit:read` |
| `GET /audit-logs/export?format=ndjson\|csv` | `iam:org:audit:read` |

They take the filters, cursors and formats above, except `organization_id`:
the caller's organization is always used (a different value is ignored). Setup
links with the `log_streams` intent cannot read the log (they hold
`iam:org:log-streams:write` only). Organization streams are described in
[log streams](platform/log-streams.md#organization-administrators).

## SDKs

```go
events := apiclient.New(baseURL, accessToken).Environment(envID)
receipt, err := events.CreateAuditLogEvent(ctx, apiclient.AuditLogInput{
    OrganizationID: orgID, Action: "invoice.paid", OccurredAt: time.Now(),
    Actor:   apiclient.AuditLogParty{Type: "user", ID: "u-ana"},
    Targets: []apiclient.AuditLogParty{{Type: "invoice", ID: "inv-1"}},
}, "payment-8841") // idempotency key; "" for none
page, err := events.AuditLogEvents(ctx, apiclient.AuditLogFilter{Actions: []string{"invoice.paid"}})
body, err := events.ExportAuditLogEvents(ctx, apiclient.AuditLogFilter{}, apiclient.AuditLogFormatNDJSON)
defer body.Close() // an io.ReadCloser; apiclient.DecodeAuditLogEvents reads NDJSON
mine := events.OrgAdmin(orgID).AuditLogEvents // organization administrators
```

```ts
import { AuditLogsClient, decodeAuditLogEvents } from "@iamkit/node";

const logs = new AuditLogsClient({ baseUrl: "https://iam.example.com", token: () => accessToken() });
await logs.createEvent(envId, event, { idempotencyKey: "payment-8841" });
const page = await logs.listEvents(envId, { action: ["invoice.paid"], limit: 50 });
for await (const e of decodeAuditLogEvents(await logs.exportEvents(envId))) console.log(e.seq);
```

See the [Go SDK](../reference/sdk/management.md#audit-logs-and-log-streams) and the
[Node.js SDK](../reference/sdk/node.md#audit-logs).

## Retention

Events are deleted after `IAMKIT_AUDIT_LOG_RETENTION` (default `8760h`, 365 days,
at least `24h`; Go duration), measured from when they were recorded, by the
hourly `audit_log_prune` [background job](../operations/observability.md#background-jobs).
Pruning is the only way an event is deleted (a database trigger refuses any other
`UPDATE` or `DELETE`; deleting an organization or environment removes its events).

## Usage

`audit_events_per_minute` ([usage limits](platform/usage-limits.md)) bounds
ingest per environment and per minute; each accepted event counts in the daily
`audit_events` usage.
