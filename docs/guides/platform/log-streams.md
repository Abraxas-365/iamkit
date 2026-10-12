# Log streams

A **log stream** forwards IAMKit's [event log](../../reference/events.md) and the
applications' audit log events to a system you run: Datadog, Splunk, an S3
bucket or any HTTPS endpoint. Records are queued in the transaction that
creates them and delivered in order, in batches, by a background job.

Streams belong to an environment (and may be restricted to one organization,
see [scope and sources](#scope-and-sources)). They are managed under
`/management/v1/environments/:environment/log-streams` and, with
`iam:audit-logs:read` / `iam:audit-logs:manage`, under
`/api/v1/environments/:environment/log-streams`.

Secrets (Datadog API key, Splunk HEC token, S3 secret access key) are sealed
with [`IAMKIT_ENCRYPTION_KEY`](../../reference/configuration.md#encryption-key)
and never returned; without a key, creating a stream answers 422
`ENCRYPTION_KEY_REQUIRED`.

## Scope and sources

| Stream | `sources` | Receives |
| --- | --- | --- |
| Environment | `events`, `audit_logs` or both (default both) | Every event of the environment, and the audit log events of every organization |
| Organization | exactly `audit_logs` (default) | Only that organization's audit log events |

An environment has at most 10 streams of its own and an organization at most 5.

## Routes

| Route | Purpose |
| --- | --- |
| `GET`, `POST /log-streams` | List, create |
| `GET`, `PATCH`, `DELETE /log-streams/:id` | Read, change (`name`, `config`, `sources`, `secret`, `active`), delete. A `config` change that moves the stored secret elsewhere (Splunk `url`; S3 `endpoint`, `bucket`, `region`, `access_key_id`, `path_style`) needs `secret` in the same request |
| `POST /log-streams/:id/test` | Send one synthetic record now; answers `{delivered, status, error}` |
| `POST /log-streams/:id/enable` | Resume a disabled stream and clear its failure |
| `POST /log-streams/:id/rotate-secret` | `https` streams only: a new signing secret |
| `GET /log-streams/:id/deliveries?status=` | The delivery log (`pending`, `delivered`, `failed`) |
| `POST /log-streams/:id/deliveries/:delivery/retry` | Queue a failed delivery's batch again |

```sh
curl -X POST -H "Authorization: Bearer $IAMKIT_KEY" "$IAMKIT/management/v1/environments/$ENV/log-streams" -d '{
  "name": "SIEM", "destination": "datadog",
  "config": {"site": "datadoghq.eu", "service": "iam", "tags": ["env:prod"]},
  "secret": "<datadog api key>", "sources": ["events", "audit_logs"]
}'
```

## Organization administrators

An organization's administrators manage **its** streams (audit logs only; the
`sources` are forced to `["audit_logs"]` and `organization_id` cannot be
chosen) under
`/api/v1/environments/:environment/organizations/:organization/admin/log-streams`
with the same routes as above, including `…/deliveries` and
`…/deliveries/:delivery/retry`:

| Route | Permission |
| --- | --- |
| `GET /log-streams`, `GET /log-streams/:id`, `GET /log-streams/:id/deliveries` | `iam:org:audit:read` or `iam:org:log-streams:write` |
| `POST /log-streams`, `PATCH`, `DELETE /log-streams/:id`, `POST …/test`, `…/enable`, `…/rotate-secret`, `…/deliveries/:delivery/retry` | `iam:org:log-streams:write` |

Another organization's stream, or one of the environment, answers 404. Secrets
are returned once (create, rotate) and never again. Changes are recorded as
`log_stream.*` [events](../../reference/events.md) carrying the organization, so
they show in the organization's `GET …/admin/events`; the actor is the admin, or
the setup link.

A [setup link](../organizations/organization-administration.md#setup-links) with
the `log_streams` intent lets a customer's IT team connect their own SIEM without
an account. Its bearer reaches the log-stream routes only: the audit log itself
stays closed (403).

```go
admin := apiclient.New(baseURL, accessToken).Environment(envID).OrgAdmin(orgID)
created, err := admin.CreateLogStream(ctx, apiclient.LogStreamInput{
    Name: "SIEM", Destination: "https", Config: apiclient.LogStreamConfig{URL: "https://siem.example.com/ingest"}})
res, err := admin.TestLogStream(ctx, created.ID)
```

## Destinations

### Datadog

| Field | Meaning |
| --- | --- |
| `config.site` | One of `datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, `ap1.datadoghq.com`, `ddog-gov.com` |
| `config.service` | Optional `service` of every log |
| `config.tags` | Optional `ddtags`, at most 20 `key:value` entries |
| `secret` | Datadog API key (`DD-API-KEY`) |

Logs are posted to `https://http-intake.logs.<site>/api/v2/logs` as a JSON
array; each entry carries the record's fields plus `ddsource: "iamkit"`,
`ddtags`, `service` and a short `message` (the event type or audit action).

### Splunk

| Field | Meaning |
| --- | --- |
| `config.url` | HTTP Event Collector base URL (`https://splunk.example.com:8088`) |
| `config.index`, `config.source`, `config.sourcetype` | Optional HEC metadata |
| `secret` | HEC token (`Authorization: Splunk <token>`) |

Records are posted to `/services/collector/event` as concatenated HEC events
`{"time", "source", "sourcetype", "index", "event": {…payload}}`.

### HTTPS

| Field | Meaning |
| --- | --- |
| `config.url` | `https` endpoint |

IAMKit generates the signing secret (`whsec_…`) and returns it **once**, on
create and on `rotate-secret`; the previous secret keeps signing for the
[overlap](../../reference/event-webhooks.md#secrets). The body is a JSON array of
payloads, signed per [Standard Webhooks](https://www.standardwebhooks.com)
(`webhook-id` is stable across a batch's retries, `webhook-timestamp`,
`webhook-signature` with one `v1,` per live secret). Verify it with the
receiver code of [event webhooks](../../reference/event-webhooks.md).

### Amazon S3 and S3-compatible storage

| Field | Meaning |
| --- | --- |
| `config.bucket` | Bucket name |
| `config.region` | Region (`us-east-1`; any value for compatible servers that ignore it) |
| `config.prefix` | Optional key prefix, no leading slash or `..` |
| `config.endpoint` | Optional `https` endpoint of an S3-compatible server (MinIO, Cloudflare R2, Ceph, RustFS, …); no path |
| `config.path_style` | Path-style addressing (`endpoint/bucket/key`), needed by most compatible servers |
| `config.access_key_id` | Access key id |
| `secret` | Secret access key |

Each batch is one object, written once and never overwritten:

```text
<prefix>/<yyyy>/<mm>/<dd>/<HH>/<stream id>-<batch>.ndjson.gz
```

(UTC time of the batch's first record), `Content-Type: application/x-ndjson`,
`Content-Encoding: gzip`, one JSON payload per line. A retry of a batch whose
object already exists counts as delivered, so a lost response never duplicates
data. Grant the key **only** `s3:PutObject` on the prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::my-logs/iam/*"
  }]
}
```

Writes are conditional (`If-None-Match: *`); the server must support them
(Amazon S3, R2, MinIO and RustFS do). The `test` route writes a separate
`…-test-<n>.ndjson.gz` object.

## Payload

Every record is the same JSON object in every destination, built from the
record's own fields plus:

| Field | Meaning |
| --- | --- |
| `source` | `events` or `audit_logs` |
| `environment_id` | The environment |
| `occurred_at` | RFC 3339 time of the record |

`events` records carry the [event](../../reference/events.md) (`id`, `type`,
`actor`, `subject`, `organization_id`, `data`); `audit_logs` records carry
`id`, `organization_id`, `action`, `version`, `actor`, `targets`, `context` and
`metadata`.

## Delivery, retries and failure

- Each stream has one batch in flight at a time, in order (a retried older
  batch waits until the one in flight settles); a batch holds up to
  500 records / 1 MiB and is sent within 2 seconds of being queued.
- A send times out after 30 seconds. Failures retry with exponential backoff
  (15 seconds up to 1 hour) for 24 hours with the **same batch** — the same
  records and, for S3, the same object key — then the batch is `failed` and the
  next one proceeds. Retry a failed batch with the `retry` route.
- `response_status` and a short, secret-free `last_error` are kept on each
  delivery row.
- A stream failing continuously for 3 days is disabled (`disabled_reason:
  "failing"`, event `log_stream.disabled`); records keep queuing, and
  `POST …/enable` resumes it with a fresh 24-hour retry window for the backlog.
  Records that waited on a disabled stream for more than 7 days are marked
  `failed` (`last_error`: the stream was disabled for too long) and can still be
  retried. An operator-set `active: false` pauses delivery **and** stops new
  records being queued until it is enabled again. Finished deliveries are kept
  7 days.
- Requests go only to public addresses, never follow redirects and cap the
  response they read. For development, `IAMKIT_ALLOW_PRIVATE_DELIVERY` lifts the
  address guard (also for S3 endpoints).

Stream changes are audited as the events `log_stream.created`, `.updated`,
`.deleted`, `.secret_rotated`, `.delivery_retried` and `.disabled`. **Before
production cutover:** use the `test` route, verify the destination accepts its
format and authentication, then inspect `…/deliveries` after sending a known
event or app audit event; keep receiver-side deduplication because delivery is
at least once.
