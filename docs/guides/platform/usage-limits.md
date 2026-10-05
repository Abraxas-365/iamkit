# Usage and limits

IAMKit meters each environment per UTC day and enforces limits on what an
environment may create or send. The deployment sets caps for every
environment; an environment's own limits can only tighten them. Without
limits, nothing changes: every limit is unlimited by default.

## Limits

| Name | Bounds | When reached |
| --- | --- | --- |
| `users_max` | Users that exist (end users and machine users) | 422 `QUOTA_EXCEEDED` on user creation: API, signup, SCIM, invitation acceptance and federated first sign-in (JIT) |
| `organizations_max` | Organizations that exist | 422 `QUOTA_EXCEEDED` |
| `applications_max` | Applications that exist | 422 `QUOTA_EXCEEDED` |
| `requests_per_minute` | `/api/v1` requests to the environment, per minute | 429 `QUOTA_EXCEEDED` |
| `emails_per_day` | Emails sent, per UTC day (codes, invitations, verification) | 429 `QUOTA_EXCEEDED` on code requests (`POST /identity/v1/challenges`, sign-up, email factor codes) for any address; invitations are still created with `delivery: failed` |
| `sms_per_day` | SMS sent, per UTC day | 429 `QUOTA_EXCEEDED` |
| `action_calls_per_minute` | [Action](actions.md) target calls, per minute | The call is skipped like an open breaker (`action.failed`, outcome `skipped`); the flow fails only for `interrupt_on_error` targets |

Errors carry `details.limit` and `details.max`:

```json
{"error":{"type":"BUSINESS","code":"QUOTA_EXCEEDED","message":"the environment reached its users_max limit","details":{"limit":"users_max","max":5000}}}
```

Totals are checked with a count before each create, so concurrent creates
may overshoot a total by a few rows. Per-minute limits use fixed one-minute
windows. With [`REDIS_URL`](../../operations/scaling-and-abuse.md#redis-optional)
the replicas share one counter; without it each replica counts on its own, so
with *n* replicas behind a load balancer an environment may get up to *n* × the
limit (also while Redis is unavailable). An unavailable counter admits the
request (limits fail open).

### Deployment caps

`IAMKIT_LIMITS` holds comma-separated `name=value` pairs, read at start-up:

```sh
IAMKIT_LIMITS=users_max=10000,requests_per_minute=600,emails_per_day=5000
```

An unknown name, a negative value or one above 10¹² stops the server from
starting. `0` refuses everything a limit bounds.

### Environment limits

An environment's own limit applies when it is lower than the deployment
cap (the effective value is the smaller one); a higher one has no effect.
Only workspace owners change them; changes are audited as the
[event](../../reference/events.md) `limits.updated` (`data.limits`: the limits set)
and apply within 30 seconds on other replicas.

Console: **Settings → Usage and limits**. Owners edit the limits; an empty
field leaves the limit to the deployment.

API (under `/management/v1/environments/:environment`):

```sh
curl -H "Authorization: Bearer $IAMKIT_KEY" "$IAMKIT/management/v1/environments/$ENV/limits"
curl -X PUT -H "Authorization: Bearer $IAMKIT_KEY" -d '{"users_max":5000,"sms_per_day":null}' \
  "$IAMKIT/management/v1/environments/$ENV/limits"
```

`GET /limits` answers `{deployment, environment, effective, updated_at}`,
each a map of limit name to value (a missing name is unlimited). `PUT
/limits` replaces the environment's limits: a number limits, `null` or a
missing name leaves the limit to the deployment; `{}` clears them all.

CLI: `iam limits get`, `iam limits set users_max=5000 sms_per_day=none`,
`iam limits clear`. SDK: `Limits`, `SetLimits(ctx, map[string]int64)`.

## Usage

Daily usage counts, per environment and UTC day:

| Metric | Counts | Added |
| --- | --- | --- |
| `logins` | Sign-ins (`session.created`, not token exchanges or impersonation) | From the event log about a minute after they happen (`usage_rollup` job) |
| `users_created` | Created users (`user.created`) | Same |
| `tokens` | Access tokens issued (identity API, `/oauth/token`, device flow, machine tokens) | By each replica, written every 30 seconds and at shutdown |
| `emails`, `sms` | Messages delivered | Same |
| `action_calls` | Action target calls made | Same |
| `api_requests` | `/api/v1` requests to the environment | Same |

Console: **Settings → Usage and limits** (last 7, 30 or 90 days).

```sh
curl -H "Authorization: Bearer $IAMKIT_KEY" "$IAMKIT/management/v1/environments/$ENV/usage?days=7"
```

`GET /usage?days=` (1–366, default 30, today included) answers `days`
(oldest first, `{day, metrics}` with every metric), `totals` over the range
and `now`: users, organizations and applications that exist, with `max`
(`null` = unlimited). It is also served at `/api/v1/environments/:environment/usage`
with the `iam:usage:read` permission.

CLI: `iam usage --days 7`. SDK: `Usage(ctx, days)`.

Daily usage is kept for 400 days (`usage_prune` job). Counts of a replica
that crashes before writing them (up to 30 seconds) are lost.
