# Observability

`GET /health` returns 200 `{status:"healthy",service:"iamkit",workers:"running",cache:"none"}`
when the database ping succeeds, otherwise 503. It is a dependency health signal,
not proof that mail, provider discovery, token exchange or business authorization
work. `workers` is `running`, `disabled` (`IAMKIT_WORKERS=false`), `idle` (not
started yet) or `stopped` (shutting down). `cache` is `none` without `REDIS_URL`,
else `up` or `down`; Redis being down never fails the check, because IAMKit
falls back to the database (see [Redis](scaling-and-abuse.md#redis-optional)).

## Background jobs

The server binary also runs background jobs (back-channel logout delivery and
pruning; `event_prune`, which deletes [events](../reference/events.md) past
`IAMKIT_EVENT_RETENTION`; `event_webhook` and `event_webhook_maintenance`,
which send [event webhooks](../reference/event-webhooks.md) and disable
failing subscriptions; `action_call_prune`; `usage_rollup` and `usage_prune`,
which add sign-ins and created users to the [daily usage](../guides/usage-limits.md#usage)
and prune it). Each replica also writes its in-memory usage counters every
30 seconds and at shutdown, whether or not it runs workers. Every replica runs them by default; they claim database rows with
`FOR UPDATE SKIP LOCKED`, so replicas never process the same row. Set
`IAMKIT_WORKERS=false` on API-only replicas — at least one replica must keep
them on, or back-channel logout notifications and event webhooks stay queued. On `SIGTERM` jobs
stop with the server; an interrupted delivery is retried by the next round.

## Request logs and request ids

Every request is logged once, after the error handler, with method, path, route
template, final status, latency and IP. Each request gets an id: a caller's
`X-Request-Id` of 1–128 characters from `A-Z a-z 0-9 . _ : -` is kept, anything
else is replaced by a random 32-hex-digit id. The id is echoed in the
`X-Request-Id` response header (exposed to CORS callers) and added as
`request_id` to every log line written while serving the request; with tracing
on, lines also carry `trace_id` and `span_id`. Quote the request id in support
tickets and search logs by it.

Do not log headers/cookies/request bodies containing credentials. Automatic
bootstrap logs its key, so prefer explicit bootstrap.

## Tracing and metrics

IAMKit uses [OpenTelemetry](https://opentelemetry.io/). Nothing is exported
until you configure it with the standard variables:

| Variable | Effect |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Base URL of an OTLP/HTTP collector (for example `http://otel-collector:4318`); turns on traces and metrics |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Per-signal endpoint; turns on that signal only |
| `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER` | `otlp` forces the signal on, `none` keeps it off |
| `OTEL_EXPORTER_OTLP_HEADERS` | Collector authentication headers |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Sampling, for example `parentbased_traceidratio` and `0.1` (default: always, honoring the caller's decision) |
| `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME` | Extra resource attributes (`deployment.environment=prod`); the service name defaults to `iamkit` |
| `OTEL_SDK_DISABLED=true` | Turns all export off, including the Prometheus listener |
| `IAMKIT_METRICS_ADDR` | Serves metrics in the Prometheus format at `http://<addr>/metrics` on a separate listener, for example `127.0.0.1:9464` or `:9464` inside a private network. Never expose it publicly and never set it to the public port |

Only OTLP over HTTP (protobuf) is supported. Incoming W3C `traceparent` headers
are continued, so a request traced by your gateway or application joins the same
trace; outbound calls forward only the trace context, never incoming baggage.

### Spans

- One server span per request, named `METHOD /route/template` (health checks are
  not traced), with status code and route.
- One span per SQL statement (statement text only — values are bound parameters
  and never recorded).
- One client span per outbound call: identity provider discovery and token
  requests, SAML metadata, `jwks_uri` fetches, email and SMS providers,
  webhooks, back-channel logout and the breached-password check.

### Metrics

Labels are low-cardinality only: route templates, methods, results and fixed
enumerations — never emails, user or tenant ids, or raw paths.

| Metric (OTLP name) | Type | Labels |
| --- | --- | --- |
| `http.server.request.duration` | histogram, s | `http.request.method`, `http.route`, `http.response.status_code` |
| `iamkit.sign_ins` | counter | `method` (`pwd`, `email`, `fed`, `hwk`, `other`), `result` (`success`, `failure`), `mfa` |
| `iamkit.mfa.failures` | counter | — |
| `iamkit.oauth.token_requests` | counter | `grant_type` (known grants, else `other`), `result` |
| `iamkit.delivery.attempts`, `iamkit.delivery.duration` | counter, histogram s | `channel` (`email`, `sms`), `source` (`environment`, `global`, `none`), `purpose`, `result` |
| `iamkit.logout.deliveries` | counter | `result` (`delivered`, `retried`, `failed`) |
| `iamkit.webhook.deliveries` | counter | `result` (`delivered`, `retried`, `failed`) |
| `iamkit.worker.round.duration` | histogram, s | `job`, `result` |
| `iamkit.worker.lag` | gauge, s | `job` — how long the oldest due item has waited (0 when none) |
| `iamkit.cache.lookups` | counter | `family` (`feature`, `action`, `oidc`), `result` (`hit`, `miss`, `error`) — only with `REDIS_URL` |
| `http.client.request.duration` | histogram, s | method, `server.address`, status code |
| `db.sql.connection.open`, `.max_open`, `.wait`, `.wait_duration` | pool gauges and counters | `status` (`idle`, `inuse`) on `open` |
| `db.client.operation.duration` | histogram, s | `db.operation.name` |

`iamkit.sign_ins` counts sessions created (every sign-in path, including
federation, passkeys and MFA completions) and wrong passwords; a failure never
records which account. `iamkit.mfa.failures` counts wrong second-factor answers.
Prometheus names add unit suffixes: `http_server_request_duration_seconds`,
`iamkit_sign_ins_total`, and so on. The Prometheus listener also exposes Go
runtime and process metrics.

A starter Grafana dashboard for the Prometheus listener is in
[`grafana-dashboard.json`](grafana-dashboard.json)
(import it and pick your Prometheus data source).

## Monitor

- HTTP availability, error rate/latency and 429 rate by route
  (`http_server_request_duration_seconds` by `http_route` and status).
- Sign-in failure ratio and MFA failures (credential stuffing, broken IdP).
- Email/SMS delivery failures by source; back-channel logout failures.
- Background job lag (`iamkit_worker_lag_seconds`) and failed rounds: a growing
  lag means no replica runs workers or the jobs cannot keep up.
- PostgreSQL connectivity, storage growth, connection/lock pressure and backup age
  (pool metrics show waits for connections).
- Credential/provider-secret expiry and failed token exchanges.
- Synthetic permitted login/API request and denied cross-tenant request.
- Restore rehearsal age and actual recovery duration.

Keep synthetic credentials isolated, rotated and redacted.

Alert response: check health and database first; correlate request failures with
recent deploy/config changes (the request id and trace lead from a log line to
every query and outbound call of that request); inspect delivery/provider outages
separately. Retain audit records according to your privacy policy, but do not
claim every management operation has exhaustive audit coverage. See
[troubleshooting](troubleshooting.md) and [incident response](incident-response.md).
