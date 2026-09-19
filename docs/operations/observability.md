# Observability

`GET /health` returns 200 `{status:"healthy",service:"iamkit"}` when the database
ping succeeds, otherwise 503. It is a dependency health signal, not proof that
mail, provider discovery, token exchange or business authorization work.

Request logging records method, path, status, latency and IP. Validate error-status
reporting in your logging pipeline; middleware timing can differ from the final
error-handler response. Do not log headers/cookies/request bodies containing
credentials. Automatic bootstrap logs its key, so prefer explicit bootstrap.

## Monitor

- HTTP availability, error rate/latency and 429 rate by endpoint family.
- PostgreSQL connectivity, storage growth, connection/lock pressure and backup age.
- Credential/provider-secret expiry, failed exchanges and mail-delivery rejection.
- Synthetic permitted login/API request and denied cross-tenant request.
- Restore rehearsal age and actual recovery duration.

Supply metrics collection/alert delivery through your platform; do not assume a
Prometheus endpoint exists. Keep synthetic credentials isolated, rotated and
redacted. Do not include user email or token values as high-cardinality labels.

Alert response: check health and database first; correlate request failures with
recent deploy/config changes; inspect delivery/provider outages separately.
Retain audit records according to your privacy policy, but do not claim every
management operation has exhaustive audit coverage. See
[troubleshooting](troubleshooting.md) and [incident response](incident-response.md).
