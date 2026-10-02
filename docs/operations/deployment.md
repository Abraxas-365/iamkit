# Deployment runbook

**Goal:** expose a pinned IAMKit backend behind TLS with durable PostgreSQL,
protected keys and a tested recovery path. Assign an operator responsible for
backups, credential rotation and incident response before rollout.

## Preflight

- Identify the exact image digest/commit, database version and migration state.
- Choose a stable HTTPS `JWT_ISSUER`. Changing it changes token trust.
- Use a dedicated PostgreSQL database and least-privileged network access.
- Generate/store an RSA signing key (2048+ bits) and stable OAuth HMAC secret.
- Mount the key read-only for the non-root container user; back it up separately.
- Configure only trusted CORS origins, provider bindings and delivery endpoints.
- Allow outbound DNS from the backend if organizations verify domains; it uses
  the system resolver (10 s timeout) and looks up TXT records only on request.
- Choose explicit bootstrap to avoid printing credentials in logs.

## Procedure

1. Follow [Docker quickstart](../start/docker-quickstart.md) in a staging installation.
2. Replace local port publishing with private ingress. Apply TLS and path routing
   from [reverse proxy](reverse-proxy.md); keep PostgreSQL off public networks.
3. Set every required container variable from [configuration](../reference/configuration.md).
   Compose interpolation is not automatic secret injection.
4. Start the database, apply migrations/start IAMKit, verify `/health`.
5. Bootstrap once using a private output mount/file; verify management `/me`.
6. Provision a test app and run login/denial checks through the **public HTTPS
   origin**, not only container localhost.
7. Verify the built-in operator console loads at the root URL and cookie login/logout works.
8. Configure monitoring, backups and a restore rehearsal before serving real users.

The root `docker-compose.production.yml` is a local starting topology; for a
public host use one of the deployments below. None of them replaces backups,
database TLS and platform resource policies. Pin release digests rather
than `latest`. Credentials in environment variables are visible to users who can
inspect containers; restrict Docker/platform administration.

## Compose with TLS

`deploy/compose/` runs IAMKit, PostgreSQL and a TLS proxy on one Docker host,
with Redis and an OpenTelemetry collector as optional profiles:

| Variant | Proxy | Certificates |
| --- | --- | --- |
| `deploy/compose/caddy` | Caddy 2 (simplest) | Automatic (Let's Encrypt/ZeroSSL), renewed by Caddy |
| `deploy/compose/traefik` | Traefik v3 | Let's Encrypt, HTTP-01 (port 80) or TLS-ALPN-01 (port 443) |

Both redirect HTTP to HTTPS, send HSTS (one year), keep PostgreSQL and Redis
on an internal network, run IAMKit read-only without capabilities, and trust
forwarded headers only from the proxy's network
([forwarded headers](reverse-proxy.md#forwarded-headers)).

1. Point the domain's DNS at the host and open ports 80 and 443.
2. Generate the configuration (never overwrites an existing one):

   ```sh
   deploy/compose/setup.sh caddy iam.example.com ops@example.com
   ```

   It writes `deploy/compose/caddy/.env` (random PostgreSQL password, HMAC
   secret and encryption key; mode 600) and `secrets/jwt.pem` (RSA 4096).
   Back both up privately: they cannot be regenerated without invalidating
   tokens and stored secrets. Set `IAMKIT_IMAGE` to a pinned release.
3. Start and check:

   ```sh
   cd deploy/compose/caddy
   docker compose up -d --wait
   curl https://iam.example.com/health
   ```

4. Bootstrap the owner as in step 5 above (`docker compose exec iamkit iamkit bootstrap … --output /tmp/owner.json`).

Optional services are Compose profiles in `.env`: `COMPOSE_PROFILES=redis` with
`REDIS_URL=redis://redis:6379/0` ([Redis](scaling-and-abuse.md#redis-optional)),
`otel` with `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`
([tracing and metrics](observability.md#tracing-and-metrics); edit
`deploy/compose/otel-collector.yaml` to export to your backend). Any other
variable from [configuration](../reference/configuration.md) goes in `.env`
too. If the proxy network's subnet overlaps one of the host's, set
`EDGE_SUBNET`.

`deploy/compose/smoke.sh <variant> <image>` starts a variant on free local
ports with internal certificates and checks HTTPS health, the redirect, HSTS,
the issuer, the client address, Redis, the collector and a restart; CI runs
it for both variants.

## Kubernetes (Helm)

The chart `deploy/helm/iamkit` (published as `oci://ghcr.io/abraxas-365/charts/iamkit`
with each release) deploys IAMKit only: bring PostgreSQL (and optionally Redis)
and create the Secrets first.

```sh
kubectl create secret generic iamkit \
  --from-literal=DATABASE_URL='postgres://iamkit:…@db:5432/iamkit?sslmode=require' \
  --from-literal=OIDC_HMAC_SECRET="$(openssl rand -hex 32)" \
  --from-literal=IAMKIT_ENCRYPTION_KEY="$(openssl rand -base64 32)"
kubectl create secret generic iamkit-signing --from-file=jwt.pem=secrets/jwt.pem
helm install iamkit oci://ghcr.io/abraxas-365/charts/iamkit --version <release> \
  --set issuer=https://iam.example.com \
  --set database.existingSecret=iamkit \
  --set secrets.hmac.existingSecret=iamkit \
  --set secrets.encryption.existingSecret=iamkit \
  --set secrets.signingKey.existingSecret=iamkit-signing \
  --set ingress.enabled=true --set ingress.className=nginx \
  --set ingress.tls.secretName=iamkit-tls \
  --set 'trustedProxies={10.244.0.0/16}'
```

What the chart sets up:

- **Migrations** run in a pre-install/pre-upgrade hook Job (`iamkit migrate`)
  before the Deployment changes; migrations hold a PostgreSQL advisory lock, so
  pods starting meanwhile wait for it. A failed Job fails the upgrade and leaves
  the running pods untouched (`migrations.job=false` leaves it to the pods).
- **Probes** on `/health`: startup (up to 5 minutes for first migrations),
  readiness, and liveness tolerant of a short database outage. Rolling updates
  keep every old pod until a new one is ready; a `preStop` pause and a 40 s
  grace period let HTTP, background jobs and the usage flush drain.
- **Security**: non-root (uid 100), read-only root, no capabilities, no
  service-account token; the signing key is a Secret volume, the other secrets
  `secretKeyRef`s — the chart never holds secret values.
- **Scaling**: `replicaCount` 2, optional HPA (`autoscaling.enabled`), a PDB
  (`minAvailable: 1`). Background jobs run on every replica and coordinate in
  the database; `workers.enabled=false` turns them off for a release (keep one
  release with them). Set `redis.existingSecret` for shared rate limits.
- **Metrics**: `metrics.enabled` serves Prometheus on port 9464 of the
  Service (never the Ingress); `metrics.serviceMonitor.enabled` adds a
  Prometheus Operator `ServiceMonitor`.
- `helm test <release>` checks `/health` and the issuer from inside the cluster.

Other settings: `env` (plain variables), `extraEnv` (e.g. `SMTP_PASSWORD` from
a Secret), `envFrom`, `resources`, `nodeSelector`, `affinity`,
`topologySpreadConstraints`; see `values.yaml`. CI lints and installs the chart
on kind with chart-testing (`.github/workflows/deploy.yml`).

## Acceptance

Healthy API/database; correct issuer/JWKS; permitted and denied API requests;
working credential rotation; no leaked bootstrap keys; HTTPS cookies functioning;
restore tested in isolation. Use [launch checklist](launch-checklist.md).

## Failure and recovery

Stop traffic admission if startup/migrations fail. Do not delete volumes or edit
checksums to force boot. Inspect failure, use the identified previous image only
if schema-compatible, otherwise follow [backup/restore](backup-and-restore.md).
No release-pair compatibility or zero-downtime guarantee is implied without testing.
