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

The provided Compose file is a starting topology, not a substitute for ingress,
backup, database TLS and platform resource policies. Pin release digests rather
than `latest`. Credentials in environment variables are visible to users who can
inspect containers; restrict Docker/platform administration.

## Acceptance

Healthy API/database; correct issuer/JWKS; permitted and denied API requests;
working credential rotation; no leaked bootstrap keys; HTTPS cookies functioning;
restore tested in isolation. Use [launch checklist](launch-checklist.md).

## Failure and recovery

Stop traffic admission if startup/migrations fail. Do not delete volumes or edit
checksums to force boot. Inspect failure, use the identified previous image only
if schema-compatible, otherwise follow [backup/restore](backup-and-restore.md).
No release-pair compatibility or zero-downtime guarantee is implied without testing.
