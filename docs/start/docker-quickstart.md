# Docker quickstart

**Outcome:** a healthy IAMKit backend and a private management credential. Run
commands from the repository root on a trusted workstation. Requires Docker
Compose v2, OpenSSL, curl and jq. The image builds Go inside Docker.

## 1. Configure the stack

Create `.env.docker` (ignored by Git) with these values. Generate separate random
values with `openssl rand -hex 32`; do not copy the placeholders literally.

```dotenv
POSTGRES_PASSWORD=REPLACE_WITH_RANDOM_HEX
OIDC_HMAC_SECRET=REPLACE_WITH_RANDOM_HEX
JWT_ISSUER=http://localhost:8080
IAMKIT_PORT=127.0.0.1:8080
```

The host port value binds the supplied Compose mapping to loopback. Keep the
internal port at 8080 for the image healthcheck. Do not set bootstrap variables
for this tutorial: explicit bootstrap writes a private file instead of logging a
management key. Compose requires the HMAC variable even for password-only use.

```sh
chmod 600 .env.docker
mkdir -p secrets .dev-secrets
chmod 700 secrets .dev-secrets
openssl genrsa -out secrets/jwt.pem 4096
chmod 600 secrets/jwt.pem
docker compose --env-file .env.docker -f docker-compose.production.yml build
```

Do not overwrite an existing signing key. Keep it stable across restarts. The
container runs as `iamkit`, not root. On an ordinary Linux bind mount, give that
identity read access without making the key world-readable:

```sh
CONTAINER_OWNER=$(docker compose --env-file .env.docker -f docker-compose.production.yml \
  run --rm --no-deps --entrypoint sh iamkit \
  -c 'printf "%s:%s" "$(id -u)" "$(id -g)"')
sudo chown "$CONTAINER_OWNER" secrets/jwt.pem
```

Rootless Docker and user namespace remapping need their own mapped ownership or
secret-mount setup. If startup says `read signing key failed`, fix mount access;
do not solve it with `chmod 644`.

## 2. Start and verify

```sh
docker compose --env-file .env.docker -f docker-compose.production.yml up -d --wait
curl --fail --silent --show-error http://localhost:8080/health
```

Expected: `{"status":"healthy","service":"iamkit"}`. Startup applies embedded
migrations. Use an empty database; do not point this tutorial at an existing
application schema. Data lives in the Compose named volume, not in the image.

## 3. Bootstrap without printing credentials

Create an output directory inside the container, owned by its runtime user:

```sh
docker compose --env-file .env.docker -f docker-compose.production.yml exec iamkit \
  sh -c 'mkdir -p /tmp/iamkit-bootstrap && chmod 700 /tmp/iamkit-bootstrap'
docker compose --env-file .env.docker -f docker-compose.production.yml exec iamkit \
  iamkit bootstrap --email owner@example.com --workspace InvoiceCloud \
  --output /tmp/iamkit-bootstrap/owner.json
docker compose --env-file .env.docker -f docker-compose.production.yml cp \
  iamkit:/tmp/iamkit-bootstrap/owner.json .dev-secrets/owner.json
chmod 600 .dev-secrets/owner.json
export MGMT=$(jq -er .management_key .dev-secrets/owner.json)
export IAMKIT_URL=http://localhost:8080
curl --fail --silent --show-error "$IAMKIT_URL/management/v1/me" \
  -H "X-API-Key: $MGMT"
```

Expected: a principal containing `workspace_id`, `operator_id` and `role: "owner"`.
Bootstrap is a one-time operation. The CLI refuses existing output files and an
already initialized workspace. Its credential expires in 24 hours. Store it in a
secret manager and rotate it before expiry; do not print it or enable shell tracing.

After secure storage, delete the temporary container copy:

```sh
docker compose --env-file .env.docker -f docker-compose.production.yml exec iamkit \
  rm /tmp/iamkit-bootstrap/owner.json
```

Next: [create your first application](first-application.md). To configure operator
password login, follow [management console](management-console.md).

## Restart and stop

`docker compose … stop` stops without deleting data; `start` resumes. Recreating
the backend runs migrations again but does not repeat explicit bootstrap. Avoid
`down --volumes` unless deliberately destroying this tutorial's data.

## Image-based deployments

The registry template is `docker-compose.iamkit.yml`; it expects
`IAMKIT_DB_PASSWORD` rather than `POSTGRES_PASSWORD`. Replace its image with a
verified release tag/digest and use the same non-root key and secret precautions.
A configured image reference does not establish that the package is public. See
[release verification](../maintainers/releases.md).

## Troubleshooting

- **Unhealthy:** inspect `docker compose … logs iamkit` and database health. Never
  share unredacted logs if automatic bootstrap was enabled elsewhere.
- **401 on management API:** use `X-API-Key`, not `Authorization: Bearer`; check expiry.
- **Invalid issuer:** HTTP is allowed only for loopback. Browser federation/OAuth
  and console flows require HTTPS; see [reverse proxy](../operations/reverse-proxy.md).
- **Bootstrap conflict:** the database already has a workspace. Use existing
  credentials or owner recovery, not volume deletion.
