#!/usr/bin/env bash
# Disposable Docker smoke test. Creates and removes only its own named resources.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
name="iamkit-docs-$RANDOM-$$"
tmp=$(mktemp -d)
cleanup() {
  docker rm -f "$name-api" "$name-db" >/dev/null 2>&1 || true
  docker volume rm "$name-key" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
umask 077
openssl genrsa -out "$tmp/jwt.pem" 2048 2>/dev/null
password=$(openssl rand -hex 24)
hmac=$(openssl rand -hex 32)
image=${IAMKIT_TEST_IMAGE:-iamkit-docs-validation:local}
owner=$(docker run --rm --entrypoint sh "$image" -c 'printf "%s:%s" "$(id -u)" "$(id -g)"')
docker network create "$name" >/dev/null
docker volume create "$name-key" >/dev/null
docker run --rm --user 0 --entrypoint sh -v "$tmp:/input:ro" -v "$name-key:/secrets" "$image" -c "cp /input/jwt.pem /secrets/jwt.pem && chmod 600 /secrets/jwt.pem && chown $owner /secrets/jwt.pem"
docker run -d --name "$name-db" --network "$name" --tmpfs /var/lib/postgresql/data -e POSTGRES_PASSWORD="$password" -e POSTGRES_USER=iamkit -e POSTGRES_DB=iamkit postgres:16-alpine >/dev/null
for i in {1..30}; do
  if docker exec "$name-db" pg_isready -U iamkit -d iamkit >/dev/null 2>&1; then break; fi
  sleep 1
done
docker run -d --name "$name-api" --network "$name" -p 127.0.0.1::8080 -v "$name-key:/secrets:ro" \
  -e DATABASE_URL="postgres://iamkit:$password@$name-db:5432/iamkit?sslmode=disable" \
  -e JWT_PRIVATE_KEY_PATH=/secrets/jwt.pem -e JWT_ISSUER=http://localhost:8080 -e OIDC_HMAC_SECRET="$hmac" "$image" >/dev/null
port=$(docker port "$name-api" 8080/tcp | cut -d: -f2)
export IAMKIT_URL="http://127.0.0.1:$port"
for i in {1..30}; do
  if curl --fail --silent "$IAMKIT_URL/health" >/dev/null; then break; fi
  sleep 1
done
curl --fail --silent "$IAMKIT_URL/health" | jq -e '.status=="healthy"' >/dev/null
docker exec "$name-api" iamkit bootstrap --email docs@example.com --workspace Docs --output /tmp/owner.json >/dev/null
docker cp "$name-api:/tmp/owner.json" "$tmp/owner.json" >/dev/null
export MGMT=$(jq -er .management_key "$tmp/owner.json")
export DEMO_PASSWORD=$(openssl rand -hex 16)
export OUTPUT="$tmp/onboarding.json"
bash "$root/docs/examples/onboarding/run.sh"
docker restart "$name-api" >/dev/null
# Docker may assign a different ephemeral host port after restart.
port=$(docker port "$name-api" 8080/tcp | cut -d: -f2)
export IAMKIT_URL="http://127.0.0.1:$port"
for i in {1..30}; do
  if curl --fail --silent "$IAMKIT_URL/health" >/dev/null; then break; fi
  sleep 1
done
curl --fail --silent "$IAMKIT_URL/management/v1/me" -H "X-API-Key: $MGMT" | jq -e '.role=="owner"' >/dev/null
printf 'Docker build runtime, non-root key mount, explicit bootstrap and restart checks passed.\n'
