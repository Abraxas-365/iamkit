#!/usr/bin/env bash
# Runs the custom sign-in UI parity journeys (e2e/journeys.spec.ts) against
# a disposable stack: Postgres (Docker), IAMKit built from this checkout,
# a TLS proxy (IAMKit's issuer and __Host- cookies need HTTPS), a mail
# webhook sink, and this Next.js app. Everything is removed on exit.
#
#   bash e2e/run.sh            # from examples/nextjs-login
#
# Needs: docker, go, node ≥ 20, openssl; `npx playwright install chromium`.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
stack="$here/e2e/.stack"
rm -rf "$stack" && mkdir -p "$stack"
name="iamkit-parity-$$"
pids=()

cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  docker rm -f "$name-db" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # url, what
  for _ in $(seq 1 60); do
    if curl --silent --fail --insecure "$1" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "$2 did not start; logs in $stack" >&2
  exit 1
}

iam_port=18080 app_port=13000 iam_tls=19443 app_tls=13443 sink_port=18025
export IAMKIT_URL="https://localhost:$iam_tls" APP_URL="https://localhost:$app_tls"

# TLS for localhost (self-signed; the browser and Node ignore the issuer).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$stack/tls.key" -out "$stack/tls.crt" 2>/dev/null
openssl genrsa -out "$stack/jwt.pem" 2048 2>/dev/null

db_password=$(openssl rand -hex 16)
docker run -d --name "$name-db" -p 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_PASSWORD="$db_password" -e POSTGRES_USER=iamkit -e POSTGRES_DB=iamkit postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do
  if docker exec "$name-db" pg_isready -U iamkit -d iamkit >/dev/null 2>&1; then break; fi
  sleep 1
done
db_port=$(docker port "$name-db" 5432/tcp | head -1 | cut -d: -f2)
sleep 2 # pg_isready answers before the init restart

(cd "$root" && go build -o "$stack/iamkit" ./cmd/iamkit)

node "$here/e2e/mailsink.mjs" >"$stack/mailsink.log" 2>&1 &
pids+=($!)
TLS_CERT="$stack/tls.crt" TLS_KEY="$stack/tls.key" PROXY_ROUTES="$iam_tls=$iam_port,$app_tls=$app_port" \
  node "$here/e2e/proxy.mjs" >"$stack/proxy.log" 2>&1 &
pids+=($!)

DATABASE_URL="postgres://iamkit:$db_password@127.0.0.1:$db_port/iamkit?sslmode=disable" \
  SERVER_PORT=$iam_port JWT_ISSUER="$IAMKIT_URL" JWT_PRIVATE_KEY_PATH="$stack/jwt.pem" \
  OIDC_HMAC_SECRET=$(openssl rand -hex 32) IAMKIT_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  EMAIL_PROVIDER=webhook EMAIL_WEBHOOK_URL="http://127.0.0.1:$sink_port/mail" \
  "$stack/iamkit" >"$stack/iamkit.log" 2>&1 &
pids+=($!)
wait_for "$IAMKIT_URL/health" IAMKit

DATABASE_URL="postgres://iamkit:$db_password@127.0.0.1:$db_port/iamkit?sslmode=disable" \
  "$stack/iamkit" bootstrap --email parity@example.com --workspace Parity --output "$stack/owner.json" >/dev/null
MGMT=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).management_key)' "$stack/owner.json")
export MGMT

# Node trusts the self-signed proxy only for this run.
export NODE_TLS_REJECT_UNAUTHORIZED=0
node "$here/e2e/seed.mjs" >"$stack/fixture.json"
client_id=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).clientId)' "$stack/fixture.json")
organization=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).organization)' "$stack/fixture.json")

(cd "$here" && IAMKIT_ISSUER="$IAMKIT_URL" IAMKIT_CLIENT_ID="$client_id" npx next build >"$stack/next-build.log" 2>&1)
(cd "$here" && IAMKIT_ISSUER="$IAMKIT_URL" IAMKIT_CLIENT_ID="$client_id" IAMKIT_ORGANIZATION_ID="$organization" \
  PORT=$app_port exec npx next start -p $app_port >"$stack/next.log" 2>&1) &
pids+=($!)
wait_for "$APP_URL/" "the Next.js app"

cd "$here"
E2E_FIXTURE="$stack/fixture.json" MAIL_SINK_URL="http://127.0.0.1:$sink_port" npx playwright test "$@"
