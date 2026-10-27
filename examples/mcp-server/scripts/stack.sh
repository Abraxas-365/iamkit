#!/usr/bin/env bash
# Starts a disposable local stack for the example: IAMKit built from this
# checkout behind TLS (MCP clients expect an https authorization server),
# a seeded environment (scripts/seed.mjs) and this MCP server. Prints how to
# connect MCP Inspector and Claude Code, then waits; Ctrl-C removes it all.
#
#   bash scripts/stack.sh                     # Postgres in Docker
#   IAMKIT_STACK_DSN=postgres://u@127.0.0.1:5432/postgres bash scripts/stack.sh
#                                             # or an existing server (a database is created and dropped)
#
# Needs: go, node ≥ 20, openssl, and docker unless IAMKIT_STACK_DSN is set.
# The issuer is https://localhost:$IAM_TLS with a self-signed certificate:
# trust it (NODE_EXTRA_CA_CERTS=.stack/tls.crt for Node clients) or use
# mkcert (MKCERT=1: certificate from the local mkcert CA).
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
stack="$here/.stack"
rm -rf "$stack" && mkdir -p "$stack"
name="iamkit-mcp-$$"
pids=()
db_name="iamkit_mcp_$$"

iam_port=${IAM_PORT:-18180} iam_tls=${IAM_TLS:-18443} mcp_port=${MCP_PORT:-3333}
export IAMKIT_URL="https://localhost:$iam_tls"

cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [[ -n "${IAMKIT_STACK_DSN:-}" ]]; then
    psql "$IAMKIT_STACK_DSN" -qc "DROP DATABASE IF EXISTS $db_name WITH (FORCE)" >/dev/null 2>&1 || true
  else
    docker rm -f "$name-db" >/dev/null 2>&1 || true
  fi
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

if [[ "${MKCERT:-}" == 1 ]]; then
  mkcert -cert-file "$stack/tls.crt" -key-file "$stack/tls.key" localhost 127.0.0.1 ::1 2>/dev/null
  ca="$(mkcert -CAROOT)/rootCA.pem"
else
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$stack/tls.key" -out "$stack/tls.crt" 2>/dev/null
  ca="$stack/tls.crt"
fi
openssl genrsa -out "$stack/jwt.pem" 2048 2>/dev/null

if [[ -n "${IAMKIT_STACK_DSN:-}" ]]; then
  psql "$IAMKIT_STACK_DSN" -qc "CREATE DATABASE $db_name" >/dev/null
  database_url=$(node -e 'const u=new URL(process.argv[1]);u.pathname="/"+process.argv[2];console.log(u.href)' "$IAMKIT_STACK_DSN" "$db_name")
else
  db_password=$(openssl rand -hex 16)
  docker run -d --name "$name-db" -p 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data \
    -e POSTGRES_PASSWORD="$db_password" -e POSTGRES_USER=iamkit -e POSTGRES_DB=iamkit postgres:16-alpine >/dev/null
  for _ in $(seq 1 30); do
    if docker exec "$name-db" pg_isready -U iamkit -d iamkit >/dev/null 2>&1; then break; fi
    sleep 1
  done
  sleep 2 # pg_isready answers before the init restart
  database_url="postgres://iamkit:$db_password@127.0.0.1:$(docker port "$name-db" 5432/tcp | head -1 | cut -d: -f2)/iamkit?sslmode=disable"
fi

(cd "$root" && GOWORK=off go build -o "$stack/iamkit" ./cmd/iamkit)

TLS_CERT="$stack/tls.crt" TLS_KEY="$stack/tls.key" PROXY_ROUTES="$iam_tls=$iam_port" \
  node "$root/examples/nextjs-login/e2e/proxy.mjs" >"$stack/proxy.log" 2>&1 &
pids+=($!)

DATABASE_URL="$database_url" SERVER_PORT=$iam_port JWT_ISSUER="$IAMKIT_URL" JWT_PRIVATE_KEY_PATH="$stack/jwt.pem" \
  OIDC_HMAC_SECRET=$(openssl rand -hex 32) IAMKIT_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  IAMKIT_TRUSTED_PROXIES=127.0.0.1 \
  "$stack/iamkit" >"$stack/iamkit.log" 2>&1 &
pids+=($!)
wait_for "$IAMKIT_URL/health" IAMKit

DATABASE_URL="$database_url" "$stack/iamkit" bootstrap --email mcp-owner@example.com --workspace MCP --output "$stack/owner.json" >/dev/null
MGMT=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).management_key)' "$stack/owner.json")
export MGMT MCP_RESOURCE_URL="http://localhost:$mcp_port/mcp"

NODE_EXTRA_CA_CERTS="$ca" node "$here/scripts/seed.mjs" >"$stack/fixture.json"
field() { node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1]))[process.argv[2]])' "$stack/fixture.json" "$1"; }

(cd "$here" && NODE_EXTRA_CA_CERTS="$ca" IAMKIT_ISSUER="$IAMKIT_URL" IAMKIT_ENVIRONMENT_ID="$(field environment)" \
  MCP_RESOURCE_URL="$MCP_RESOURCE_URL" PORT=$mcp_port exec npx tsx src/server.ts >"$stack/mcp.log" 2>&1) &
pids+=($!)
wait_for "http://127.0.0.1:$mcp_port/health" "the MCP server"

cat <<EOF

IAMKit        $IAMKIT_URL   (CA: $ca)
MCP server    $MCP_RESOURCE_URL
User          $(field email) / $(field password)   (notes:read; $(field writerEmail) also has notes:write)
Fixture       $stack/fixture.json

MCP Inspector (CLI):
  NODE_EXTRA_CA_CERTS=$ca npx @modelcontextprotocol/inspector --cli $MCP_RESOURCE_URL \\
    --client-id $(field inspectorClientId) --method tools/list

Claude Code:
  claude mcp add --transport http --client-id $(field claudeClientId) --callback-port 19876 iamkit-notes $MCP_RESOURCE_URL
  NODE_EXTRA_CA_CERTS=$ca claude      # then /mcp → iamkit-notes → Authenticate

Ctrl-C stops everything.
EOF
wait
