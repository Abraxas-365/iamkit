#!/usr/bin/env bash
# Disposable smoke test of the Compose deployments (deploy/compose/<variant>):
# starts the variant on local ports with an image you built, without ACME
# (Traefik serves its default certificate, Caddy its internal CA), and
# checks HTTPS health, the HTTP redirect, HSTS, the issuer, forwarded client
# addresses and the optional Redis and collector profiles. Removes only its
# own Compose project.
#
#   docker build -t iamkit:local . && deploy/compose/smoke.sh traefik iamkit:local
set -euo pipefail
variant=${1:?usage: smoke.sh <traefik|caddy> <image>}
image=${2:?usage: smoke.sh <traefik|caddy> <image>}
root=$(cd "$(dirname "$0")" && pwd)
src="$root/$variant"
work=$(mktemp -d)
project="iamkit-smoke-$variant-$$"
free() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
http=${SMOKE_HTTP_PORT:-$(free)}
https=${SMOKE_HTTPS_PORT:-$(free)}
domain=iam.localhost

# A copy of the variant, so its .env and secrets stay untouched.
cp -R "$src" "$work/$variant"
cp "$root/setup.sh" "$root/otel-collector.yaml" "$work/"
dir="$work/$variant"
rm -rf "$dir/.env" "$dir/secrets"
compose() { docker compose -p "$project" --project-directory "$dir" -f "$dir/compose.yml" "$@"; }
cleanup() {
  status=$?
  if [ $status -ne 0 ]; then compose logs --tail 40 >&2 || true; fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
  exit $status
}
trap cleanup EXIT

bash "$work/setup.sh" "$variant" "$domain" ops@example.com >/dev/null
if bash "$work/setup.sh" "$variant" "$domain" ops@example.com >/dev/null 2>&1; then
  echo "setup.sh overwrote an existing configuration" >&2
  exit 1
fi
{
  echo "IAMKIT_IMAGE=$image"
  echo "IAMKIT_HTTP_PORT=$http"
  echo "IAMKIT_HTTPS_PORT=$https"
  echo "EDGE_SUBNET=${SMOKE_EDGE_SUBNET:-10.89.$((200 + RANDOM % 50)).0/24}"
  echo "COMPOSE_PROFILES=redis,otel"
  echo "REDIS_URL=redis://redis:6379/0"
  echo "OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318"
} >>"$dir/.env"
if [ "$variant" = caddy ]; then
  # No ACME offline: Caddy's internal CA instead (in the copy only).
  sed 's/^\temail {$ACME_EMAIL}$/&\n\tlocal_certs/' "$src/Caddyfile" >"$dir/Caddyfile"
  grep -q local_certs "$dir/Caddyfile"
else
  # No ACME offline: an unknown resolver makes Traefik serve its default
  # certificate without contacting Let's Encrypt.
  echo "IAMKIT_ACME_CHALLENGE=none" >>"$dir/.env"
fi

compose up -d --wait --wait-timeout 180 >/dev/null
base="https://$domain:$https"
curlx() { curl --silent --show-error --insecure --resolve "$domain:$https:127.0.0.1" --resolve "$domain:$http:127.0.0.1" "$@"; }
for i in $(seq 1 60); do
  if curlx --fail "$base/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
health=$(curlx --fail "$base/health")
echo "$health" | grep -q '"status":"healthy"' || { echo "health: $health" >&2; exit 1; }
for i in $(seq 1 20); do
  health=$(curlx --fail "$base/health")
  echo "$health" | grep -q '"cache":"up"' && break
  sleep 1
done
echo "$health" | grep -q '"cache":"up"' || { echo "redis not used: $health" >&2; exit 1; }

headers=$(curlx --include --output /dev/null --dump-header - "$base/health")
echo "$headers" | grep -qi '^strict-transport-security: max-age=31536000' || { echo "no HSTS: $headers" >&2; exit 1; }
redirect=$(curlx --output /dev/null --write-out '%{http_code} %{redirect_url}' "http://$domain:$http/health")
case $redirect in 30[178]\ https://$domain*) ;; *) echo "no HTTPS redirect: $redirect" >&2; exit 1 ;; esac

issuer=$(curlx --fail "$base/.well-known/openid-configuration" | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')
[ "$issuer" = "https://$domain" ] || { echo "issuer = $issuer" >&2; exit 1; }

# The proxy names the client: a spoofed X-Forwarded-For from outside must
# not reach IAMKit's request log as the client address.
curlx --fail --output /dev/null -H 'X-Forwarded-For: 203.0.113.66' "$base/.well-known/jwks.json"
sleep 1
logged=$(compose logs iamkit 2>/dev/null | grep 'path=/.well-known/jwks.json' | tail -1)
proxy=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$(compose ps -q "$variant")")
client=$(echo "$logged" | sed -n 's/.* ip=\([^ ]*\).*/\1/p')
[ -n "$client" ] || { echo "no request log line: $logged" >&2; exit 1; }
[ "$client" != 203.0.113.66 ] || { echo "spoofed client address accepted: $logged" >&2; exit 1; }
case " $proxy " in *" $client "*) echo "proxy address logged, not the client: $logged" >&2; exit 1 ;; esac

# The collector receives IAMKit's telemetry.
for i in $(seq 1 30); do
  if compose logs otel-collector 2>/dev/null | grep -qE 'Traces|Metrics'; then break; fi
  sleep 2
done
compose logs otel-collector 2>/dev/null | grep -qE 'Traces|Metrics' || { echo "collector received nothing" >&2; exit 1; }

# Restart keeps the key volume readable and the database.
compose restart iamkit >/dev/null
for i in $(seq 1 60); do
  if curlx --fail "$base/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curlx --fail "$base/health" >/dev/null
echo "$variant: HTTPS health, redirect, HSTS, issuer, client address, Redis, collector and restart checks passed."
