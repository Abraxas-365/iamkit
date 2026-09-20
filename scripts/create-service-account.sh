#!/usr/bin/env bash
# scripts/create-service-account.sh — Create a service account.
# Outputs the full credential JSON (id, secret, expires_at) to stdout.
# Capture the secret — it cannot be retrieved again.
#
# Usage:
#   ./scripts/create-service-account.sh ENV_ID "Deploy Bot" APP_ID RESOURCE_ID "api:read,api:write" [EXPIRES_IN]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: create-service-account.sh ENV_ID NAME APP_ID RESOURCE_ID PERMISSIONS [EXPIRES_IN]}"
name="${2:?Usage: create-service-account.sh ENV_ID NAME APP_ID RESOURCE_ID PERMISSIONS [EXPIRES_IN]}"
app_id="${3:?Usage: create-service-account.sh ENV_ID NAME APP_ID RESOURCE_ID PERMISSIONS [EXPIRES_IN]}"
resource_id="${4:?Usage: create-service-account.sh ENV_ID NAME APP_ID RESOURCE_ID PERMISSIONS [EXPIRES_IN]}"
permissions="${5:?Usage: create-service-account.sh ENV_ID NAME APP_ID RESOURCE_ID PERMISSIONS [EXPIRES_IN]}"
expires_in="${6:-24h}"

IFS=',' read -ra perms <<< "$permissions"
perms_json=$(printf '%s\n' "${perms[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

e=$(env_path "$env_id")
result=$(api_post "${e}/service-accounts" "$(jq -nc \
  --arg n "$name" --arg a "$app_id" --arg r "$resource_id" \
  --argjson p "$perms_json" --arg exp "$expires_in" \
  '{name:$n,application_id:$a,resource_id:$r,permissions:$p,expires_in:$exp}')")
info "Created service account: $(jq -r .id <<<"$result")"
printf '%s\n' "$result"
