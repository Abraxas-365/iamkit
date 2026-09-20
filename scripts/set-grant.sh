#!/usr/bin/env bash
# scripts/set-grant.sh — Set (create/replace) a direct permission grant.
# Outputs the grant ID to stdout.
#
# Usage:
#   ./scripts/set-grant.sh ENV_ID ORG_ID USER_ID RESOURCE_ID "api:read,api:write"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: set-grant.sh ENV_ID ORG_ID USER_ID RESOURCE_ID PERMISSIONS}"
org_id="${2:?Usage: set-grant.sh ENV_ID ORG_ID USER_ID RESOURCE_ID PERMISSIONS}"
user_id="${3:?Usage: set-grant.sh ENV_ID ORG_ID USER_ID RESOURCE_ID PERMISSIONS}"
resource_id="${4:?Usage: set-grant.sh ENV_ID ORG_ID USER_ID RESOURCE_ID PERMISSIONS}"
permissions="${5:?Usage: set-grant.sh ENV_ID ORG_ID USER_ID RESOURCE_ID PERMISSIONS}"

IFS=',' read -ra perms <<< "$permissions"
perms_json=$(printf '%s\n' "${perms[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

e=$(env_path "$env_id")
id=$(api_put "${e}/grants" "$(jq -nc \
  --arg o "$org_id" --arg u "$user_id" --arg r "$resource_id" \
  --argjson p "$perms_json" \
  '{organization_id:$o,user_id:$u,resource_id:$r,permissions:$p}')" | extract_id)
info "Set grant: ${id}"
printf '%s\n' "$id"
