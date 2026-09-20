#!/usr/bin/env bash
# scripts/update-role.sh — Update an existing role's name and permissions.
#
# Usage:
#   ./scripts/update-role.sh ENV_ID ROLE_ID "New Name" RESOURCE_ID "api:read,api:write,api:admin"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: update-role.sh ENV_ID ROLE_ID NAME RESOURCE_ID PERMISSIONS}"
role_id="${2:?Usage: update-role.sh ENV_ID ROLE_ID NAME RESOURCE_ID PERMISSIONS}"
name="${3:?Usage: update-role.sh ENV_ID ROLE_ID NAME RESOURCE_ID PERMISSIONS}"
resource_id="${4:?Usage: update-role.sh ENV_ID ROLE_ID NAME RESOURCE_ID PERMISSIONS}"
permissions="${5:?Usage: update-role.sh ENV_ID ROLE_ID NAME RESOURCE_ID PERMISSIONS}"

IFS=',' read -ra perms <<< "$permissions"
perms_json=$(printf '%s\n' "${perms[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

e=$(env_path "$env_id")
api_put "${e}/roles/${role_id}" "$(jq -nc \
  --arg n "$name" --arg r "$resource_id" --argjson p "$perms_json" \
  '{name:$n,resource_id:$r,permissions:$p}')" >/dev/null
info "Updated role ${role_id}"
