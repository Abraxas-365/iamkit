#!/usr/bin/env bash
# scripts/update-permissions.sh — Update a resource's permission catalog.
# Use this when deploying new API versions that add or change scopes.
#
# Usage:
#   ./scripts/update-permissions.sh ENV_ID RESOURCE_ID "New Name" "api:read,api:write,api:admin"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: update-permissions.sh ENV_ID RESOURCE_ID NAME PERMISSIONS}"
resource_id="${2:?Usage: update-permissions.sh ENV_ID RESOURCE_ID NAME PERMISSIONS}"
name="${3:?Usage: update-permissions.sh ENV_ID RESOURCE_ID NAME PERMISSIONS}"
permissions="${4:?Usage: update-permissions.sh ENV_ID RESOURCE_ID NAME PERMISSIONS}"

IFS=',' read -ra perms <<< "$permissions"
perms_json=$(printf '%s\n' "${perms[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

e=$(env_path "$env_id")
api_put "${e}/resources/${resource_id}" "$(jq -nc \
  --arg n "$name" --argjson p "$perms_json" \
  '{name:$n,permissions:$p}')" >/dev/null
info "Updated resource ${resource_id} permissions: ${permissions}"
