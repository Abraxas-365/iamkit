#!/usr/bin/env bash
# scripts/create-role.sh — Create a role for a resource.
# Outputs the role ID to stdout.
#
# Usage:
#   ./scripts/create-role.sh ENV_ID "Editor" RESOURCE_ID "api:read,api:write"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: create-role.sh ENV_ID NAME RESOURCE_ID PERMISSIONS}"
name="${2:?Usage: create-role.sh ENV_ID NAME RESOURCE_ID PERMISSIONS}"
resource_id="${3:?Usage: create-role.sh ENV_ID NAME RESOURCE_ID PERMISSIONS}"
permissions="${4:?Usage: create-role.sh ENV_ID NAME RESOURCE_ID PERMISSIONS}"

IFS=',' read -ra perms <<< "$permissions"
perms_json=$(printf '%s\n' "${perms[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

e=$(env_path "$env_id")
id=$(api_post "${e}/roles" "$(jq -nc \
  --arg n "$name" --arg r "$resource_id" --argjson p "$perms_json" \
  '{name:$n,resource_id:$r,permissions:$p}')" | extract_id)
info "Created role: ${id}"
printf '%s\n' "$id"
