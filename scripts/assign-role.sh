#!/usr/bin/env bash
# scripts/assign-role.sh — Assign a role to a user in an organization.
#
# Usage:
#   ./scripts/assign-role.sh ENV_ID ORG_ID USER_ID ROLE_ID
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: assign-role.sh ENV_ID ORG_ID USER_ID ROLE_ID}"
org_id="${2:?Usage: assign-role.sh ENV_ID ORG_ID USER_ID ROLE_ID}"
user_id="${3:?Usage: assign-role.sh ENV_ID ORG_ID USER_ID ROLE_ID}"
role_id="${4:?Usage: assign-role.sh ENV_ID ORG_ID USER_ID ROLE_ID}"

e=$(env_path "$env_id")
api_post "${e}/role-assignments" "$(jq -nc \
  --arg o "$org_id" --arg u "$user_id" --arg r "$role_id" \
  '{organization_id:$o,user_id:$u,role_id:$r}')" >/dev/null
info "Assigned role ${role_id} to user ${user_id} in org ${org_id}"
