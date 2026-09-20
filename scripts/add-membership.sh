#!/usr/bin/env bash
# scripts/add-membership.sh — Add a user to an organization.
#
# Usage:
#   ./scripts/add-membership.sh ENV_ID ORGANIZATION_ID USER_ID
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: add-membership.sh ENV_ID ORG_ID USER_ID}"
org_id="${2:?Usage: add-membership.sh ENV_ID ORG_ID USER_ID}"
user_id="${3:?Usage: add-membership.sh ENV_ID ORG_ID USER_ID}"

e=$(env_path "$env_id")
api_post "${e}/memberships" "$(jq -nc --arg o "$org_id" --arg u "$user_id" \
  '{organization_id:$o,user_id:$u}')" >/dev/null
info "Added user ${user_id} to organization ${org_id}"
