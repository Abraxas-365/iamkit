#!/usr/bin/env bash
# scripts/delete-entity.sh — Delete/suspend/revoke an entity by ID.
# Works for: users (suspend), roles, grants, service-accounts (revoke),
#            role-assignments, application-resources.
#
# Usage:
#   ./scripts/delete-entity.sh ENV_ID users USER_ID
#   ./scripts/delete-entity.sh ENV_ID roles ROLE_ID
#   ./scripts/delete-entity.sh ENV_ID grants GRANT_ID
#   ./scripts/delete-entity.sh ENV_ID service-accounts ACCOUNT_ID
#   ./scripts/delete-entity.sh ENV_ID role-assignments ROLE_ID/ORG_ID/USER_ID
#   ./scripts/delete-entity.sh ENV_ID application-resources APP_ID/RESOURCE_ID
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: delete-entity.sh ENV_ID ENTITY_TYPE ENTITY_ID}"
entity="${2:?Usage: delete-entity.sh ENV_ID ENTITY_TYPE ENTITY_ID}"
entity_id="${3:?Usage: delete-entity.sh ENV_ID ENTITY_TYPE ENTITY_ID}"

e=$(env_path "$env_id")
api_delete "${e}/${entity}/${entity_id}"
info "Deleted ${entity}/${entity_id}"
