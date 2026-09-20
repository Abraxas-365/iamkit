#!/usr/bin/env bash
# scripts/get-entity.sh — Fetch a single entity by ID.
# Outputs JSON to stdout.
#
# Usage:
#   ./scripts/get-entity.sh ENV_ID users USER_ID
#   ./scripts/get-entity.sh ENV_ID resources RESOURCE_ID
#   ./scripts/get-entity.sh ENV_ID applications APP_ID
#   ./scripts/get-entity.sh ENV_ID organizations ORG_ID
#   ./scripts/get-entity.sh ENV_ID roles ROLE_ID
#   ./scripts/get-entity.sh ENV_ID grants GRANT_ID
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: get-entity.sh ENV_ID ENTITY_TYPE ENTITY_ID}"
entity="${2:?Usage: get-entity.sh ENV_ID ENTITY_TYPE ENTITY_ID}"
entity_id="${3:?Usage: get-entity.sh ENV_ID ENTITY_TYPE ENTITY_ID}"

e=$(env_path "$env_id")
api_get "${e}/${entity}/${entity_id}"
