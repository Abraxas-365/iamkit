#!/usr/bin/env bash
# scripts/link-app-resource.sh — Link an application to a resource.
#
# Usage:
#   ./scripts/link-app-resource.sh ENV_ID APPLICATION_ID RESOURCE_ID
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: link-app-resource.sh ENV_ID APP_ID RESOURCE_ID}"
app_id="${2:?Usage: link-app-resource.sh ENV_ID APP_ID RESOURCE_ID}"
resource_id="${3:?Usage: link-app-resource.sh ENV_ID APP_ID RESOURCE_ID}"

e=$(env_path "$env_id")
api_post "${e}/application-resources" "$(jq -nc --arg a "$app_id" --arg r "$resource_id" \
  '{application_id:$a,resource_id:$r}')" >/dev/null
info "Linked application ${app_id} → resource ${resource_id}"
