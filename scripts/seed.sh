#!/usr/bin/env bash
# scripts/seed.sh — Bootstrap a project, environment, resource, application,
# user, organization, membership, and grant in a single run.
#
# Designed for deployment init scripts and CI pipelines.
# Outputs a JSON object with all created IDs to stdout.
#
# Required env:
#   IAMKIT_URL, IAMKIT_KEY (see lib.sh)
#
# Optional env (defaults in parentheses):
#   PROJECT_NAME       ("Default")
#   ENVIRONMENT_NAME   ("Development")
#   ORG_NAME           ("Default")
#   APP_NAME           ("Web App")
#   APP_REDIRECT_URIS  ("http://localhost:3000/callback")  — comma-separated
#   RESOURCE_NAME      ("API")
#   RESOURCE_PREFIX    ("api")
#   RESOURCE_AUDIENCE  ("http://localhost:8080")
#   RESOURCE_PERMS     ("api:read,api:write")              — comma-separated
#   USER_NAME          ("Admin")
#   USER_EMAIL         ("admin@example.com")
#   USER_PASSWORD      — if set, creates user with password
#   GRANT_PERMISSIONS  — defaults to RESOURCE_PERMS
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# ── Defaults ──────────────────────────────────────────────────────────
PROJECT_NAME="${PROJECT_NAME:-Default}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-Development}"
ORG_NAME="${ORG_NAME:-Default}"
APP_NAME="${APP_NAME:-Web App}"
APP_REDIRECT_URIS="${APP_REDIRECT_URIS:-http://localhost:3000/callback}"
RESOURCE_NAME="${RESOURCE_NAME:-API}"
RESOURCE_PREFIX="${RESOURCE_PREFIX:-api}"
RESOURCE_AUDIENCE="${RESOURCE_AUDIENCE:-http://localhost:8080}"
RESOURCE_PERMS="${RESOURCE_PERMS:-api:read,api:write}"
USER_NAME="${USER_NAME:-Admin}"
USER_EMAIL="${USER_EMAIL:-admin@example.com}"
GRANT_PERMISSIONS="${GRANT_PERMISSIONS:-${RESOURCE_PERMS}}"

# ── Helpers ──────────────────────────────────────────────────────────
csv_to_json_array() {
  local -a items
  IFS=',' read -ra items <<< "$1"
  printf '%s\n' "${items[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))'
}

# ── Create entities ──────────────────────────────────────────────────
info "Creating project: ${PROJECT_NAME}"
project_id=$(api_post "/projects" "$(jq -nc --arg n "$PROJECT_NAME" '{name:$n}')" | extract_id)
info "  → project: ${project_id}"

info "Creating environment: ${ENVIRONMENT_NAME}"
environment_id=$(api_post "/projects/${project_id}/environments" "$(jq -nc --arg n "$ENVIRONMENT_NAME" '{name:$n}')" | extract_id)
info "  → environment: ${environment_id}"

e=$(env_path "$environment_id")

info "Creating organization: ${ORG_NAME}"
org_id=$(api_post "${e}/organizations" "$(jq -nc --arg n "$ORG_NAME" '{name:$n}')" | extract_id)
info "  → organization: ${org_id}"

redirects=$(csv_to_json_array "$APP_REDIRECT_URIS")
info "Creating application: ${APP_NAME}"
app_id=$(api_post "${e}/applications" "$(jq -nc --arg n "$APP_NAME" --argjson r "$redirects" '{name:$n,redirect_uris:$r}')" | extract_id)
info "  → application: ${app_id}"

perms=$(csv_to_json_array "$RESOURCE_PERMS")
info "Creating resource: ${RESOURCE_NAME}"
resource_id=$(api_post "${e}/resources" "$(jq -nc \
  --arg n "$RESOURCE_NAME" --arg p "$RESOURCE_PREFIX" \
  --arg a "$RESOURCE_AUDIENCE" --argjson perms "$perms" \
  '{name:$n,prefix:$p,audience:$a,permissions:$perms}')" | extract_id)
info "  → resource: ${resource_id}"

info "Linking application → resource"
api_post "${e}/application-resources" "$(jq -nc --arg a "$app_id" --arg r "$resource_id" \
  '{application_id:$a,resource_id:$r}')" >/dev/null

user_body=$(jq -nc --arg n "$USER_NAME" --arg e "$USER_EMAIL" '{name:$n,email:$e}')
if [[ -n "${USER_PASSWORD:-}" ]]; then
  user_body=$(jq -c --arg p "$USER_PASSWORD" '. + {password:$p}' <<<"$user_body")
fi
info "Creating user: ${USER_EMAIL}"
user_id=$(api_post "${e}/users" "$user_body" | extract_id)
info "  → user: ${user_id}"

info "Adding membership: ${USER_EMAIL} → ${ORG_NAME}"
api_post "${e}/memberships" "$(jq -nc --arg o "$org_id" --arg u "$user_id" \
  '{organization_id:$o,user_id:$u}')" >/dev/null

grant_perms=$(csv_to_json_array "$GRANT_PERMISSIONS")
info "Setting grant: ${USER_EMAIL} → ${RESOURCE_NAME}"
grant_id=$(api_put "${e}/grants" "$(jq -nc \
  --arg o "$org_id" --arg u "$user_id" --arg r "$resource_id" \
  --argjson p "$grant_perms" \
  '{organization_id:$o,user_id:$u,resource_id:$r,permissions:$p}')" | extract_id)
info "  → grant: ${grant_id}"

info "Seed complete."

# ── Output ───────────────────────────────────────────────────────────
jq -nc \
  --arg project "$project_id" \
  --arg environment "$environment_id" \
  --arg organization "$org_id" \
  --arg application "$app_id" \
  --arg resource "$resource_id" \
  --arg user "$user_id" \
  --arg grant "$grant_id" \
  '{project_id:$project,environment_id:$environment,organization_id:$organization,application_id:$application,resource_id:$resource,user_id:$user,grant_id:$grant}'
