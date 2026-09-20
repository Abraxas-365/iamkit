#!/usr/bin/env bash
# scripts/create-application.sh — Create an application in an environment.
# Outputs the application ID to stdout.
#
# Usage:
#   ./scripts/create-application.sh ENV_ID "Web App" "http://localhost:3000/callback,http://localhost:3000/auth"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: create-application.sh ENV_ID NAME [REDIRECT_URIS]}"
name="${2:?Usage: create-application.sh ENV_ID NAME [REDIRECT_URIS]}"
redirect_uris="${3:-}"

if [[ -n "$redirect_uris" ]]; then
  IFS=',' read -ra uris <<< "$redirect_uris"
  redirects=$(printf '%s\n' "${uris[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')
else
  redirects='[]'
fi

e=$(env_path "$env_id")
id=$(api_post "${e}/applications" "$(jq -nc --arg n "$name" --argjson r "$redirects" '{name:$n,redirect_uris:$r}')" | extract_id)
info "Created application: ${id}"
printf '%s\n' "$id"
