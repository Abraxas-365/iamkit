#!/usr/bin/env bash
# scripts/create-user.sh — Create a user in an environment.
# Outputs the user ID to stdout.
#
# Usage:
#   ./scripts/create-user.sh ENVIRONMENT_ID "Alice" "alice@example.com" [PASSWORD]
#   echo '{"name":"Alice","email":"alice@example.com"}' | \
#     ENVIRONMENT=ENV_ID ./scripts/create-user.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

if [[ $# -ge 2 ]]; then
  env_id="$1"; name="$2"; email="${3:?Usage: create-user.sh ENV_ID NAME EMAIL [PASSWORD]}"
  body=$(jq -nc --arg n "$name" --arg e "$email" '{name:$n,email:$e}')
  if [[ -n "${4:-}" ]]; then
    body=$(jq -c --arg p "$4" '. + {password:$p}' <<<"$body")
  fi
else
  env_id="${ENVIRONMENT:?Set ENVIRONMENT or pass ENV_ID as first arg}"
  body=$(cat)
fi

e=$(env_path "$env_id")
id=$(api_post "${e}/users" "$body" | extract_id)
info "Created user: ${id}"
printf '%s\n' "$id"
