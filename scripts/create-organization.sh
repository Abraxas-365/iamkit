#!/usr/bin/env bash
# scripts/create-organization.sh — Create an organization in an environment.
# Outputs the organization ID to stdout.
#
# Usage:
#   ./scripts/create-organization.sh ENVIRONMENT_ID "Acme Corp"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: create-organization.sh ENV_ID NAME}"
name="${2:?Usage: create-organization.sh ENV_ID NAME}"

e=$(env_path "$env_id")
id=$(api_post "${e}/organizations" "$(jq -nc --arg n "$name" '{name:$n}')" | extract_id)
info "Created organization: ${id}"
printf '%s\n' "$id"
