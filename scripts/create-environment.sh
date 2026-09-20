#!/usr/bin/env bash
# scripts/create-environment.sh — Create an environment inside a project.
# Outputs the environment ID to stdout.
#
# Usage:
#   ./scripts/create-environment.sh PROJECT_ID "Production"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

project="${1:?Usage: create-environment.sh PROJECT_ID NAME}"
name="${2:?Usage: create-environment.sh PROJECT_ID NAME}"

id=$(api_post "/projects/${project}/environments" "$(jq -nc --arg n "$name" '{name:$n}')" | extract_id)
info "Created environment: ${id}"
printf '%s\n' "$id"
