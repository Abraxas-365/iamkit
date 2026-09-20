#!/usr/bin/env bash
# scripts/create-project.sh — Create a project.
# Outputs the project ID to stdout.
#
# Usage:
#   ./scripts/create-project.sh "My Project"
#   echo '{"name":"My Project"}' | ./scripts/create-project.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

if [[ $# -ge 1 ]]; then
  name="$1"
else
  name=$(jq -er '.name')
fi

id=$(api_post "/projects" "$(jq -nc --arg n "$name" '{name:$n}')" | extract_id)
info "Created project: ${id}"
printf '%s\n' "$id"
