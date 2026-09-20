#!/usr/bin/env bash
# scripts/list-environments.sh — List environments in a project.
# Outputs JSON to stdout.
#
# Usage:
#   ./scripts/list-environments.sh PROJECT_ID
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

project_id="${1:?Usage: list-environments.sh PROJECT_ID}"
api_get "/projects/${project_id}/environments"
