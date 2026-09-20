#!/usr/bin/env bash
# scripts/list-projects.sh — List all projects in the workspace.
# Outputs JSON to stdout.
#
# Usage:
#   ./scripts/list-projects.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

api_get "/projects"
