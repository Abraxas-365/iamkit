#!/usr/bin/env bash
# scripts/list-entities.sh — List entities in an environment.
# Outputs JSON to stdout.
#
# Usage:
#   ./scripts/list-entities.sh ENV_ID users
#   ./scripts/list-entities.sh ENV_ID resources --limit 50 --offset 0 --search "api"
#
# Supported entity types:
#   users, organizations, applications, resources, roles, grants,
#   service-accounts, sessions, audit-events, role-assignments
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: list-entities.sh ENV_ID ENTITY_TYPE [--limit N] [--offset N] [--search Q]}"
entity="${2:?Usage: list-entities.sh ENV_ID ENTITY_TYPE}"
shift 2

# Parse optional flags
limit="" offset="" search=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --limit)  limit="$2";  shift 2 ;;
    --offset) offset="$2"; shift 2 ;;
    --search) search="$2"; shift 2 ;;
    *) die "Unknown option: $1" ;;
  esac
done

e=$(env_path "$env_id")

# Build query string
qs=""
[[ -n "$limit" ]]  && qs="${qs}&limit=${limit}"
[[ -n "$offset" ]] && qs="${qs}&offset=${offset}"
[[ -n "$search" ]] && qs="${qs}&search=$(jq -Rr @uri <<<"$search")"
qs="${qs#&}"  # trim leading &
[[ -n "$qs" ]] && qs="?${qs}"

api_get "${e}/${entity}${qs}"
