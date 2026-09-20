#!/usr/bin/env bash
# scripts/lib.sh — Shared helpers for IAMKit management scripts.
# Source this file; do not execute it directly.
#
# Required env:
#   IAMKIT_URL   — Base URL, e.g. http://localhost:8080
#   IAMKIT_KEY   — Management API key (ik_mgmt_…)
#
# Optional env:
#   IAMKIT_QUIET — Set to 1 to suppress stderr info messages.
set -euo pipefail

: "${IAMKIT_URL:?IAMKIT_URL is required (e.g. http://localhost:8080)}"
: "${IAMKIT_KEY:?IAMKIT_KEY is required (ik_mgmt_… management key)}"

_base="${IAMKIT_URL%/}/management/v1"

# ── Logging ──────────────────────────────────────────────────────────
info()  { [[ "${IAMKIT_QUIET:-}" == "1" ]] || printf '• %s\n' "$*" >&2; }
warn()  { printf 'WARN: %s\n' "$*" >&2; }
die()   { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ── HTTP helpers ─────────────────────────────────────────────────────
# _api METHOD PATH [BODY]
# Sends a JSON request to the management API.
# Prints the response body to stdout. Exits non-zero on HTTP errors.
_api() {
  local method="$1" path="$2" body="${3:-}"
  local url="${_base}${path}"
  local -a args=(
    --fail --silent --show-error
    --request "$method"
    -H "X-API-Key: ${IAMKIT_KEY}"
    -H 'Content-Type: application/json'
  )
  if [[ -n "$body" ]]; then
    args+=(--data-binary "$body")
  fi
  curl "${args[@]}" "$url"
}

# Convenience wrappers — output raw JSON to stdout.
api_get()    { _api GET    "$1"; }
api_post()   { _api POST   "$1" "$2"; }
api_put()    { _api PUT    "$1" "$2"; }
api_patch()  { _api PATCH  "$1" "$2"; }
api_delete() { _api DELETE "$1"; }

# ── JSON helpers ─────────────────────────────────────────────────────
# extract_id — reads JSON from stdin, prints the .id field.
extract_id() { jq -er '.id'; }

# require_cmd — abort if a command is missing.
require_cmd() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
  done
}

# ── Environment prefix ──────────────────────────────────────────────
# env_path ENVIRONMENT_ID — returns the /environments/:id prefix.
env_path() { printf '/environments/%s' "$1"; }

require_cmd curl jq
