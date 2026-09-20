#!/usr/bin/env bash
# scripts/create-resource.sh — Create a resource (API audience + permission catalog).
# Outputs the resource ID to stdout.
#
# Usage:
#   ./scripts/create-resource.sh ENV_ID "Invoices API" invoices https://api.example.com "invoices:read,invoices:write"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

env_id="${1:?Usage: create-resource.sh ENV_ID NAME PREFIX AUDIENCE PERMISSIONS}"
name="${2:?Usage: create-resource.sh ENV_ID NAME PREFIX AUDIENCE PERMISSIONS}"
prefix="${3:?Usage: create-resource.sh ENV_ID NAME PREFIX AUDIENCE PERMISSIONS}"
audience="${4:?Usage: create-resource.sh ENV_ID NAME PREFIX AUDIENCE PERMISSIONS}"
permissions="${5:?Usage: create-resource.sh ENV_ID NAME PREFIX AUDIENCE PERMISSIONS}"

IFS=',' read -ra perms <<< "$permissions"
perms_json=$(printf '%s\n' "${perms[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

e=$(env_path "$env_id")
id=$(api_post "${e}/resources" "$(jq -nc \
  --arg n "$name" --arg p "$prefix" --arg a "$audience" --argjson perms "$perms_json" \
  '{name:$n,prefix:$p,audience:$a,permissions:$perms}')" | extract_id)
info "Created resource: ${id}"
printf '%s\n' "$id"
