#!/usr/bin/env bash
# Sync one resource's permission catalog and roles from a manifest.
# Idempotent; see docs/guides/applications/permissions-as-code.md.
#
#   IAMKIT_URL=… MGMT=ik_mgmt_… ENVIRONMENT=<environment id> \
#   AUDIENCE=https://api.example.com bash sync.sh [--dry-run] [--prune]
#
# Variables: MANIFEST [permissions.json next to this script]; AUDIENCE is used
# only when the resource (found by prefix) does not exist yet — prefix and
# audience never change afterwards.
#
# Without --prune, permissions that left the manifest stay in the catalog and in
# the roles holding them: removing a permission from the catalog strips it from
# every role, grant and service account at once. Prune only once no deployed
# code checks it. Roles not in the manifest are left alone.
# Never enable shell tracing: the management key is in play.
set -euo pipefail
: "${IAMKIT_URL:?Set IAMKIT_URL}"
: "${MGMT:?Set MGMT to a private management key}"
: "${ENVIRONMENT:?Set ENVIRONMENT to the environment id}"
MANIFEST=${MANIFEST:-$(dirname "$0")/permissions.json}
dry_run=0 prune=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --prune) prune=1 ;;
    *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

# Refuse an incoherent manifest before sending anything.
problems=$(jq -r '
  .resource.prefix as $p | [.permissions[].name] as $c
  | [$c[] | select(startswith($p + ":") | not) | "\(.) does not start with \($p):"]
  + [$c | group_by(.)[] | select(length > 1) | "\(.[0]) is listed twice"]
  + [.roles[]? as $r | $r.permissions[] | select(IN($c[]) | not) | "role \($r.name): \(.) is not in the catalog"]
  | .[]' "$MANIFEST")
[[ -z "$problems" ]] || { printf 'invalid manifest:\n%s\n' "$problems" >&2; exit 1; }

e="${IAMKIT_URL%/}/management/v1/environments/$ENVIRONMENT"
api() {
  curl --fail-with-body --silent --show-error --request "$1" "$e$2" \
    -H "X-API-Key: $MGMT" -H 'Content-Type: application/json' --data-binary @-
}
# write: changes only; a dry run sends nothing and returns a placeholder id.
write() {
  if (( dry_run )); then cat >/dev/null; echo '{"id":"dry-run"}'
  else api "$@"; fi
}
# say: report one change ("[dry-run] " prefix when nothing is sent).
say() { if (( dry_run )); then printf '[dry-run] '; fi; printf '%s\n' "$*"; }
# changes OLD NEW -> "+a -b" (empty when equal).
changes() { jq -rn --argjson o "$1" --argjson n "$2" '[($n - $o | map("+" + .)), ($o - $n | map("-" + .))] | add | join(" ")'; }

name=$(jq -r .resource.name "$MANIFEST"); prefix=$(jq -r .resource.prefix "$MANIFEST")
wanted=$(jq -c '[.permissions[].name]' "$MANIFEST")
resources=$(api GET "/resources?limit=100" </dev/null)
current=$(jq -c --arg p "$prefix" '[.items[] | select(.prefix == $p)][0] // empty' <<<"$resources")
stale='[]'
if [[ -z "$current" ]]; then
  : "${AUDIENCE:?Set AUDIENCE: the resource does not exist yet}"
  resource=$(jq -n --arg n "$name" --arg p "$prefix" --arg a "$AUDIENCE" --argjson perms "$wanted" \
    '{name:$n,prefix:$p,audience:$a,permissions:$perms}' | write POST /resources | jq -er .id)
  say "created resource $name ($resource)"
else
  resource=$(jq -r .id <<<"$current")
  have=$(jq -c '.permissions' <<<"$current")
  stale=$(jq -cn --argjson h "$have" --argjson w "$wanted" '$h - $w')
  catalog=$(if (( prune )); then echo "$wanted"; else jq -cn --argjson w "$wanted" --argjson s "$stale" '$w + $s'; fi)
  diff=$(changes "$have" "$catalog")
  if [[ -n "$diff" ]]; then
    jq -n --arg n "$name" --argjson perms "$catalog" '{name:$n,permissions:$perms}' | write PUT "/resources/$resource" >/dev/null
    say "catalog: $diff"
  else printf 'catalog: unchanged (%s permissions)\n' "$(jq length <<<"$catalog")"; fi
fi

# Roles are per resource; /roles is paged (100 per page is plenty for one app).
roles=$(if [[ "$resource" == dry-run ]]; then echo '[]'; else api GET "/roles?limit=100" </dev/null | jq -c --arg r "$resource" '[.items[] | select(.resource_id == $r)]'; fi)
while IFS= read -r role; do
  role_name=$(jq -r .name <<<"$role"); perms=$(jq -c .permissions <<<"$role")
  existing=$(jq -c --arg n "$role_name" '[.[] | select(.name == $n)][0] // empty' <<<"$roles")
  if [[ -z "$existing" ]]; then
    jq -n --arg n "$role_name" --arg r "$resource" --argjson p "$perms" '{name:$n,resource_id:$r,permissions:$p}' | write POST /roles >/dev/null
    say "created role $role_name"
    continue
  fi
  have=$(jq -c .permissions <<<"$existing")
  # Keep the stale permissions a role already holds until --prune.
  (( prune )) || perms=$(jq -cn --argjson p "$perms" --argjson h "$have" --argjson s "$stale" '$p + ($h - ($h - $s)) | unique')
  diff=$(changes "$have" "$perms")
  if [[ -n "$diff" ]]; then
    jq -n --arg n "$role_name" --arg r "$resource" --argjson p "$perms" '{name:$n,resource_id:$r,permissions:$p}' |
      write PUT "/roles/$(jq -r .id <<<"$existing")" >/dev/null
    say "role $role_name: $diff"
  fi
done < <(jq -c '.roles // [] | .[]' "$MANIFEST")

if [[ "$stale" != '[]' ]]; then
  if (( prune )); then say "pruned: $(jq -r 'join(", ")' <<<"$stale")"
  else printf 'kept (not in the manifest; --prune once no deployed code checks them): %s\n' "$(jq -r 'join(", ")' <<<"$stale")"; fi
fi
(( dry_run )) && printf 'dry run: nothing was changed\n'
exit 0
