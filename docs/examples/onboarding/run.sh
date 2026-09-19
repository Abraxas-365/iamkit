#!/usr/bin/env bash
# Run against a disposable installation. Never enable shell tracing.
set -euo pipefail
: "${IAMKIT_URL:?Set IAMKIT_URL}"
: "${MGMT:?Set MGMT to a private management key}"
: "${DEMO_PASSWORD:?Set DEMO_PASSWORD (12-72 bytes)}"
: "${OUTPUT:?Set OUTPUT to a new private JSON file path}"
[[ ! -e "$OUTPUT" ]] || { printf 'OUTPUT already exists\n' >&2; exit 1; }
umask 077
base=${IAMKIT_URL%/}
management() {
  curl --fail --silent --show-error --request "$1" "$base/management/v1$2" \
    -H "X-API-Key: $MGMT" -H 'Content-Type: application/json' --data-binary @-
}
project=$(printf '%s' '{"name":"InvoiceCloud docs"}' | management POST /projects | jq -er .id)
environment=$(printf '%s' '{"name":"Tutorial"}' | management POST "/projects/$project/environments" | jq -er .id)
prefix="/environments/$environment"
organization=$(printf '%s' '{"name":"Acme"}' | management POST "$prefix/organizations" | jq -er .id)
other=$(printf '%s' '{"name":"Other tenant"}' | management POST "$prefix/organizations" | jq -er .id)
application=$(printf '%s' '{"name":"Web App","redirect_uris":["https://app.example.com/callback"]}' | management POST "$prefix/applications" | jq -er .id)
resource=$(printf '%s' '{"name":"Invoices API","prefix":"invoices","audience":"https://api.example.com","permissions":["invoices:read","invoices:write"]}' | management POST "$prefix/resources" | jq -er .id)
jq -n --arg a "$application" --arg r "$resource" '{application_id:$a,resource_id:$r}' | management POST "$prefix/application-resources" >/dev/null
user=$(jq -n --arg p "$DEMO_PASSWORD" '{name:"Alice",email:"alice@example.com",password:$p}' | management POST "$prefix/users" | jq -er .id)
jq -n --arg o "$organization" --arg u "$user" '{organization_id:$o,user_id:$u}' | management POST "$prefix/memberships" >/dev/null
jq -n --arg o "$organization" --arg u "$user" --arg r "$resource" '{organization_id:$o,user_id:$u,resource_id:$r,permissions:["invoices:read"]}' | management PUT "$prefix/grants" >/dev/null
boundary=$(jq -n --arg e "$environment" --arg o "$organization" --arg a "$application" --arg r "$resource" '{environment_id:$e,organization_id:$o,application_id:$a,resource_id:$r}')
tokens=$(jq --arg p "$DEMO_PASSWORD" '. + {email:"alice@example.com",password:$p}' <<<"$boundary" | curl --fail --silent --show-error "$base/identity/v1/login" -H 'Content-Type: application/json' --data-binary @-)
access=$(jq -er .access_token <<<"$tokens")
# Online validation must confirm current access without printing the token.
result=$(jq -n --arg e "$environment" '{environment_id:$e,audience:"https://api.example.com"}' | curl --fail --silent --show-error "$base/identity/v1/introspect" -H "Authorization: Bearer $access" -H 'Content-Type: application/json' --data-binary @-)
jq -e '.active == true and (.claims.permissions | index("invoices:read") != null)' <<<"$result" >/dev/null
status=$(jq --arg p "$DEMO_PASSWORD" --arg o "$other" '. + {organization_id:$o,email:"alice@example.com",password:$p}' <<<"$boundary" | curl --silent --show-error -o /dev/null -w '%{http_code}' "$base/identity/v1/login" -H 'Content-Type: application/json' --data-binary @-)
[[ "$status" == 401 || "$status" == 403 ]] || { printf 'Expected cross-tenant denial, got %s\n' "$status" >&2; exit 1; }
# noclobber prevents overwriting a file created since the initial check.
(set -o noclobber; jq -n --argjson b "$boundary" --argjson t "$tokens" --arg u "$user" --arg p "$project" --arg other "$other" '$b + $t + {user_id:$u,project_id:$p,other_organization_id:$other,audience:"https://api.example.com"}' >"$OUTPUT")
printf 'Provisioning, login, introspection and cross-tenant login denial passed. Private result: %s\n' "$OUTPUT"
