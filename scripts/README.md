# IAMKit Management Scripts

Standalone bash scripts for automating IAMKit management operations.
Designed for deployment pipelines, init containers, CI/CD, and infrastructure
automation — not tutorials.

## Requirements

- **bash** ≥ 4.0
- **curl**
- **jq**

## Configuration

All scripts read two environment variables:

```sh
export IAMKIT_URL=http://localhost:8080   # Base URL of IAMKit
export IAMKIT_KEY=ik_mgmt_...            # Management API key
```

Set `IAMKIT_QUIET=1` to suppress informational stderr messages (IDs still go to
stdout).

## Scripts

### Seed — full bootstrap in one command

```sh
# Create project + environment + org + app + resource + user + membership + grant
bash scripts/seed.sh

# With custom values
PROJECT_NAME="MyApp" \
ENVIRONMENT_NAME="Production" \
ORG_NAME="Acme" \
APP_NAME="Dashboard" \
APP_REDIRECT_URIS="https://app.acme.com/callback" \
RESOURCE_NAME="Billing API" \
RESOURCE_PREFIX="billing" \
RESOURCE_AUDIENCE="https://api.acme.com" \
RESOURCE_PERMS="billing:read,billing:write,billing:admin" \
USER_NAME="Alice" \
USER_EMAIL="alice@acme.com" \
USER_PASSWORD="secure-password-here" \
bash scripts/seed.sh
```

Outputs a JSON object with all created IDs:

```json
{"project_id":"...","environment_id":"...","organization_id":"...","application_id":"...","resource_id":"...","user_id":"...","grant_id":"..."}
```

Pipe to a file or use with `jq`:

```sh
bash scripts/seed.sh > .seed-ids.json
ENV=$(jq -r .environment_id .seed-ids.json)
```

### Workspace operations

```sh
# List projects
bash scripts/list-projects.sh

# Create a project
PROJECT_ID=$(bash scripts/create-project.sh "My Project")

# List environments in a project
bash scripts/list-environments.sh "$PROJECT_ID"

# Create an environment
ENV_ID=$(bash scripts/create-environment.sh "$PROJECT_ID" "Production")
```

### Entity CRUD

All entity scripts take the environment ID as the first argument and output
IDs (or JSON) to stdout for piping.

```sh
# Users
USER_ID=$(bash scripts/create-user.sh "$ENV" "Alice" "alice@acme.com" "password123!")
bash scripts/list-entities.sh "$ENV" users
bash scripts/list-entities.sh "$ENV" users --search "alice" --limit 10
bash scripts/get-entity.sh "$ENV" users "$USER_ID"
bash scripts/delete-entity.sh "$ENV" users "$USER_ID"  # suspends

# Organizations
ORG_ID=$(bash scripts/create-organization.sh "$ENV" "Acme Corp")

# Applications
APP_ID=$(bash scripts/create-application.sh "$ENV" "Dashboard" "https://app.acme.com/callback")

# Resources
RES_ID=$(bash scripts/create-resource.sh "$ENV" "Billing API" billing https://api.acme.com "billing:read,billing:write")

# Link app to resource
bash scripts/link-app-resource.sh "$ENV" "$APP_ID" "$RES_ID"

# Memberships
bash scripts/add-membership.sh "$ENV" "$ORG_ID" "$USER_ID"

# Roles
ROLE_ID=$(bash scripts/create-role.sh "$ENV" "Editor" "$RES_ID" "billing:read,billing:write")
bash scripts/update-role.sh "$ENV" "$ROLE_ID" "Editor v2" "$RES_ID" "billing:read,billing:write,billing:admin"
bash scripts/assign-role.sh "$ENV" "$ORG_ID" "$USER_ID" "$ROLE_ID"
bash scripts/delete-entity.sh "$ENV" roles "$ROLE_ID"

# Grants (direct permissions)
GRANT_ID=$(bash scripts/set-grant.sh "$ENV" "$ORG_ID" "$USER_ID" "$RES_ID" "billing:read")
bash scripts/delete-entity.sh "$ENV" grants "$GRANT_ID"

# Service accounts
bash scripts/create-service-account.sh "$ENV" "CI Bot" "$APP_ID" "$RES_ID" "billing:read" "720h"

# Update resource permissions (deploy new API version)
bash scripts/update-permissions.sh "$ENV" "$RES_ID" "Billing API" "billing:read,billing:write,billing:admin,billing:export"
```

### Listing and querying

```sh
# All entity types support list with pagination and search
bash scripts/list-entities.sh "$ENV" users --limit 50 --offset 100 --search "john"
bash scripts/list-entities.sh "$ENV" organizations
bash scripts/list-entities.sh "$ENV" applications
bash scripts/list-entities.sh "$ENV" resources
bash scripts/list-entities.sh "$ENV" roles
bash scripts/list-entities.sh "$ENV" grants
bash scripts/list-entities.sh "$ENV" service-accounts
bash scripts/list-entities.sh "$ENV" sessions
bash scripts/list-entities.sh "$ENV" audit-events
bash scripts/list-entities.sh "$ENV" role-assignments
```

## Deployment example

Use in a Docker entrypoint or init container:

```sh
#!/usr/bin/env bash
set -euo pipefail

export IAMKIT_URL="${IAMKIT_URL:?}"
export IAMKIT_KEY="${IAMKIT_KEY:?}"

# Wait for IAMKit to be ready
until curl -sf "${IAMKIT_URL}/management/v1/me" -H "X-API-Key: ${IAMKIT_KEY}" >/dev/null 2>&1; do
  echo "Waiting for IAMKit..." >&2
  sleep 2
done

# Bootstrap the environment
ids=$(bash scripts/seed.sh)
echo "$ids" > /run/secrets/iamkit-ids.json

# Or compose individual scripts
PROJECT=$(bash scripts/create-project.sh "MyApp")
ENV=$(bash scripts/create-environment.sh "$PROJECT" "Production")
RES=$(bash scripts/create-resource.sh "$ENV" "API" myapp https://api.myapp.com "myapp:read,myapp:write")
```

## CI pipeline example

```yaml
# GitHub Actions
- name: Sync IAMKit permissions
  env:
    IAMKIT_URL: ${{ secrets.IAMKIT_URL }}
    IAMKIT_KEY: ${{ secrets.IAMKIT_KEY }}
  run: |
    bash scripts/update-permissions.sh \
      "$ENV_ID" "$RESOURCE_ID" "My API" \
      "api:read,api:write,api:admin,api:export"
```

## Design principles

- **Stdout = data** — IDs and JSON go to stdout; messages go to stderr.
- **Composable** — pipe output between scripts: `ENV=$(bash scripts/create-environment.sh ...)`
- **Idempotent where possible** — `set-grant.sh` uses PUT (upsert). Create scripts
  will error on duplicates (by design — catch and handle in your pipeline).
- **No state files** — scripts don't write temp files or caches.
- **No dependencies** — just bash, curl, and jq. No npm, no Go, no Python.
