# Getting started

A hands-on walkthrough from an empty checkout to a successfully validated permission check.
Every command is copy-pasteable against a local instance. For the conceptual "why," see
[Concepts](concepts.md); for the full endpoint reference, see [API guide](api.md).

## 1. Requirements

- Go 1.26.6+
- Docker Compose
- OpenSSL
- `curl` and `jq` (used below to read responses; optional but convenient)

## 2. Start a local instance

```sh
git clone <this repo> iamkit && cd iamkit
cp .env.example .env
mkdir -p .dev-secrets
openssl genrsa -out .dev-secrets/jwt.pem 2048
chmod 600 .dev-secrets/jwt.pem
docker compose up -d --wait
set -a; . ./.env; set +a
go run ./cmd/iamkit migrate
go run ./cmd/iamkit bootstrap --email owner@example.com --workspace Demo --output .dev-secrets/owner.json
go run ./cmd/iamkit
```

Leave the server running in this terminal; run the rest of this guide from another terminal in
the same directory (re-run `set -a; . ./.env; set +a` there too, or just hardcode
`http://localhost:8080` below).

> [!NOTE]
> Compose's `identity_data` volume is **not** wiped or upgraded automatically — always point
> `migrate` at a genuinely empty database. See [Configuration](configuration.md) for what every
> variable in `.env` means, and the full list of what's optional (email delivery, federation,
> OAuth) versus required.

The `bootstrap` command wrote your one-time management credential to
`.dev-secrets/owner.json`. This is the **only** time it's shown; it expires in 24 hours (rotate
before then — see `api.md#operator-administration`).

```sh
export MGMT=$(jq -r .management_key .dev-secrets/owner.json)
export API=http://localhost:8080
```

## 3. Confirm the server is up

```sh
curl -s $API/health | jq
# {"status":"healthy","service":"iamkit"}
```

## 4. Create a project and environment

Every product lives under a project; every project has one or more isolated environments (see
[Concepts → the hierarchy](concepts.md#the-hierarchy)).

```sh
PROJECT=$(curl -s -X POST $API/management/v1/projects \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Demo Product"}' | jq -r .id)

ENV=$(curl -s -X POST $API/management/v1/projects/$PROJECT/environments \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"production"}' | jq -r .id)

BASE=$API/management/v1/environments/$ENV
```

## 5. Register an application and a resource

An **application** is what logs users in; a **resource** is an API it's allowed to call, with
its own permission catalog (see [Concepts → the hierarchy](concepts.md#the-hierarchy)).

```sh
APP=$(curl -s -X POST $BASE/applications \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Demo Web","redirect_uris":["https://demo.example/callback"]}' | jq -r .id)

RESOURCE=$(curl -s -X POST $BASE/resources \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Demo API","audience":"https://api.demo.example","permissions":["invoices:read"]}' | jq -r .id)

curl -s -X POST $BASE/application-resources \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d "{\"application_id\":\"$APP\",\"resource_id\":\"$RESOURCE\"}"
```

## 6. Create an organization, a user, and a grant

```sh
ORG=$(curl -s -X POST $BASE/organizations \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Acme Inc"}' | jq -r .id)

USER=$(curl -s -X POST $BASE/users \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","name":"Alice","password":"a-long-initial-password"}' | jq -r .id)

curl -s -X POST $BASE/memberships \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG\",\"user_id\":\"$USER\",\"role\":\"owner\"}"
```

Membership alone grants no API access — you must issue a direct grant or role assignment (see
[Concepts → permissions, roles and grants](concepts.md#permissions-roles-and-grants)):

```sh
curl -s -X PUT $BASE/grants \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG\",\"user_id\":\"$USER\",\"resource_id\":\"$RESOURCE\",\"permissions\":[\"invoices:read\"]}"
```

## 7. Log in as that user

```sh
TOKENS=$(curl -s -X POST $API/identity/v1/login -H 'Content-Type: application/json' -d "{
  \"environment_id\":\"$ENV\",
  \"organization_id\":\"$ORG\",
  \"application_id\":\"$APP\",
  \"resource_id\":\"$RESOURCE\",
  \"email\":\"alice@example.com\",
  \"password\":\"a-long-initial-password\"
}")
ACCESS=$(echo $TOKENS | jq -r .access_token)
echo $TOKENS | jq
```

You now have a 15-minute access token bound to exactly this
`(environment, organization, application, resource)` tuple (see
[Concepts → every token is a 4-way boundary](concepts.md#every-token-is-a-4-way-boundary)).

## 8. Validate the token like a resource server would

```sh
curl -s -X POST $API/identity/v1/introspect \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d "{\"environment_id\":\"$ENV\",\"audience\":\"https://api.demo.example\"}" | jq
```

You should see `"active": true` and `"claims"` including `"permissions": ["invoices:read"]`.
This is what `sdk/authclient.Client.Introspect` does for you in Go — see
[Recipes → protect your Fiber API](recipes.md#recipe-protect-your-fiber-api-with-permission-checks).

## 9. See a permission check fail on purpose

Shrink the resource's permission catalog and watch the previously-granted permission disappear
from a fresh token:

```sh
curl -s -X PUT $BASE/resources/$RESOURCE \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Demo API","permissions":[]}'
```

Now `POST /identity/v1/login` again with the same credentials and inspect the new token's
`permissions` claim (via introspect) — it will be empty. Removing a catalog permission strips it
from every grant/role/service-account that used it immediately, not just going forward.

## 10. Clean up / next steps

- Stop the server with Ctrl-C; `docker compose down` to stop Postgres (add `-v` to also delete
  the `identity_data` volume before your next fresh run).
- Read [Concepts](concepts.md) for the reasoning behind boundaries you just exercised.
- Read [Recipes](recipes.md) for end-to-end flows: Google login, service accounts, SCIM,
  impersonation, OAuth clients, wiring the SDK into your own Fiber app.
- Read [Configuration](configuration.md) before any non-local deployment.
- Read [Security status](../SECURITY.md) before any non-local deployment — this project is
  explicitly early development and not independently audited.
