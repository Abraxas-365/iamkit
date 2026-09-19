<div align="center">

<img src="docs/assets/iamkit-banner.svg" alt="IAMKit — identity and access management with explicit boundaries" width="1200" />

# IAMKit

**Self-hosted identity and resource-scoped access control for your application's backend.**

Run IAMKit alongside your app. Your backend manages users and business access;
your users sign in through the identity API. You own the product experience.

**[Run with Docker](#get-started)** · **[Integrate your app](#integrate-your-application)** ·
**[IAMKit vs Ory and Keycloak](#iamkit-vs-ory-and-keycloak)** · **[Documentation](docs/index.md)**

</div>

> [!NOTE]
> **Integration responsibilities:** your application provides signup/invitation
> workflows and end-user login/consent pages. Deployment supplies TLS, shared abuse
> controls and signing-key lifecycle management. Passkeys/MFA are not implemented.
> See [security requirements](SECURITY.md) and
> [publication requirements](#provenance--license).

## How it fits into your application

<img src="docs/assets/application-integration.svg" alt="The browser sends signup requests to your backend, which uses a private management key to provision users, memberships and grants in IAMKit. The browser can also call IAMKit's identity API to sign in. Your API validates access tokens and permissions." width="1200" />

IAMKit separates **administration** from **authentication**:

- **Your app backend** owns signup eligibility, invitations, tenant selection and
  default access. It calls `/management/v1` using a private `ik_mgmt_…` key to
  create users, add memberships and assign permissions.
- **Your frontend** supplies the login UI. Password, email OTP and external OIDC
  federation are available through `/identity/v1`. These requests do not need a
  management key. They can also go through your backend/BFF.
- **Your protected API** validates the access token's signature, issuer, audience
  and environment/application/resource boundaries, then checks permissions and
  matches the token's organization to the requested tenant. A successful login
  is not permission to call every API or access another tenant's data.
- **IAMKit** stores identities, memberships, grants and sessions in PostgreSQL.
  The Docker image includes a built-in **operator management console** (React SPA)
  served at the root URL — no separate frontend deployment needed. The console
  source lives in [`frontend/`](frontend/README.md).

**A service account is not a workspace operator credential.** It exchanges its
secret for a machine JWT. With explicit built-in IAM resource permissions, that
JWT can administer selected entities through the [scoped IAM API](docs/reference/api/scoped-iam.md).
That API currently has [environment and permission-routing blockers](docs/reference/api/scoped-iam.md#deployment-blockers):
keep it restricted until fixed and tested; do not rely on it for environment isolation.
It cannot replace workspace/federation/OAuth administration through `/management/v1`.
Management keys belong to workspace operators and carry workspace-wide authority.
Never expose either secret in browser code or build an unrestricted public proxy.

For browser calls, use a same-origin reverse proxy or configure the trusted
`CORS_ALLOWED_ORIGINS` allowlist. Keep management routes out of public signup
proxies. Use HTTPS for non-local deployments.

## IAMKit vs Ory and Keycloak

A comparison of approach, not a performance benchmark or feature-parity claim.

| | **IAMKit** | **Ory** | **Keycloak** |
| :--- | :--- | :--- | :--- |
| **What is it?** | Single Go binary with built-in operator console. Users, orgs, permissions, OIDC federation, OAuth 2.0 and SCIM — all included. | Toolkit — pick Kratos (users), Hydra (OAuth), Keto (permissions) and wire them together. | Full platform — SSO server with built-in admin console, login pages, and account management. |
| **SSO and federation** | OIDC federation (Google, Microsoft, any OIDC provider). OAuth 2.0/OIDC server with PKCE. No SAML or LDAP. | Hydra provides OAuth/OIDC. Federation and SAML require additional integration. | OIDC, SAML 2.0, LDAP/AD, Kerberos — broadest protocol support out of the box. |
| **Who builds the UI?** | You do. Your app handles signup forms, login pages and onboarding. IAMKit provides the APIs and an operator management console. | You do, but each component has its own integration surface. | Keycloak provides hosted login/registration pages you configure and theme. |
| **How does access control work?** | Resources have permission catalogs. You assign permissions to users via roles or direct grants, scoped to an organization. | Add Keto for relationship-based authorization, or roll your own. | Roles and policy-based authorization built into the platform. |
| **Best for** | A shared identity layer for B2B apps and multi-service systems, with tenant-aware access and your own login UI. | Teams that want to pick and compose identity building blocks for a custom architecture. | Teams that want a battle-tested platform with broad enterprise protocol support (SAML, LDAP/AD) and minimal custom UI work. |
| **Main trade-off** | You own the signup flow and login UI. No SAML/LDAP or built-in MFA yet. | You pick the pieces and own the glue — more architectural decisions upfront. | You work within Keycloak's realm/client/flow model — flexibility comes through configuration, not code. |

All three support SSO via OIDC. Choose based on your requirements: if you need
SAML, LDAP/AD or built-in MFA today, evaluate Keycloak. If you want fully
modular, independent components, evaluate Ory. If you want one binary that
covers identity, access control and multi-tenant boundaries — whether for a
single product or as a shared identity layer across services — IAMKit is built
for that.

Official references: [Ory](https://www.ory.com/docs/oss/getting-started),
[Keycloak](https://www.keycloak.org/).

## Get started

### 1. Build and configure the Docker stack

Requirements: Docker with Compose, OpenSSL and a checkout of this repository.
**No host Go installation is needed.** Use the source-build Compose file until
you have a verified published image.

Create a private `.env.docker` file with the following values, replacing every
placeholder (do not commit it):

```dotenv
POSTGRES_PASSWORD=REPLACE_WITH_RANDOM_HEX
OIDC_HMAC_SECRET=REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
JWT_ISSUER=http://localhost:8080
IAMKIT_PORT=8080
IAMKIT_BOOTSTRAP_EMAIL=owner@example.com
IAMKIT_BOOTSTRAP_WORKSPACE=Demo
IAMKIT_BOOTSTRAP_PASSWORD=REPLACE_WITH_UNIQUE_12_TO_72_BYTE_PASSWORD
```

Generate secrets with `openssl rand -hex 32`. A hex database password avoids
special-character escaping in the connection URL. The Compose template requires
`OIDC_HMAC_SECRET` even if you only intend to try password login.

```sh
chmod 600 .env.docker
mkdir -p secrets
chmod 700 secrets
openssl genrsa -out secrets/jwt.pem 4096
chmod 600 secrets/jwt.pem

docker compose --env-file .env.docker -f docker-compose.production.yml build
```

The image runs as a non-root `iamkit` user. On Linux bind mounts, ensure that user
can read the key; do **not** make the private key world-readable. For a local
Docker host with ordinary UID mapping, obtain the image's IDs and set ownership:

```sh
CONTAINER_OWNER=$(docker compose --env-file .env.docker -f docker-compose.production.yml \
  run --rm --no-deps --entrypoint sh iamkit \
  -c 'printf "%s:%s" "$(id -u)" "$(id -g)"')
sudo chown "$CONTAINER_OWNER" secrets/jwt.pem
```

Rootless Docker, user-namespace remapping and managed container platforms may
require different ownership/secret-mount configuration. Keep the mount read-only
and grant access only to the runtime identity.

### 2. Start IAMKit

```sh
docker compose --env-file .env.docker -f docker-compose.production.yml up -d --wait
curl --fail http://localhost:8080/health
```

The expected health response is `{"status":"healthy","service":"iamkit"}`.
PostgreSQL data persists in a named volume. Do not remove that volume to upgrade.

On startup IAMKit runs embedded migrations. With bootstrap variables set and no
workspace yet, it creates the owner/workspace and sets the operator password.
Existing workspaces skip bootstrap; changing bootstrap variables is **not** a
password-reset mechanism. Start with an empty database: unmanaged non-empty
schemas and modified migration checksums are rejected.

> [!WARNING]
> **Automatic bootstrap currently prints the initial management key to logs.**
> View it only in a trusted terminal, move it into secret storage, and rotate/revoke
> it after setup. Restrict container log access and retention. The initial key
> expires after 24 hours. Remove bootstrap values after initialization.
> For deployments that must not log credentials, omit bootstrap variables and use
> the explicit `iamkit bootstrap … --output /secure/path/owner.json` CLI flow with
> a writable, restricted output mount. Follow the [explicit-bootstrap quickstart](docs/start/docker-quickstart.md)
> and [deployment runbook](docs/operations/deployment.md).

```sh
docker compose --env-file .env.docker -f docker-compose.production.yml logs iamkit
```

The sample publishes port 8080 on the host. Restrict it to loopback or a private
network as appropriate, and put TLS in front before exposing it. HTTP localhost
is for testing password/machine login and health checks; OAuth, federation and
operator-console cookies require HTTPS. The Compose filename does not imply
production hardening.

### 3. Configure optional login services

Configuration is read from **process environment**. Compose's `--env-file` supplies
interpolation values; it does not automatically inject every variable into the
container. Add optional settings to the `iamkit.environment` map (or a Compose
override) as well as your private environment file.

| Container variable | Purpose |
| :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string; supplied by the example Compose stack |
| `JWT_PRIVATE_KEY_PATH` | Mounted RSA private key; `/secrets/jwt.pem` in the example |
| `JWT_ISSUER` | Stable public issuer URL; HTTPS outside loopback development |
| `SERVER_PORT` | API port inside the container; keep 8080 to match the example healthcheck |
| `OIDC_HMAC_SECRET` | Stable OAuth secret, at least 32 random bytes |
| `EMAIL_WEBHOOK_URL`, `EMAIL_WEBHOOK_TOKEN` | Default HTTPS mail-delivery webhook and its bearer token (can be overridden per environment from the console) |
| `FEDERATION_CREDENTIAL_BINDINGS` | Approved environment/issuer/client/secret-reference combinations |
| `IAMKIT_PROVIDER_*` | Provider client secrets referenced by federation bindings |

Email OTP, email verification and password reset use the webhook. IAMKit sends
`{email, purpose, code}`; **your service sends the email**. The global
`EMAIL_WEBHOOK_URL` applies to all environments by default; you can override it
per environment from the operator console (**Notifications** tab) or the
management API (`PUT /environments/:id/delivery`). Per-environment config takes
priority; if not set, the global env var is used. Do not log codes or webhook
payloads.

Federation supports OIDC providers, not every OAuth-only provider. Create an
approved connection and explicitly link its provider subject to a local user;
there is no first-login signup or automatic linking by matching email.
See [`.env.example`](.env.example) for the deployment binding format.

## Integrate your application

### Example: InvoiceCloud signup and password login

**One-time setup:** create a project/environment, an organization (`Acme`), an
application (`Web App`) and a resource (`Invoices API`). Define the resource's
permission catalog and bind the application to it. Use the management console or
management API as illustrated below.

For example, under `/management/v1/environments/ENV_UUID`, authenticated with your
backend's management key:

```http
POST /applications
{"name":"Web App","redirect_uris":["https://app.example.com/callback"]}

POST /resources
{"name":"Invoices API","prefix":"invoices","audience":"https://api.example.com","permissions":["invoices:read"]}

POST /application-resources
{"application_id":"APP_UUID","resource_id":"RESOURCE_UUID"}
```

These are relative routes and illustrative JSON bodies; replace UUID placeholders
with IDs returned by creation calls. All JSON requests need `Content-Type:
application/json`.

**Signup:** Alice submits your signup form to **your backend**, not to an IAMKit
`/signup` endpoint (there isn't one). Your backend checks eligibility and selects
the organization/default permissions server-side, then makes these management
calls under the same environment prefix:

```http
POST /users
{"name":"Alice","email":"alice@example.com","password":"example-password-replace-me"}

POST /memberships
{"organization_id":"ORG_UUID","user_id":"USER_UUID"}

PUT /grants
{"organization_id":"ORG_UUID","user_id":"USER_UUID","resource_id":"RESOURCE_UUID","permissions":["invoices:read"]}
```

Each request carries `X-API-Key: ik_mgmt_…` **from your backend only**.
Membership and an appropriate resource grant are prerequisites for this login,
not optional onboarding decorations. These are separate requests, not one atomic
signup transaction: handle partial failures/retries in your onboarding workflow.
Do not trust a public form to select privileged roles, arbitrary orgs or grants.
Add abuse prevention and email-ownership verification appropriate to your product.

**Sign in:** your frontend (or BFF) sends Alice's credentials and the intended
boundary to IAMKit. No management key is needed:

```js
const response = await fetch('/identity/v1/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    environment_id: 'ENV_UUID',
    organization_id: 'ORG_UUID',
    application_id: 'APP_UUID',
    resource_id: 'RESOURCE_UUID',
    email: 'alice@example.com',
    password: passwordFromForm,
  }),
})
if (!response.ok) throw new Error('Sign-in failed')
const { access_token, refresh_token } = await response.json()
```

This relative URL assumes your app's reverse proxy forwards `/identity/` to
IAMKit. IDs are identifiers, not secrets; IAMKit checks the requested boundary
against actual memberships, bindings and grants. Select tenant context through a
trusted onboarding/invitation flow, not by granting whatever the browser requests.

**Call your API:** send `Authorization: Bearer <access_token>` to the Invoices API.
The API must validate the token, require `invoices:read`, and match its
`organization_id` to the requested tenant before returning data. Scope database
queries to that organization; a permission check alone is not tenant isolation.
Use the SDK's `RequireOrganization` middleware or an equivalent application check.
Keep browser tokens in memory or use a BFF with appropriately protected cookies;
do not log tokens. Treat refresh tokens as secrets and handle rotation.

Use `/.well-known/jwks.json` / the [Go SDK](sdk/README.md) for signature and boundary
validation. Offline validation cannot see revocation before token expiry; use
online introspection when you need current session/access status.

### Other ways to sign in

| Method | App flow | Prerequisites |
| :--- | :--- | :--- |
| Password | `POST /identity/v1/login` with the full boundary | Active user with a password, membership, app/resource binding and grant |
| Email OTP | `POST /identity/v1/challenges` with environment, email and `purpose: "login"`; then `/challenges/verify` with challenge ID, 8-character code, purpose and full boundary | User has OTP enabled; email webhook configured; same access prerequisites |
| Google/Microsoft or another OIDC provider | `POST /identity/v1/federation/start` with connection ID and full boundary; follow provider redirect/callback | Approved connection, explicit external-identity link and appropriate local access |
| OAuth/OIDC client flow | Register an OAuth client bound to an app/resource, then use authorization code + S256 PKCE | Your login/consent UI and HTTPS; see the [OAuth guide](docs/guides/oauth-oidc.md) |

OAuth clients represent **apps obtaining tokens from IAMKit**; federation
connections represent **external providers authenticating users to IAMKit**.
The fixed app/resource mapping is an IAMKit design choice, not a universal OAuth
requirement. Password/federation specify that boundary at login time; OTP currently
specifies it at verification time.

One user can have a password, OTP enabled and multiple linked providers. These
resolve to the same local user, but each successful login creates its own session.
Email OTP is a login method, **not** a second-factor MFA feature.

Forgot password uses `/challenges` with `purpose: "password_reset"`, followed by
`/challenges/verify` with environment, challenge ID, code, purpose and the new
12–72 byte password. Success returns 204, not a login session. It requires an
existing password and configured email delivery. Your app supplies the UI.

## Model and capabilities

```text
Workspace — operators and management credentials
└── Project
    └── Environment — isolated development / staging / production
        ├── Users and organization memberships
        ├── Organizations — units, reporting managers, positions
        ├── Applications — resource bindings and OAuth clients
        ├── Resources — audiences, permission catalogs, roles and grants
        ├── Service accounts — resource-bound machine credentials
        └── Federation and SCIM provisioning connections
```

There is no special `iam` application or wildcard administrative permission.
Each environment has a built-in IAM resource with explicit permissions for the
scoped management API. Organization membership and job titles never imply
workspace operator authority.

Also included: refresh-token rotation/replay revocation, online introspection,
SCIM provisioning, owner-only audited impersonation, a Go SDK with Fiber middleware,
and embedded checksummed migrations. See [security boundaries](SECURITY.md).
Read the [concept guides](docs/concepts/identity-model.md) and
[API reference](docs/reference/api/index.md).

## Container registry and publishing

The registry-oriented example [`docker-compose.iamkit.yml`](docker-compose.iamkit.yml)
references `ghcr.io/abraxas-365/iamkit:latest`. **That reference is a publishing
target, not confirmation that a public image is available.** Use the source-build
quickstart above until a release has been published and verified.

Once published, use that Compose file with the same signing-key setup. It uses
`IAMKIT_DB_PASSWORD` instead of the source-build file's `POSTGRES_PASSWORD`.
Replace `latest` with a verified version tag or immutable digest for deployments.

For maintainers, [the existing publishing workflow](.github/workflows/publish.yml):

- Publishes to GHCR under the GitHub repository's image name.
- Runs on pushes to `main`, `v*` tags and manual dispatch.
- Requests Linux amd64/arm64 builds and authenticates with `GITHUB_TOKEN`.
- Produces branch, SHA and semantic-version tags. `main` is not itself a release;
  verify the resulting tags rather than assuming `latest` exists.

Before triggering publication:

1. Resolve [ownership/license permission](#provenance--license), audit source and
   image contents for secrets, and review dependency licenses/vulnerabilities.
2. Verify the workflow builds both requested architectures and that the image
   boots against a fresh PostgreSQL database.
3. Publish an approved release, then set/check the GHCR package's public visibility.
4. Test an anonymous pull of the release tag on a clean machine and record its
   digest before recommending it to users.

No registry push is required to use a locally built image.

## Development and documentation

Start at the [documentation hub](docs/index.md):
[Docker quickstart](docs/start/docker-quickstart.md),
[first application](docs/start/first-application.md),
[application integration](docs/guides/application-integration.md),
[API reference](docs/reference/api/index.md) and
[operations checklist](docs/operations/launch-checklist.md).
See the [validation record](docs/maintainers/validation.md) for tested examples
and remaining deployment acceptance work.
The default `docker-compose.yml` is for local infrastructure; the Docker
quickstart above explicitly selects the full-stack file.

```sh
make build
make test              # root and nested SDK
make vet               # root and nested SDK
make test-e2e          # disposable PostgreSQL; Docker required
```

Plain `go test ./...` skips database tests unless `IAMKIT_TEST_E2E=1`. Tests must
not use development data. Current references: [Go SDK](sdk/README.md),
[management console](frontend/README.md), [configuration example](.env.example)
and [security requirements](SECURITY.md).

## Provenance / license

This project adapts local `paframework`, which identified
`github.com/Practical-Action-Global/iam`. No upstream root license was found.
No distribution license is asserted: confirm ownership/permission and dependency
licensing before publishing. Source secrets, deployment infrastructure and Git
history were not copied.
