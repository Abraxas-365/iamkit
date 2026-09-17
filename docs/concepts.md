# Concepts

The mental model behind IAMKit's boundaries. Read this before `api.md`/`recipes.md` if you're
new — those assume the vocabulary defined here.

## The hierarchy

```text
Workspace — operators and opaque management credentials
└── Project
    └── Environment — isolated development / staging / production
        ├── Users → organization memberships
        ├── Organizations → org units, reporting managers, positions
        ├── Applications → OAuth clients and client/resource bindings
        ├── Resources → API audiences, permission catalogs, roles and grants
        ├── Service accounts → resource-bound machine credentials
        └── Federation and SCIM provisioning connections
```

- **Workspace** — the whole IAMKit deployment. Owned by **operators** (people who hold
  `ik_mgmt_...` management credentials). One workspace can host many unrelated products.
- **Project** — a grouping of environments for one product, e.g. "Saas Idea 1." Purely
  organizational; carries no permissions of its own.
- **Environment** — the real isolation boundary. `production` and `development` under the same
  project share nothing: no users, no sessions, no tokens, no grants. Composite database keys
  enforce this — a grant can't reference a user or resource from a different environment even
  if application code has a bug.
- **User** — an end user of one environment. Not a workspace operator. Users authenticate with
  `/identity/v1/...` endpoints, never `/management/v1/...`.
- **Organization** — a business tenant inside an environment (a company, a team). Users join
  organizations via **memberships**. Organizations own **org units** (a configurable tree —
  region/department/whatever you define), reporting managers and **positions** (job titles),
  but none of that structure grants API access by itself.
- **Application** — something that logs users in (a web app, mobile app, CLI). Applications have
  OAuth clients and are explicitly bound to the resources they're allowed to call.
- **Resource** — an API. Owns an **audience** (its identifier, e.g.
  `https://billing.example`) and an exact **permission catalog** (the only strings that can ever
  appear in a token issued for that resource). Roles and grants can only use permissions the
  resource has declared — there's no free-text permission escape hatch.
- **Service account** — a machine credential (`ik_svc_...`) bound to one application/resource
  pair, for workers/cron jobs that aren't acting as a user.

## Why no "iam" app or wildcard scope

Many legacy systems have one privileged internal application (often literally named `iam`) or a
wildcard admin scope that, once granted, can do anything. IAMKit deliberately has neither:

- Workspace/operator authority (`ik_mgmt_...`) is a completely separate credential system from
  end-user, OAuth, service-account and SCIM tokens. None of the latter can ever administer
  IAMKit, no matter what permissions they're granted.
- Organization roles, reporting-manager relationships and job titles never imply operator
  authority. A user being their organization's "owner" only affects that organization's
  memberships/grants — it does not touch other organizations or the workspace.
- Every permission a token can carry is scoped to one resource's declared catalog. There is no
  permission string that means "everything."

This is a design constraint, not an oversight: it bounds the blast radius of any single leaked
credential.

## Token purposes

Every access token carries a `purpose` claim (see `sdk/authclient/validator.go`), and consumers
must treat different purposes differently:

| Purpose | Issued to | Has `organization_id`/session? | Notes |
| :--- | :--- | :--- | :--- |
| `application` | A logged-in user | Yes | Normal end-user session token. Carries `permissions` from grants + role assignments for that organization/resource. |
| `machine` | A service account | No | No user, no organization, no refresh token concept the same way — re-minted from the service-account secret. |

OAuth-issued tokens and impersonation tokens are still `purpose: application`, but impersonation
tokens additionally carry `actor_id` (the impersonating operator) and are restricted: no refresh,
can't update the impersonated user's own profile, can't authorize new OAuth grants.

## Permissions, roles and grants

- A **resource's permission catalog** is the source of truth — e.g.
  `["invoices:read","invoices:write"]`. Shrinking the catalog strips those permissions from
  every existing grant, role and service account that referenced them; nothing keeps
  now-invalid permissions around.
- A **role** is a named, reusable bundle of permissions scoped to one resource
  (`{name, resource_id, permissions}`), assignable to (organization, user) pairs.
- A **direct grant** is a permission set assigned straight to a (organization, user, resource)
  triple, without going through a role.
- A user's effective permissions for a resource in a session = the union of their direct grant
  and any role assignments, for that organization only. Membership alone grants nothing — an
  organization owner still needs an explicit grant or role assignment before a token carries any
  permission for a resource.

## Every token is a 4-way boundary

A token isn't just "for this user" — it's scoped to an exact
`(environment, organization, application, resource)` tuple, decided at login time (see
`POST /identity/v1/login` in `api.md`). Switching organizations means authenticating again for
that organization; a single token never spans two organizations or two resources. Consumers are
expected to check environment/application/resource/audience explicitly rather than trust
whatever the token happens to claim — see `sdk/authclient/validator.go`'s required parameters
for a concrete example of this being enforced in code.

## Login methods are independent, not layered

Password login, opt-in email OTP login and OIDC federation login are three **separate** ways to
obtain the same kind of token — not a base factor plus a second factor. In particular:

- Enabling OTP for a user (`otp_enabled: true`) does not require or imply they also have a
  password.
- Email OTP is explicitly **not** MFA — it's a standalone passwordless login path, not a
  second-factor check layered on top of a password.
- A federation-only user (no password set) can exist; password reset cannot retroactively add a
  password to such a user.

## Explicit linking over inference

IAMKit refuses to infer identity or authority from convenient-looking coincidences:

- Federation (Google/Microsoft/etc.) subjects are linked to a user explicitly via
  `POST /external-identities` — never auto-linked because an email happens to match.
- SCIM-provisioned identities are linked the same way, explicitly, never by email collision.
- Reporting-manager relationships, org-unit membership and position/job-title do not confer
  authorization; they're descriptive data an application can read, not an access-control input.

This trades away some signup convenience (see `recipes.md`'s Google-login recipe for the
practical consequence) in exchange for eliminating an entire class of account-takeover-by-email
bugs.

## Errors are classified, not just HTTP codes

Every backend failure carries an `internal/errx.Type` (`VALIDATION`, `NOT_FOUND`, `CONFLICT`,
`AUTHORIZATION`, `BUSINESS`, `EXTERNAL`, `INTERNAL`) and is rendered as
`{"error":{"code":...,"message":...,"type":...,"http_status":...}}`. Clients should branch on
`code`/`type`, not parse `message` text — internal details are deliberately not exposed in
messages.

## Where to go next

- New to the API surface? Start with [Getting started](getting-started.md).
- Wiring an app end-to-end? See [Recipes](recipes.md).
- Need exact request/response shapes? See [API guide](api.md).
- Need every environment variable? See [Configuration](configuration.md).
