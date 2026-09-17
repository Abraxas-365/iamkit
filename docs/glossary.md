# Glossary

Quick lookup for terms used throughout the docs. See [Concepts](concepts.md) for the full
explanations these summarize.

| Term | Meaning |
| :--- | :--- |
| **Workspace** | The whole IAMKit deployment, owned by operators. Top of the hierarchy. |
| **Operator** | A person holding an `ik_mgmt_...` credential; administers the workspace via `/management/v1`. Roles: owner, admin, viewer. Never the same thing as an end user. |
| **Project** | An organizational grouping of environments for one product. No permissions of its own. |
| **Environment** | The real isolation boundary — `production`/`staging`/`development`. Users, sessions, tokens, grants never cross environments; enforced by composite database keys. |
| **User** | An end user of one environment. Authenticates via `/identity/v1`, never `/management/v1`. |
| **Organization** | A business tenant inside an environment. Users join via memberships. Owns org units, positions, reporting managers — none of which grant API access by themselves. |
| **Membership** | A user's relationship to an organization (role: owner/admin/member). Grants no resource permissions alone. |
| **Org unit** | A node in an organization's configurable tree (region, department, etc. — the kind is data, not a fixed schema). |
| **Position** | A configurable job title/role assignable within an organization. Descriptive, not authorization. |
| **Application** | Something that logs users in (web app, mobile app, CLI). Has OAuth clients and explicit resource bindings. |
| **Resource** | An API. Owns an audience and an exact permission catalog — the only strings any token for it can ever carry. |
| **Audience** | A resource's identifier string (e.g. `https://billing.example`), checked against the token's `aud` claim. |
| **Permission catalog** | The exact, declared set of permission strings a resource allows. Shrinking it strips those permissions from every grant/role/service-account that used them, immediately. |
| **Grant** | A permission set assigned directly to a (organization, user, resource) triple, bypassing roles. |
| **Role** | A named, reusable permission bundle scoped to one resource, assignable to (organization, user) pairs. |
| **Service account** | A machine credential (`ik_svc_...`) bound to one application/resource pair. No user, no organization. |
| **Purpose** | A token claim: `application` (a logged-in user) or `machine` (a service account). Consumers must branch on it. |
| **Boundary** | The 4-tuple `(environment, organization, application, resource)` every user token is scoped to at login. |
| **Federation connection** | An environment-scoped, deployment-approved OIDC provider configuration (issuer/client/secret) — e.g. "Google" or "Microsoft." |
| **External identity** | An explicit link between a federation connection's provider `subject` and an IAMKit user. Never created automatically by email match. |
| **Subject (`sub`)** | The OIDC provider's stable identifier for a user — what gets linked, not the email. |
| **SCIM connection** | An organization-bound provisioning relationship, authenticated with `ik_scim_...` credentials, used by an external IdP (Okta, Azure AD, etc.). |
| **Impersonation** | An owner-only, reasoned, 15-minute, no-refresh token acting as another user, carrying `actor_id`. Restricted: cannot self-update profile or authorize OAuth. |
| **Introspection** | Live, online token validation (`POST /identity/v1/introspect`) that reflects revocation immediately, at the cost of a round trip. |
| **Offline validation** | Local JWT/JWKS signature validation (`authclient.Validate`), no network round trip, but cannot see revocation before expiry. |
| **Access token** | Short-lived (15 minute) RSA-signed JWT, the thing resource servers actually check. |
| **Refresh token** | Long-lived (within a fixed 24-hour session family), rotated on each use; replay revokes the whole family. |
| **Session family** | The set of refresh tokens descended from one login, tracked to detect replay. |
| **Management credential** | `ik_mgmt_...` — an operator's workspace administration credential. Never usable for end-user/application authentication. |
| **`errx`** | The internal classified-error type (`internal/errx`) every backend failure uses; rendered as the public `{"error":{...}}` envelope. |
| **`apierror`** | The SDK's own error type (`sdk/apierror`), decoded from the same envelope but independent of `internal/errx`. |

## See also

- [Concepts](concepts.md) for the reasoning behind these terms.
- [Architecture](architecture.md) for how the codebase itself is organized (modules, adapters,
  composition root) — a related but distinct vocabulary.
