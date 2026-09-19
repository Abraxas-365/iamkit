# API reference

Use the API matching the caller's authority. Credential types are not interchangeable.
All example UUID labels must be replaced with IDs returned by your installation.
JSON APIs use `Content-Type: application/json`; OAuth token endpoints use form data.

| Base | Authority | Reference |
| --- | --- | --- |
| `/management/v1` | Workspace operator; X-API-Key or console cookie | [Workspace management](management.md) |
| `/management/v1/environments/:environment` | Same operator, environment in workspace | [Users/orgs](users-and-organizations.md), [apps/permissions](applications-and-authorization.md), [integrations](integrations.md) |
| `/api/v1/environments/:environment` | JWT with built-in IAM resource permissions | [Scoped IAM](scoped-iam.md) |
| `/identity/v1` | Credentials/challenges or end-user/machine JWT, route-dependent | [Identity](identity.md) |
| `/oauth`, `/.well-known` | OAuth client/protocol credentials; discovery public | [OAuth/OIDC](oauth-oidc.md) |
| `/scim/v2` | Connection-scoped X-API-Key | [SCIM](scim.md) |

The references describe current routes and significant constraints. Endpoint
examples with capitalized IDs are request templates, not executable seed data;
use [onboarding](../../start/first-application.md) to obtain actual IDs.

Read [errors/pagination](../errors-and-pagination.md) before implementing list
clients. Permission checks are exact; check [credential boundaries](../../concepts/credentials-and-boundaries.md)
and enforce tenant isolation in your own API too. `GET /health` is public and
checks database reachability; it does not exercise external integrations.
