# Breaking migration

This is a **fresh-database replacement**, not an automatic data upgrade. Public APIs and SDKs intentionally break compatibility. The old organization-owned schema and privileged application authorization are not supported fallbacks.

## Boundaries

- Workspace operators are separate from environment users. Matching emails never link or promote identities.
- Projects belong to workspaces; environments belong to projects. Organization membership belongs to an environment user.
- Applications/OAuth clients are separate from API resources/audiences. Grants and roles target resources in an organization context.
- `ik_mgmt_` credentials authenticate management; `ik_svc_` credentials mint resource-bound machine tokens; `ik_scim_` credentials provision a single organization through a stable connection.
- JWTs contain issuer/audience/environment/application/resource/purpose and user organization/session context. No special `iam` name or wildcard administrative permission exists.

## Existing installations

Use an empty PostgreSQL database, new signing key and new issuer. Run `go run ./cmd/iamkit migrate` before bootstrap/server startup. Migration files are embedded, applied under an advisory lock and tracked by SHA-256 checksums in `iamkit_migrations`. Applied files are immutable. Unmanaged non-empty schemas and checksum changes fail rather than being adopted.

Compose uses `identity_data` and does not remove old volumes. Do not manually apply genesis SQL or point the new runner at an old deployment. Existing tokens, credentials and sessions are incompatible. A future importer would need explicit project/environment mappings, identity conflicts and operator authority approval; no email-based merge is provided.

## API replacement

- Old business administration `/api/v1` → operator-authenticated `/management/v1/environments/{environment}`.
- Old `/auth` → `/identity/v1` password/challenge/profile/session/federation APIs.
- OAuth server → `/oauth/authorize`, `/oauth/authorize/complete`, `/oauth/token`, `/oauth/revoke`, standard discovery and JWKS.
- Provisioning → `/scim/v2`, using provisioning credentials, not operator keys.
- Old application scope synchronization → resource permission catalog `PUT /resources/{id}`, application metadata PATCH and explicit application-resource binding.
- Old general API keys → narrowly scoped service accounts or provisioning credentials. Their names/job titles never confer operator authority.

Google and tenant-specific Microsoft providers use verified OIDC discovery instead of proprietary OAuth profile endpoints. Deployment administrators approve the exact credential/environment/issuer/client tuple using `FEDERATION_CREDENTIAL_BINDINGS`. Provision users, link provider subject explicitly, then initiate federation. Account enumeration and automatic email matching are intentionally not ported.

OTP login is opt-in (`otp_enabled` on management user create/PATCH); enabling it does not assert email verification. Passwordless/federation-only users may be created without passwords. Password reset cannot introduce a password for an identity that has none. Public responses do not reveal account eligibility. OTP is not second-factor MFA.

See [functional equivalences](functional-migration.md), [API details](api.md) and [security caveats](../SECURITY.md).
