# Security status

IAMKit is experimental, not an independently audited or certified production identity service.

## Enforced boundaries

- Management accepts hashed opaque `ik_mgmt_` credentials for active workspace operators, never application/OIDC/SCIM/machine tokens.
- Composite database keys enforce environment/organization boundaries. Organization roles, reporting hierarchy and positions do not grant operator authority.
- Exact permission catalogs reject wildcard/management permissions. Role and direct grants are combined; catalog changes are serialized against permission writes by database triggers.
- Access JWTs last 15 minutes. Online introspection validates current sessions, grants, memberships and credentials. Offline validation observes expiry, not immediate revocation.
- User refresh tokens are hashed, rotated and bound to a fixed 24-hour session. Replay revokes the family. OAuth code/refresh replay also revokes its stored family; endpoint family locks serialize concurrent rotation across replicas.
- Challenges expire after five minutes, have five attempts and single consumption. OTP login is opt-in. Password changes invalidate outstanding challenges and sessions. Email OTP is not phishing-resistant MFA.
- Federation requires deployment-approved exact environment/issuer/client/secret bindings and explicit subject links. No email collision auto-linking. Browser state/nonce/PKCE and secure binding cookies protect callbacks.
- OAuth authorization requires an application token and browser-bound approval. ID tokens are not API tokens. `prompt` and `max_age` are rejected rather than falsely claiming fresh authentication. There is no hosted consent/login UI.
- SCIM credentials own a stable organization-bound provisioning connection. Updates affect membership profiles, not other organizations. Manager references must belong to that connection and be acyclic.
- Owner impersonation requires an attributable reason, has no refresh, and cannot authorize OAuth or update self-service profiles. Consumers should inspect `actor_id` for their own restrictions.

## Deployment requirements

Use HTTPS and a stable issuer, a protected RSA key (2048+ bits), stable random `OIDC_HMAC_SECRET` (32+ bytes), secret management, restricted database access and network egress controls. Provider bindings authorize trusted IdPs, including the endpoints advertised by their metadata; do not approve attacker-controlled issuers. Keep management, provider, SCIM, service and confidential client credentials out of browsers. SDK HTTP clients reject redirects carrying credentials.

Email webhooks are trusted HTTPS services; no redirects, ten-second timeout. Protect their payloads and token. Bootstrap/recovery assume trusted local database access and write exclusively created 0600 credential files. Management/service/provisioning secrets currently expire after 24 hours; plan rotation and offline owner recovery.

IP rate limiting is process-local. Distributed abuse prevention, trusted proxy configuration, per-account controls, operational timeouts, comprehensive audit/retention, expired-record cleanup, signing-key rotation and production monitoring still require deployment work. Some inventories are bounded or unpaginated. Protect expensive login and introspection operations at the ingress layer. Do not interpret existing tests as exhaustive concurrency or protocol certification.

Use only empty managed databases for migration initialization. Tests use disposable PostgreSQL containers, never development data.

## Publication

Confirm upstream ownership/permission, dependency licenses and a publication secrets audit before distributing. The dependency graph includes Fosite and its transitive dependencies; review retracted/vulnerable dependencies before release (the current Fosite graph includes retracted `github.com/dgraph-io/ristretto v1.0.0`). No stable supported release is asserted. Use private vulnerability reporting or contact the maintainer privately; never post credentials publicly.
