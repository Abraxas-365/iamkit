# AGENTS.md — IAMKit Architecture & Coding Guidelines

This document is the single source of truth for architectural decisions.
Every rule here reflects code that compiles and ships today. Do not add
aspirational patterns — update this file when the code changes.

---

## Project Structure

```
cmd/iamkit/              CLI entry point
cmd/openapi/             Writes api/openapi.json (make openapi); its test fails when the file is stale
api/                     openapi.json (generated, embedded as api.Spec, served at /openapi.json)
clients/typescript/      @iamkit/api — openapi-typescript types + openapi-fetch client
clients/js/              @iamkit/js — browser sign-in SDK (authorize ticket, login flows, MFA, passkeys, federation, complete)
clients/react/           @iamkit/react — headless SignInFlow, hooks, unstyled <SignInForm>/<AcceptInvitation>
examples/nextjs-login/   Next.js custom sign-in app + Playwright parity journeys (e2e/run.sh)
deploy/compose/          Production Compose (traefik/, caddy/: TLS proxy + IAMKit + PostgreSQL, profiles redis/otel); setup.sh writes .env + secrets, smoke.sh checks a variant
deploy/helm/iamkit/      Helm chart (migrations as a pre-install/pre-upgrade hook Job, probes on /health, HPA/PDB/ServiceMonitor); ct.yaml + ci/ for chart-testing on kind (.github/workflows/deploy.yml), pushed to GHCR OCI by release.yml
internal/
  bootstrap/             Composition root — only place concrete types are wired
  config/                Constants (TTLs, limits)
  errx/                  Typed application errors (the only error system)
  httpx/                 HTTP-specific helpers (parse pagination from Fiber ctx)
  i18n/                  End-user text catalogs (locales/<code>.json), Resolve/T/Date — stdlib only
  identity/              Typed IDs, domain primitives, validation helpers
  netx/                  Guarded dialing to operator-supplied hosts (public addresses only)
  query/                 Pagination types (Pagination, Paginated[T]) — transport-agnostic
  cache/                 Optional cache port (Store, Read, Forget — stdlib only, domain services may import it); adapters cachememory (process) and cacheredis (REDIS_URL: shared Store, usage Window, fiber limiter Storage; 250 ms per call, falls back to the database / process memory)
  worker/                Background job runner (periodic rounds, panic recovery, round/lag metrics, IAMKIT_WORKERS)
  telemetry/             OpenTelemetry setup (OTLP, Prometheus listener), metric helpers, request ids, slog handler, outbound Transport
  openapigen/            OpenAPI generator: routes of the assembled app + go/types reading of each handler (dev tool, never imported by the server)
  ptrx/                  Pointer helpers
  console/               Embedded SPA assets
  server/                Fiber server, route registration, error middleware; Server.TrustedProxies (IAMKIT_TRUSTED_PROXIES) is the only switch for reading X-Forwarded-* (c.IP())
    apiauth/             JWT authentication middleware for /api/v1/*
  iam/
    <module>/            Domain package (structs + interfaces + filters)
      adapters/
        <mod>http/       Fiber HTTP handlers
        <mod>pg/         PostgreSQL repositories (sqlx)
        <mod>*           Other adapters (bcrypt, jwt, oidc, fosite, mail, secrets)
      <mod>svc/          Service (use-case orchestration)
      <mod>module/       Module assembler (wires adapters → service → ports)
```

### Module Inventory

| Module | Domain package | Purpose |
|--------|---------------|---------|
| action | `internal/iam/action` | Actions: synchronous hooks to operator endpoints (migration 052: `action_targets` ≤ `action.MaxTargets` per environment, secret `whsec_` sealed with `action.Cipher` + `previous_sealed` for `config.EventWebhookSecretOverlap`; `action_executions(condition, target_ids uuid[])` ≤ `MaxExecutionTargets`; `action_calls` log pruned after `config.ActionCallRetention` by the `action_call_prune` job). `action.Conditions` is the curated catalog (`function:pre_sign_in`/`pre_registration`/`post_federation`/`pre_access_token`/`pre_id_token`/`pre_userinfo`, `request:user.create`/`user.update`/`membership.create`) with what each accepts (deny, claims, patch fields). `actionsvc.Service.Run` (exposed as `actionmodule.Module.Runner`) calls bound targets in order: `call` applies the answer (`Response.Check`: reserved claims `action.ReservedClaims`, ≤ `config.ActionMaxClaims`), `webhook` needs a 2xx, `async` is detached; deny → 403 `ACTION_DENIED`, a failure of an `interrupt_on_error` target → 502 `ACTION_FAILED`, other failures drop that target's changes; per-target in-memory `action.Breaker` (`config.ActionBreakerFailures` → skip `ActionBreakerOpen`); feature `actions` off skips everything. `actionhook.Caller` signs per Standard Webhooks, dials through `netx.GuardedDialer` (tests: `bootstrap.WithActionTransport`), caps bodies at `config.ActionMaxResponse`, follows no redirects. `actionpg` writes through `eventpg` (`action.failed`, `action_target.*`, `action_execution.*`). Consumers declare one-method `Actions` ports (authentication: `NewSession` → pre_sign_in, `CompleteSignup` → pre_registration; federation: `fedsvc.account` → post_federation, pre_registration only when no user has the email (`Repository.HasUser`); user/organization: request hooks; oauth: `oauthhttp` `tokenHooks` in `finish`/device, `accessHook` on refresh, `userInfoHook`), set via `SetActions`/`Deps.Actions` in bootstrap. Identity-API JWTs are never changed. `actionhttp` at `…/action-*` (management only); receivers use `sdk/action` |
| application | `internal/iam/application` | OAuth/OIDC application registration |
| authentication | `internal/iam/authentication` | Password login, sessions, refresh tokens, challenges |
| authorization | `internal/iam/authorization` | Resources, roles, grants, role assignments, group role assignments; resource ownership and grants to organizations (`resources.owner_organization_id`/`require_grant`, `resource_grants`, migration 039): with `require_grant` the `effective_grants` view keeps only the owner and granted organizations (granted roles only, `role_ids` NULL = all); narrowing, revoking or changing access ends the affected sessions in the same transaction (`authzpg` `endUngranted`/`endOrganization`); the IAM resource is never owned or granted |
| event | `internal/iam/event` | Typed event log / outbox (`events`, migration 045): `Event{ID, Type, Actor, Subject, Organization, Data}`, catalog `<subject>.<verb>` (`catalog.go`), `Classify(action, target)` derives type/subject/data from a `Mutation`'s audit strings. Writers never go through a service: every `*pg` adapter calls the shared SQL package `eventpg` (documented exception like `authpg.Resolve`, enforced by `architecture_test.go`) inside its own transaction — `Audit`/`AuditWith` (audit row + classified event; `AuditSubject` also names the subject of create routes, whose target is only the collection), `Emit` (explicit actor), `Record` (actor = `event.ActorFrom(ctx)`, set by `mgmthttp`/`apiauth` via `event.WithActor`), `UserCreated`/`Membership` helpers and `Tx`. Triggers write `session.created`/`session.revoked`; `event_actor()` resolves `actor_kind` (`operator`, `user`, `service_account`, `directory` = SCIM credential, `system`). Reads: `Queries.List` (keyset by id: `after` oldest first — a feed cursor, else newest first below `before`; `event.Page{Items, Next}`, not `query.Paginated`), served by `eventhttp` at `…/environments/:environment/events` (management) and `/api/v1` (`iam:events:read`). Change history (migration 047, no event sourcing): `AFTER UPDATE` trigger `record_changes` on users, organizations, applications, oauth_clients, roles and resources diffs the row (`jsonb` object columns per key; hashes, secrets and bookkeeping columns hidden) into the transaction-local setting `iamkit.changes` (≤ 100 rows per transaction), and `BEFORE INSERT` trigger `event_changes` moves the subject's entry into `data.changes` `{field: [old, new]}` — writers change nothing. `eventhttp.Histories` maps collections to subject kinds: `GET …/<collection>/:id/history` (`Filter.SubjectKind` + `Subject`, newest first; `/api/v1` also needs the collection's read permission) and `GET …/events/export` (`Queries.Export`, NDJSON oldest first in `event.ExportBatch` reads, streamed with a request-detached context). `Commands.Prune` is the `event_prune` worker job (`eventmodule.Module.Jobs`), retention `IAMKIT_EVENT_RETENTION` (`bootstrap.WithEventRetention`, default `config.EventRetention`). Webhooks (migration 046): `event_subscriptions` (≤ `event.MaxSubscriptions` per environment, `types` exact or `family.*`, empty = all; secret `whsec_` sealed with `event.Cipher` → 422 `ENCRYPTION_KEY_REQUIRED` without a key, `previous_sealed` signs too until `previous_expires_at`, `config.EventWebhookSecretOverlap`) and the `event_deliveries` outbox filled by trigger `queue_event_deliveries` in the event's transaction (active subscriptions and those disabled for failing — migration 057 — so re-enabling resumes; an operator's disable stops queuing; `event_id` is not an FK: pruned events deliver as `failed`). `SubscriptionCommands`/`SubscriptionQueries`/`SubscriptionRepository` + `Sender`/`Secrets`/`Dispatcher` ports, `eventsvc.Subscriptions`; `eventhttp.Subscriptions` at `…/webhooks` (management, and `/api/v1` with `iam:webhooks:read`/`write`). Delivery is one in-flight row per subscription, in id order (`ClaimDeliveries`: each active subscription's oldest pending row, leased with `FOR UPDATE SKIP LOCKED`; a round that finished a head reports `more`, so a backlog drains at once); `event.DeliveryRetryAfter` backs off from `first_attempt_at` within `config.EventWebhookRetryWindow`, then `failed` and the next row proceeds; `event_webhook_maintenance` disables subscriptions failing for `config.EventWebhookDisableAfter` (`eventpg.System`: event only, actor `system` — `audit_events.actor_id` is a uuid) and prunes deliveries. `eventhook.Sender` signs per Standard Webhooks (key = base64 part of the secret, one `v1,` per live secret), truncates `data` past `config.EventWebhookMaxPayload`, dials through `netx.GuardedDialer`; tests and `IAMKIT_ALLOW_PRIVATE_DELIVERY` replace it via `bootstrap.WithWebhookTransport`; tests call `Server.WebhookDispatcher`. Receivers verify with `sdk/webhook` |
| feature | `internal/iam/feature` | IAMKit's own feature flags (not a flag service for applications). The registry is `config.Flags` (`config.Flag{Name, Default, Scope, Description}`, scope `deployment` or `environment`); deployment values come from `IAMKIT_FEATURES` (`feature.ParseDeployment`, unknown names logged and ignored, `bootstrap.WithFeatures`); environment-scoped flags are overridden in `environment_features` (migration 051; rows of removed flags ignored). `feature.Resolve`: override › deployment › default. `Queries.Enabled` is the port features consult (`hosted.Features`: `beta_languages` off narrows an environment without listed languages to `i18n.Stable()` + its chosen default in `hostedsvc.Branded`, which emails and SMS also read through `authentication.Brand.Languages`); deployment-only flags are read in bootstrap (`saml_idp` off leaves `Server.SAML` nil). `featurehttp` at `…/features` (unknown → 404 `UNKNOWN_FEATURE`, deployment-scoped PUT → 400), audited `feature.updated`/`feature.reset` |
| federation | `internal/iam/federation` | External identity provider connections (OIDC, presets Google/Microsoft/GitHub/GitHub Enterprise/GitLab/Apple, generic OAuth 2.0 with a claim mapping, SAML 2.0 and LDAP/AD for organizations), linking by email, profile refresh |
| hosted | `internal/iam/hosted` | Server-rendered hosted sign-in/invitation pages for `hosted_login` OAuth clients, login branding: environment default ← client style ← organization overrides (`hosted.OrganizationSettings`, `organization_login_settings`, migration 041; nil fields inherit, `Apply` merges, `Queries.Branded` resolves). `hostedsvc.brandOrganization` picks the organization for a page: the authorize hint (`oauth.FormOrganization`: `organization_id` or `urn:iamkit:org:id:` scope, admitted by `oauthfosite.scopeStrategy`) › the parked login's `Chosen` › a verified domain of the typed email (`Repository.DomainOrganization`); the hint also narrows `hostedsvc.step`'s organizations and `oauthhttp.finish` refuses another organization (`oauth.ErrOrganizationHint`). Invitation pages and emails (`authentication.Message.OrganizationID` → `Branding.Brand`) use the organization's brand; codes stay environment-branded. Custom sign-in texts (`hosted.Texts`, `hosted_texts`, migration 050: one `texts` jsonb per environment/client/organization × locale; `TextCommands`/`TextQueries`): keys restricted to the `hosted.*` catalog of the locale, plain text, `i18n.SameArgs` placeholders, `TextLimit`; `Queries.Wording` lays environment › client › organization (`LayTexts`, stale keys dropped) for `hosted.Page.Texts`, and `hostedhttp.view.T/N/V` read `i18n.Texts` (custom first, then catalog) — a lookup failure only logs |
| impersonation | `internal/iam/impersonation` | Audited admin impersonation |
| invitation | `internal/iam/invitation` | Email invitations into organizations (token issue, preview, accept) |
| management | `internal/iam/management` | Workspaces, projects, environments, operators, keys |
| mfa | `internal/iam/mfa` | Second factors (TOTP, email and SMS codes, WebAuthn security keys), passkeys, recovery codes, pending MFA logins, per-organization MFA policy and allowed factors |
| oauth | `internal/iam/oauth` | OAuth2/OIDC server (authorization code + PKCE, RFC 8628 device authorization, RFC 8693 token exchange, client_credentials for service accounts, private_key_jwt, UserInfo, RFC 7662 introspection, RP-initiated and back-channel logout, per-client JWT or opaque access tokens) |
| organization | `internal/iam/organization` | Organizations, memberships, org units, positions, groups, verified domains |
| orgadmin | `internal/iam/orgadmin` | Organization-scoped administration for end users (`/api/v1/…/organizations/:organization/admin`): an `orgadmin.Principal` (token user, organization, `iam:org:*` permissions — built by `bootstrap.orgAdminCaller`, zero for impersonated tokens) is checked by `orgadminsvc`, which composes the organization, user, authorization, invitation and federation ports. Rules: users outside the organization are 404; user-record writes need `users.home_organization_id` = the organization; roles are assignable only when the caller holds all their permissions (`Role.Assignable`) or belong to a resource the organization owns or was granted (`Role.Granted`, computed by `orgadminpg.roleColumns`); owners of a resource grant it through `ResourceGrantCommands` after `orgadminsvc.owned` checks ownership (404 otherwise), the `org_owner` built-in role only by owners, and the last direct owner stays (`Owners.KeepsOwner`). `…/admin/branding` and `…/admin/password-policy` reuse `hosted.Commands`/`Queries` organization settings and `authentication.PasswordPolicyCommands` (`iam:org:read` / `iam:org:settings:write`). Built-in roles are `roles.system_role` rows (`authorization.SystemRoles`, never edited). `audit_events.actor_kind`/`organization_id` are filled by the `audit_event_context` trigger (migration 038), so writers keep inserting four columns. The opt-in hosted portal (`orgadmin.Portal`, `PortalCommands`/`PortalQueries`/`PortalRepository`, `orgadminsvc.Portals`, `orgadminhttp.Portal`) is IAMKit's own public OAuth client per environment (`oauth_clients.system = 'org_admin'`, migration 044, on the IAM resource; `oauthsvc` refuses `Update`/`Disable` of system clients with 409); `GET /identity/v1/org-admin/:environment` publishes it, the SPA under `/org-admin` (`frontend/src/org-admin`, own CSP in `server/spa.go`) signs in with code + PKCE and calls the `/admin` routes with the bearer token; disabling revokes its sessions |
| provisioning | `internal/iam/provisioning` | SCIM user and group provisioning |
| samlidp | `internal/iam/samlidp` | IAMKit as a SAML 2.0 identity provider for applications: registered service providers (entity ID, ACS URLs, application/resource, NameID format, attribute mapping), SP-initiated SSO through the hosted pages |
| serviceaccount | `internal/iam/serviceaccount` | Machine-to-machine credentials |
| signing | `internal/iam/signing` | Per-environment token signing keys (`next`→`active`→`retiring`→`retired`), JWKS, the `Keyring` every token signer/verifier uses |
| usage | `internal/iam/usage` | Limits and daily usage per environment (migration 056). `usage.Catalog`: totals `users_max`/`organizations_max`/`applications_max` (count query, 422 `QUOTA_EXCEEDED` via `usage.ErrExceeded`, soft under concurrency), daily `emails_per_day`/`sms_per_day` (`usage_daily` + unflushed counts, 429) and per-minute `requests_per_minute`/`action_calls_per_minute` (fixed window through the `usage.Window` port: `cacheredis.Window` shared by the replicas with `REDIS_URL` (falls back to `usagememory`), else `usagememory` per replica; fails open, 429). Deployment caps `IAMKIT_LIMITS` (`usage.ParseDeployment`, `bootstrap.WithLimits`) are ceilings; `environment_limits` (NULL = deployment) only `Tighten`s them; `PUT …/limits` workspace owners only (`usage.Mutation.Owner`), audited `limits.updated`; effective limits cached `config.UsageLimitCacheTTL`. Consumers declare their own ports and get them via `SetQuota`/`SetUsage` + `Deps.Quota`/`Deps.Usage` in bootstrap: `Quota.Admit` (user, organization, application, provisioning, invitation accept, federation first sign-in) and `Usage{Admit, Count}` (authentication: signup, `DeliveryService.Send`, `SMSService.SendSMS`, `Tokens.Issue`; action: `actionsvc.call` skips refused calls as `OutcomeSkipped`; oauth: `oauthhttp.Handler.issued` after fosite token responses). `Commands.Count` keeps counts in memory; `Server.Start` runs `FlushUsage` every `config.UsageFlushInterval` and at shutdown (`Server.WaitFlushed`) on every replica. `usage_rollup` (logins = `session.created` without parent session/impersonation, `users_created`; cursor `usage_rollup_cursor`, events settled `config.UsageRollupSettle`) and `usage_prune` (`config.UsageRetention`) are worker jobs. `usagehttp.Meter` (on `/api/v1/environments/:environment`) admits `requests_per_minute` and counts `api_requests`; `…/limits` (management) and `…/usage?days=` (management + `/api/v1` `iam:usage:read`) |
| user | `internal/iam/user` | End-user CRUD; derived `user.State` (`userpg.stateSQL`: suspended › locked › initial › inactive › active — `active` stays the only sign-in gate; `users.last_signed_in_at` is written by `authpg.Transaction.CreateSession`), deactivate/reactivate (audited); incident actions `RevokeSessions` (`POST …/users/:id/revoke-sessions`: every live session ends, audited `user.sessions_revoked` with `data.count`) and `RequirePasswordChange` (`users.password_change_required`, migration 059: `authentication.PasswordAccount.MustChange` treats it like an expired password; every password write clears it; users without a password → 422); per-key metadata (`identity.ValidateMetadata`/`SetMetadata`, shared with organizations), `users.profile` checked against the environment's `user_schemas` row (`SchemaValidator`), self-service `/identity/v1/me/profile` (`x-iamkit-self`), claims released through `oauth.ProfileClaims` (`x-iamkit-claim`, `profile` scope); `users.avatar_url` (`identity.AvatarURL`: https link only, no uploads) is released as `picture` the same way, set by users via `PATCH /identity/v1/me` (`authentication.ProfileUpdate`) and filled from federation `picture` claims (`fedpg.fillAvatar` only when empty); optional `users.username` (`identity.Username`, never `@`, unique per environment — `userpg.usernameTaken` → 409) is a second login identifier: `identity.Login` splits input into email or username, `authpg.PasswordUser`/`EligibleChallengeUser` match either in one query, `authsvc.requireNoSSOAfter` checks SSO enforcement for username logins only after the password matched, hosted `Identify` sends usernames straight to the password page; released as `preferred_username`; `users.phone`/`phone_verified` (CHECK `users_phone_verified`: verified needs a number) are verified by users through `PhoneCommands` (`usersvc.Phones`, `/identity/v1/me/phone` + `/verify`, fresh sign-in `user.FreshAuth`, SMS through the one-method `user.SMS` port = `authsvc.SMSService.SendSMS`, purpose `phone_verification`; the pending code lives in `phone_verifications`, migration 042, limits in `user.PhoneVerification.Send`) or set by operators (`Update.PhoneVerified`, audited `user.phone_verified_set`); released as `phone_number(_verified)` with the `phone` scope (`Queries.Claims` takes the granted scopes); SCIM maps `phoneNumbers[type eq "mobile"]` only when `provisioning_connections.map_phone` (`provisioning.Principal.MapPhone`); `users.kind` `machine` (migration 040: no email/username/password/phone/OTP by CHECK, trigger `refuse_machine_user` refuses factors, external/provisioned identities and challenges; SCIM group reads/replaces skip them) — machine users authenticate only with personal access tokens (`user_access_tokens`, `ik_pat_`, `AccessTokenCommands`/`AccessTokenQueries`/`AccessTokenRepository`, one organization + application resource each). `authpg.Repository.AccessToken` re-checks token, user, membership, organization, application and `effective_grants` on every use; `authsvc` `Validate`/`ValidateSelf` branch on the prefix (so `apiauth` and `/identity/v1/introspect` accept them, `Purpose` `pat`, no session), `ExchangeAccessToken` (`POST /identity/v1/token-exchange`) issues an application JWT on one reused `sessions.access_token_id` session; revoking a token ends those sessions. Machine users also sign in with keys (`user_keys`, migration 043, at most `user.MaxKeys`; `KeyCommands`/`KeyQueries`/`KeyRepository`, `/users/:id/keys`): a public JWK uploaded (`identity.ParsePublicJWK`: RSA ≥ 2048 or EC P-256/384/521, public members only, stored in `identity.MarshalPublicJWK` form) or generated by the `user.KeyPairs` port (`userkeys.RSA`, private PEM returned once). The RFC 7523 grant `oauth.GrantJWTBearer` is dispatched by `oauthhttp.Handler.keyGrant` before fosite (no client) to `authentication.TokenIssuer.KeyGrant`: `TokenCodec.AssertionKey` (kid) → `TokenRepository.MachineKey` (live key, active machine user) → `TokenCodec.VerifyAssertion` (`authjwt`, iss = sub = user, aud = issuer or token endpoint, exp ≤ `config.ClientAssertionMaxAge`) → `TokenRepository.KeySession` (jti spent in `client_assertion_jtis` under a `user_key:` prefix, `authpg.Resolve`, one reused `sessions.user_key_id` session, `amr` `swk`); removing a key revokes its sessions; every refusal is `invalid_grant` |

---

## Ports & Adapters (Hexagonal Architecture)

Every module follows the same four-package layout:

```
<module>/
  ports.go           Interfaces only — Commands, Queries, Repository
  <entity>.go        Domain structs, Validate() methods, Mutation, constants
  adapters/
    <mod>http/       Inbound adapter — HTTP handlers (Fiber)
    <mod>pg/         Outbound adapter — PostgreSQL (sqlx)
  <mod>svc/          Service — implements Commands/Queries, depends on Repository interface
  <mod>module/       Assembler — New(Deps) Module, returns interface values
```

### Interface Segregation: Commands, Queries, Repository

Every module in `ports.go` defines **three interface roles**:

```go
// Commands — write operations exposed to handlers and other modules.
type Commands interface {
    Create(ctx context.Context, environment identity.EnvironmentID, input Create) (identity.ApplicationID, error)
    Update(ctx context.Context, m Mutation, application identity.ApplicationID, input Update) error
}

// Queries — read operations exposed to handlers and other modules.
type Queries interface {
    Find(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) (Application, error)
    List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
}

// Repository — persistence contract consumed only by the service.
type Repository interface {
    Create(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, input Create) error
    Find(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) (Application, error)
    List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
    Update(ctx context.Context, m Mutation, application identity.ApplicationID, input Update) error
}
```

**The three roles serve different consumers:**

| Interface | Implemented by | Consumed by |
|-----------|---------------|-------------|
| `Commands` | Service | HTTP handlers, other modules |
| `Queries` | Service | HTTP handlers, other modules |
| `Repository` | PG adapter | Service only |

**Key differences between Commands and Repository:**

- **Commands generate IDs** — `Create` returns `(identity.ApplicationID, error)`.
  The service calls `identity.NewApplicationID()` and passes it down.
- **Repository receives IDs** — `Create` takes the ID as a parameter and
  returns only `error`. It never generates identifiers.
- **Commands validate** — the service calls `input.Validate()` before
  delegating. The repository trusts the service layer.

**The service implements both Commands and Queries** with a compile-time check:

```go
var _ application.Commands = (*Service)(nil)
var _ application.Queries = (*Service)(nil)
```

**Modules with sub-domains** split further. Authorization has separate
`ResourceCommands`/`ResourceQueries`/`ResourceRepository`,
`GrantCommands`/`GrantQueries`/`GrantRepository` and
`ResourceGrantCommands`/`ResourceGrantQueries`/`ResourceGrantRepository`.
Organization has `StructureCommands`/`StructureQueries`,
`GroupCommands`/`GroupQueries`/`GroupRepository` and
`DomainCommands`/`DomainQueries`/`DomainRepository` (plus the `Resolver` DNS
port, adapter `orgdns`, replaceable in tests via `bootstrap.WithResolver`);
provisioning has the same trio for SCIM groups. Federation's `fedoidc` adapter
dials providers through `GuardedTransport` (public addresses only, via
`netx.GuardedDialer`) for
sealed-secret connections; tests replace it via
`bootstrap.WithFederationTransport`. Authentication has
`DeliveryConfigCommands`/`DeliveryConfigQueries`/`DeliveryConfigRepository`
(per-environment email delivery; secrets sealed with `Cipher`, never returned)
and `TemplateCommands`/`TemplateQueries`/`TemplateRepository` (email wording
overrides per purpose × language, text only — `Copy` with `{{placeholders}}`,
no HTML) and `PasswordPolicyCommands`/`PasswordPolicyQueries`/`PasswordPolicyRepository`
(one end-user `PasswordPolicy` per environment, default when none is saved;
organizations add `PasswordRequirements` that only `Tighten` it — users are
environment-wide, so `PasswordPolicies.MemberPolicy` applies every active
membership's; user and invitation modules consume it through their own one-method
`PasswordPolicy` port, wired in bootstrap) and
`SignInPolicyCommands`/`SignInPolicyQueries`/`SignInPolicyRepository` (allowed
methods per environment, narrowed by the organization's `allow_*` columns via
`Transaction.OrganizationMethods`, checked by `authsvc.Service.allowed` before
any account lookup → 403 `METHOD_NOT_ALLOWED`; its `mfa_required` is OR-ed into
`mfapg.Policy`; its `allow_signup` + `signup_organization_id`/`signup_group_id`
drive `SignupCommands` (`Signup` parks a `signups` row and emails an
`email_verification` code, 202 whether or not the email has an account;
`CompleteSignup` creates the verified user, membership and group membership in
one `SignupTransaction.Join`, audited `user.signup`, no session — hosted
`Flow.CompleteSignup` then continues through `hostedsvc.result`; per-client
`client_sign_in.signup` hides the hosted link); its `allowed_factors`
(`identity.ValidateFactors`, omitted on PUT = keep) intersects the organization's
`allowed_factors` in `mfapg.Policy`) and `SMSCommands`/`SMSQueries`/`SMSRepository`
(one SMS provider per environment, `twilio` or `webhook`, secret sealed; the
`authsms` adapters dial through the guarded transport — `authmodule.Mail.SMSClient`
/ `TwilioEndpoint` override it in tests; attempts share `delivery_activity`
keyed by `channel`). Its `authmail` SMTP/Resend/webhook adapters dial environment providers
through `netx.GuardedDialer` (webhooks also sign requests per Standard
Webhooks, `authmail.SignWebhook`); the deployment-wide provider (`EMAIL_PROVIDER`,
read in `bootstrap/mail.go`) may reach private hosts; tests override both via
`bootstrap.WithMail` (`Dial`, `ResendClient`, `WebhookClient`, `SMSClient`), and the
development-only `IAMKIT_ALLOW_PRIVATE_DELIVERY` sets `Dial`/`WebhookClient`/`SMSClient`
to unguarded ones (warning logged). Management has
`ControlCommands`/`ControlQueries` and `ActivityCommands`/`ActivityQueries`.
Method names still use standard verbs (`Create`, `List`, `Find`). When a
single Queries/Repository interface manages multiple entity types, prefix the
verb with the entity: `ListRoles`, `ListGrants` — the verb always leads.

**The module assembler** exposes only interface types, never the concrete service:

```go
type Module struct {
    Commands application.Commands
    Queries  application.Queries
    HTTP     *apphttp.Handler
}

func New(deps Deps) Module {
    service := appsvc.New(apppg.New(deps.DB))
    return Module{
        Commands: service,
        Queries:  service,
        HTTP:     apphttp.New(service, service, deps.ActorID),
    }
}
```

The HTTP handler constructor takes `Commands` and `Queries` as separate
parameters — it never sees `*Service` or `Repository`.

### Additional Port Interfaces

Beyond the core three, modules define additional interfaces for
infrastructure concerns that should be swappable:

| Interface | Module | Purpose |
|-----------|--------|---------|
| `Passwords` | authentication, management | `Hash(string) (string, error)`, `Compare(string, string) bool` |
| `Secrets` | authentication, federation, oauth, provisioning, serviceaccount | Token/key generation and hashing |
| `Delivery` | authentication | Send challenge codes and invitations (`Message`); per environment a webhook, SMTP or Resend configuration (`DeliveryConfig.Provider`), else the global one |
| `Mailer` / `Renderer` / `Branding` | authentication | Send a rendered `Email` (SMTP, Resend); render a `Message` in the environment's `Brand` and language (`internal/i18n`); read that brand |
| `Mailer` | invitation | Send invitation mail and build links; `invmail` adapts authentication delivery |
| `Provider` | federation | Provider discovery, authorization and verification (`fedoidc`): OIDC discovery + ID token, or for `github`/`github_enterprise`/`oauth2` (no ID token, no nonce) PKCE + a user API read (`gitHubClaims` at the connection's API base; `oauth2Claims` maps `Options.Claims` dotted paths, email verified only via the mapped member). `federation.Preset` derives the issuer (`base_url`, or the `authorize_url` origin for `oauth2`). `fedsaml` (`github.com/crewjam/saml`) serves `ProviderSAML` (organization connections only): `Prepare` fetches/parses IdP metadata (guarded transport) and sets `Issuer` = IdP entity ID, `Client` = SP entity ID (`federation.SAMLServiceProvider`); `Authorize` builds an HTTP-Redirect AuthnRequest whose ID is `fedsaml.RequestID(nonce)`; `Verify` checks the posted response (signature, `InResponseTo`, audience, ACS, validity) and maps NameID/`Options.Attributes`; `Metadata` serves SP metadata. The SP key is the environment's `signing.Keyring` signer with a self-signed certificate derived from it (stable across replicas). `fedmodule.router` picks `fedoidc` or `fedsaml` by `Connection.Provider`. The ACS (`fedhttp.ACS`) parks the response (`Repository.ParkAssertion`, `saml_responses`, one-time `ik_saml_` handle) and 303s to the ordinary callback, which takes it (`TakeAssertion`) under the binding cookie; `UseAssertion` (`saml_assertions`) refuses replays. Tests use the in-process IdP `fedsaml/samltest` |
| `Directory` | federation | Password check against an organization's LDAP directory (`ProviderLDAP`, organization connections only, no redirect). `fedldap` (`github.com/go-ldap/ldap/v3`) dials `ldaps://` or `ldap://`+StartTLS (plaintext refused by `validLDAP`) through `netx.GuardedDialer` unless the host is in `IAMKIT_LDAP_ALLOWED_HOSTS` (`fedmodule.Deps.LDAPAllowed`; tests replace the dial via `bootstrap.WithLDAPDialer`), binds as `Options.BindDN` (password = the sealed client secret) or anonymously, searches `UserBaseDN` with `UserFilter` (`{email}`/`{username}` escaped; exactly one entry), binds as it and maps `Options.Attributes`. `Discovery.Provider` = `ldap` tells clients to post the password: headless `Flows.Directory` (`POST /identity/v1/federation/ldap/login`, answers like `/login`), hosted `Flows.DirectoryHosted` via `hosted.Flow.Directory` (Route method `ldap`). Both reuse `fedsvc` account resolution, so logins are `authentication.MethodSSO` (`amr` `fed`). Issuer = `federation.LDAPServer(url)`, Client = lowercased base DN; neither can change. Tests use the in-process directory `fedldap/ldaptest` (`github.com/jimlambrt/gldap`) |
| `Flows` | federation | Browser login flows (`Discover`, `Start`, `StartHosted`, `Callback`, `Redeem`, `EnvironmentConnections`), separate from Commands/Queries. `Callback` returns an `Outcome`: a session, or for hosted starts (`Continuation` = OAuth ticket) only the `Verified` identity, or for a headless start with `federation.Return` (custom sign-in UI, migration 054: `return_to` on an origin of an OAuth client of the application — `Repository.ReturnAllowed` — + S256 `code_challenge`) a one-time `ik_fedres_` handle parked in `federation_results` (`ResultTTL`, no token stored) that `fedhttp.Callback` 303s to `return_to`; `POST /identity/v1/federation/result` → `Redeem` (`Result.Verifies`, wrong verifier spends it) issues the session like `/login`. First logins go through `Connection.Admit` → `Repository.Provision` (`Provisioning.Create` = JIT; without it an organization `link_email` connection links only an existing member, origin `email`); `Connection.UpdateProfile` calls `Repository.Refresh` (`Connection.Profile`) on every sign-in, audited `federation.profile_updated` |
| `Authenticator` | authentication | Verify a credential without a session (`VerifyPassword`, `VerifyCode` → `Verified`), list accessible `Organizations` (leaving out those whose methods refuse the `Verified.PolicyMethod()`), then `Issue` the session once the organization is chosen (re-checks SSO enforcement and the method) |
| `Flow` | hosted | The hosted sign-in journey; consumes the `Authorizations` (pending OAuth ticket), `Challenges`, `Federation`, `Invitations` and `SecondFactor` ports declared in `hosted/ports.go` plus `authentication.Authenticator`. The parked `hosted.Login{Verified, Chosen, Attempts}` carries state between pages; `hostedsvc.step` orders: MFA first for an enrolled user with several organizations (non-SSO logins; a factor applies in all of them) → chooser → MFA/enrollment for the chosen organization → `Issue`. Second-factor tries are reserved atomically (`Repository.Attempt`) before the code is checked |
| `SecondFactor` | authentication | Login-time MFA (`Requirement`, `Begin`, `Complete`, `Enroll`), implemented by `mfasvc` (`mfa.Logins`). `Login`/`VerifyChallenge` return `authentication.Result{Issued, MFA}`: `SignIn` commits the credential transaction, then either issues the session or parks a pending `ik_mfa_` login. `authhttp.Respond` renders either shape; federation receives it as the injected `Respond` closure |
| `Logins` | mfa | Everything login flows need from mfa (headless pending logins + hosted `Verify`/`Enrolling` without a pending token) |
| `TOTP` | mfa | RFC 6238 codes/URIs (`mfatotp`, stdlib only, RFC test vectors) |
| `Relying` | mfa | WebAuthn relying party (`mfawebauthn.New(issuer, origins)`: RP ID = issuer host, origins = issuer origin + `IAMKIT_WEBAUTHN_ORIGINS`; zero value disabled). Ceremony state is opaque to `mfasvc` and parked in `webauthn_sessions` (hashed `ik_wa_` id, single use, `config.WebAuthnCeremonyTTL`). Tests drive it with the stdlib software authenticator `mfawebauthn/softkey` |
| `Passkeys` | mfa, authentication, hosted | Discoverable-credential sign-in: `mfa.Passkeys` (`BeginPasskey`/`FinishPasskey` → user) is consumed by `authsvc` as `authentication.Passkeys`, which exposes `PasskeyCommands` (headless `/identity/v1/passkeys/login/*`) and `Authenticator.VerifyPasskey` (hosted); `hosted.Passkeys` starts hosted ceremonies. A passkey is gated by `SignInPolicy.AllowPasskey`, `organizations.allow_passkey` (method `passkey`) and the `webauthn` factor being allowed; its `amr` is `hwk`,`user`,`mfa` (`authentication.FirstFactorAMR`), so `HasMFA` skips the second factor |
| `Sender` | mfa | Deliver email/SMS factor codes; `mfasend.Sender` adapts authentication `Delivery` (purpose `mfa`) and `SMSCommands.SendSMS`, wired by `mfamodule.Module.Deliver` in bootstrap |
| `SMSDelivery` | authentication | Send one `SMS` (`authsms.Twilio`, `authsms.Webhook`, Standard Webhooks-signed) |
| `Cipher` | authentication, event, federation, mfa | Seal/open stored secrets (SMTP password / Resend API key, client secrets, TOTP secrets); implemented by `internal/cryptox.Sealer` (`IAMKIT_ENCRYPTION_KEY`), injected via `bootstrap.WithSealer` |
| `Breaches` | authentication | Breached-password lookup for the policy's `breach_check`; `authhibp` (Have I Been Pwned range API, k-anonymity). Errors and `config.BreachCheckTimeout` fail open; tests replace it via `bootstrap.WithBreaches` (nil disables) |
| `TokenCodec` | authentication | JWT sign/parse (combines `TokenIssuer` + `TokenValidator`) |
| `Keyring` | signing | `Signer(environment)` (the environment's active key, else the deployment key `JWT_PRIVATE_KEY_PATH`; an active key that cannot be opened fails closed), `Verifier(kid)` (`Verifier.Allows(environment)`: environment keys verify only their environment), `JWKS`. `signingsvc` caches published keys `config.SigningKeyCacheTTL` and reloads on an unknown kid at most once per `config.SigningKeyMissInterval`. Consumed by `authjwt.Codec` and `oauthfosite` (`Signer`, `Hints`, provider); private halves sealed with `signing.Cipher` (`IAMKIT_ENCRYPTION_KEY`, else 422 `ENCRYPTION_KEY_REQUIRED`). Retiring needs `config.SigningKeyRetireDelay` after demotion or `force` (409 `KEY_IN_USE`) |
| `Transaction` | authentication, invitation, mfa, oauth | Database transaction handle for multi-step mutations |
| `AccountRepository` | oauth | Service accounts as OAuth clients of `client_credentials` (`FindAccount` → `oauth.Account`: SHA-256 secret hash + `identity.ClientAuth`). `oauthfosite.Accounts.Authenticate` runs fosite's client authentication over it (`digest` hasher, not bcrypt); `oauthhttp.Handler.token` branches `grant_type=client_credentials` to it (set with `Handler.Accounts`) and mints with `authhttp.Tokens.IssueMachine` — the same token as `/identity/v1/machine-token`, which refuses `private_key_jwt` accounts |
| `LogoutCommands` / `LogoutQueries` / `LogoutRepository` / `LogoutSender` / `Dispatcher` | oauth | Back-channel logout. A trigger (`queue_logout_notification`, migration 027) fills the `logout_notifications` outbox when a session with `oauth_client_id` ends (`revoked_at` set or row deleted) and the client has a `backchannel_logout_uri`. `oauthsvc.Logouts.DispatchLogouts` leases due rows (`ClaimLogouts`, `FOR UPDATE SKIP LOCKED`, safe on every replica), sends through `oauthfosite.LogoutSender` (logout+jwt signed by the environment key, guarded transport) and retries with `oauth.RetryAfter` until `LogoutMaxAttempts`, then `LogoutFailed` audits `oauth.backchannel_failed`. Delivery and pruning are `internal/worker` jobs (`oauthmodule.Module.Jobs`: `logout_delivery` with `Logouts.Lag` → `iamkit.worker.lag`, `logout_prune`), registered on `server.Server.Workers` in bootstrap, started by `Server.Start(ctx)` from `cmd/iamkit` and stopped with the signal context; tests call `Server.LogoutDispatcher` or `Workers.RunOnce` directly. Operators read `…/logout-deliveries` and retry failed ones (`oauthhttp.Logouts`) |
| `SubscriptionCommands` / `SubscriptionQueries` / `SubscriptionRepository` / `Sender` / `Secrets` / `Dispatcher` | event | Event webhooks (see the event module row): subscriptions, the `event_deliveries` outbox, the `event_webhook` / `event_webhook_maintenance` jobs (`eventmodule.Module.Jobs`) and the Standard Webhooks `eventhook.Sender` |
| `Devices` | oauth, hosted | RFC 8628 device authorization grant. `oauth_clients.grant_types` (`oauth.ValidateGrantTypes`: default `authorization_code`+`refresh_token`; `GrantDeviceCode` needs `hosted_login`; redirect URIs only with `authorization_code`). `oauth_device_codes` (migration 028) keeps hashed `ik_device_` and user codes (`UserCodeAlphabet`, 8 consonants); `oauth.Device.Poll` is the polling state machine (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant` as `errx.Error.Code`). `/hosted/device` (`hostedhttp` device pages, `hosted.Devices`) runs the unchanged hosted journey on an `oauth_authorizations` ticket with `device_hash`; `oauthhttp.Handler.finish` branches on `Ticket.Device` to `Authorization.ApproveDevice` (audited `oauth.device_approved`) and renders `hostedhttp.Handler.DeviceApproved` instead of redirecting. At `/oauth/token` fosite authenticates the client, `oauthfosite.deviceGrant` (a custom `TokenEndpointHandler`) checks the request and mints tokens after `Devices.RedeemDevice` fills the session (`Handler.session`, shared with the code flow). Wired in bootstrap with `Handler.Devices` on both HTTP handlers |
| `Exchanges` / `ExchangeRepository` | oauth | RFC 8693 token exchange at `/oauth/token`, handled in `oauthhttp.exchangeToken` before fosite (fosite only authenticates the client via `oauthfosite.AuthenticateClient`); issued tokens are ordinary IAMKit access JWTs signed with `authhttp.Tokens.Sign` (no refresh/ID token). `subject_token_type` `access_token`: a confidential client with `oauth.GrantTokenExchange` (`oauth.ValidateExchangeClient`) exchanges a user token for another resource of its application — `oauthpg.ExchangeSession` recomputes access with `authpg.Resolve` and reuses/creates a child session (`sessions.parent_session_id`, one live child per resource, revoked with its parent by trigger `session_children_ended`, migration 029; audited `oauth.token_exchanged`). `urn:iamkit:params:oauth:token-type:user_id`: a service account with `service_accounts.can_impersonate` (owner-only `saccthttp` `PUT …/impersonation`, audited `service_account.impersonation`; forbidding revokes its `sessions.actor_account_id` sessions) impersonates a user with a `reason`; the token's `act` claim (`authentication.Token.ActorAccount`) names it and `Token.Impersonated()` covers both actor kinds; audited `oauth.impersonated`. Errors are `errx` with `oauth.Exchange*` codes mapped to OAuth errors by `exchangeError` |
| `Protocol` / `Flows` | samlidp | SAML IdP. `samlxml` (crewjam `IdentityProvider` pieces) builds the IdP metadata at `/saml/:environment/metadata` (entity ID = that URL, SSO `/saml/:environment/sso`, key = the environment's `signing.Keyring` signer + `signing.Signer.Certificate`), decodes AuthnRequests (Redirect or POST) and signs responses + assertions (RSA-SHA256, not encrypted, `SessionIndex` = IAMKit session). `samlidp.AuthnRequest.Check` accepts only a registered issuer (`FindEntity`) and ACS URL; AuthnRequest signatures are not verified. `Flows.Begin` parks it in `saml_sso_requests` (hashed `ik_samlreq_` ticket = `samlidp.TicketPrefix`, browser binding hash, `RequestTTL`, single use) and `samlhttp.SSO` 303s to `/hosted/login`. Bootstrap's `tickets` composite (`internal/bootstrap/saml.go`) implements `hosted.Authorizations`, routing `ik_samlreq_` tickets to `Flows.Target` as an `oauth.Pending` whose `Client` has a zero ID (environment branding and default sign-in options, `hostedsvc.options`); `finisher` routes `Finish` to `samlhttp.Handler.Finish`, which `Flows.Finish`es (audited `saml.assertion_issued`) and renders `hostedhttp.Handler.PostForm` (auto-submit form, nonce'd script). Service providers reference `application_resources`; deleting one is a hard delete. Tests use the in-process SP `samlxml/samltest` |
| `SchemaValidator` | user | `Check(schema)` compiles a user schema (draft 2020-12 only, remote `$ref` refused, formats asserted), `Validate(schema, profile)`; `userschema.Validator` (`santhosh-tekuri/jsonschema`). `user.Properties` reads the `x-iamkit-self`/`x-iamkit-claim` annotations; schemas are never applied retroactively (`SaveSchema` only counts `NonConforming`) |
| `ProfileClaims` | oauth | A user's `x-iamkit-claim` attributes (`user.Queries.Claims`, wired in bootstrap with `oauthhttp.Handler.ProfileClaims`), added to ID tokens (`finish`, device grant) and UserInfo when the `profile` (or, for `phone_number(_verified)`, `phone`) scope was granted; a lookup failure leaves them out |
| `Hints` | oauth | Verify an `id_token_hint` for `/oauth/end_session` (`oauthfosite.Hints`: `signing.Keyring` + issuer, expired tokens allowed) → `oauth.IDTokenHint`; `oauthsvc.Logout` ends its `sid` via `Repository.EndSession` (audited `oauth.logout`) |

These follow the same rule: defined in `ports.go`, implemented by adapters,
consumed by services.

### Rules

1. **`ports.go` contains only interfaces.** No structs, no constants, no
   `Validate()` methods. One file, predictable location.

2. **Domain files are named after the aggregate**, not `models.go` or `types.go`:
   `resource.go`, `grant.go`, `connection.go`, `credential.go`, etc.

3. **Domain structs own their validation.** Every create/update struct gets
   `Validate() error` on a value receiver. One field → one error message.

4. **Services are thin orchestrators.** They call `input.Validate()`, generate
   IDs, enforce cross-entity invariants, and delegate to the repository.

5. **Adapters never import other adapters** (except `authpg.Resolve` which is
   shared SQL reused by `fedpg` and `oauthpg` for session resolution, and
   `eventpg`, the event writer every `*pg` adapter calls in its own
   transaction — only `*pg` packages may import it).

6. **Module assemblers are the only place** where concrete adapter types appear
   together. They return a `Module` struct with interface-typed fields.

7. **The composition root** (`internal/bootstrap/container.go`) calls module
   assemblers and wires cross-module dependencies (e.g. authentication sessions
   into federation). Cycles between HTTP adapters are closed there with a
   setter: `fedhttp.Handler.Continue(hostedhttp.Handler.Federated)` lets the
   federation callback resume a hosted login, and the hosted module receives
   `oauthhttp.Handler.Finish` to complete the authorization.

8. **OIDC endpoints** live in `oauthhttp`: discovery is built from
   `oauth.NewDiscovery` (a struct; only add fields); `/oauth/introspect`
   uses fosite's introspection factory (`oauthfosite.Session.GetExtraClaims`
   surfaces the IAMKit access claims) and re-checks session/client liveness
   with `Flows.Access`; `/oauth/userinfo` goes through `authhttp.Tokens.Self`
   and needs an OAuth-issued token (`oauth_client_id`, `scp` ∋ `openid`);
   `/oauth/end_session` renders `hostedhttp.Handler.SignedOut`, wired in
   bootstrap with `oauthhttp.Handler.SignedOut`; `/oauth/device_authorization`
   authenticates clients with `oauthfosite.AuthenticateClient` (fosite's
   own client authentication outside its endpoints). Token endpoint
   authentication of OAuth clients and service accounts is one
   `identity.ClientAuth` (`none`, `client_secret_basic`, `client_secret_post`,
   `private_key_jwt` with `jwks` or `jwks_uri`); `oauthfosite.authClient`
   turns it into fosite's client view. `private_key_jwt` assertion `jti`s are
   single-use per client in `client_assertion_jtis` (`oauthfosite.Assertions`);
   `jwks_uri` is fetched through `oauthfosite.KeyFetcher` over the guarded
   transport (`bootstrap.WithFederationTransport` replaces it in tests).
   `oauth_clients.access_token_format` (`oauth.TokenFormatJWT` default,
   `TokenFormatOpaque`) picks the access token shape: `oauthfosite.formatStrategy`
   issues JWTs or fosite HMAC handles (`ory_at_…`) and validates both by shape,
   so a format change never strands issued tokens. Opaque tokens are resolved
   only by `/oauth/introspect` and `/oauth/userinfo` (`Handler.opaqueToken`:
   `Flows.AccessTokenClient` finds the client by `oauthfosite.OpaqueKey`, then
   fosite introspection + `Flows.Access` liveness); `apiauth`, `/identity/v1`
   and SDK validation accept JWTs only. `finish` records the
   session's client (`Authorization.Bind` → `sessions.oauth_client_id`).

9. **Hosted pages** (`hostedhttp`) are server-rendered `html/template` files
   embedded from `templates/`, without JavaScript except one embedded
   WebAuthn script (security keys, passkeys) emitted only when a ceremony
   can be offered, and the one-line auto-submit of the SAML response page
   (`post`), both bound to the CSP script nonce. Every page sets its own CSP
   with a per-response style nonce (`font-src` only when the theme sets a
   font: `'self'` for the OFL fonts embedded from `fonts/` and served at
   `/hosted/fonts/:file`, `https:` for a custom `.woff2`);
   `internal/server/hosted.go` mounts them
   under `/hosted` with frame/referrer headers and per-route rate limits.
   Every form action re-validates the OAuth (or SAML, `ik_samlreq_`) ticket
   and its binding cookie. The SAML IdP routes (`/saml/:environment/*`) are
   mounted by `Server.samlRoutes` with the same headers and their own limits.

10. **Custom sign-in UIs** (`clients/js`, `clients/react`,
   `examples/nextjs-login`) run the hosted journeys over `/identity/v1`
   from another origin. `oauth_clients.allowed_origins` (migration 053,
   `oauth.Origins`: https or loopback http, ≤ `oauth.MaxOrigins`,
   normalized) feed `Server.ClientOrigins` (`oauth.Queries.OriginAllowed`,
   cached `config.ClientOriginCacheTTL`). `server/cors.go` honours them
   only on `browserFacing` routes (`/identity/v1/`, `/oauth/`, `/.well-known/`); the
   deployment-wide `CORS_ALLOWED_ORIGINS` applies everywhere. The ticket
   stays bound to the `__Host-iamkit-authorization` cookie:
   `GET /identity/v1/authorize/:ticket` (`hosted.Flow.Authorization` →
   `hosted.Authorization`, refused for `hosted_login` clients) needs it, and
   so does `/oauth/authorize/complete`, which answers `{redirect_to}`
   (`oauthhttp.Completion`) for `Accept: application/json`. The sign-in
   calls themselves are cookie-less (JSON body + bearer token), which is
   the CSRF model. The same origins authorize federation `return_to`
   (`federation.Return`). Packages import with explicit `.js` extensions
   (Node ESM). `examples/nextjs-login/e2e` is the Playwright parity suite
   (CI job `custom-ui-parity`).
### Interface Parameter Naming

Interface methods **must** name every parameter. Bare positional types are
not allowed — they are unreadable at the call site:

```go
// ✗ Bad — unnamed, unreadable
LinkApplication(context.Context, identity.EnvironmentID, identity.ApplicationID, identity.ResourceID) error

// ✓ Good — short names, the type carries the "ID" semantics
LinkApplication(ctx context.Context, environment identity.EnvironmentID,
    application identity.ApplicationID, resource identity.ResourceID) error
```

Naming conventions:
- `ctx context.Context` — always first.
- **Typed ID parameters use the short entity name** — `environment`, `application`,
  `user`, `session`, `role`, `connection`, `credential`, etc. Do **not** suffix
  with `ID` — the type `identity.ApplicationID` already says it's an ID.
- Non-ID strings: `email`, `password`, `name`, `role`, `code`, `purpose`.
- Struct parameters: `p Principal`, `m Mutation`, `b Boundary`, `input Create`.
- When two IDs of the same entity kind appear, disambiguate with a prefix:
  `sourceUser identity.UserID, targetUser identity.UserID`.

---

## `identity` — The Foundation Package

`internal/identity/` is the lowest-level application package. It defines
**what identities are** — ID types, format validators, domain primitives.

### Dependency Rule

`identity` imports only `errx` and external libraries (`uuid`). It **never**
imports anything from `internal/iam/`. Every domain and adapter package imports
`identity`. This makes it the foundation of the type system.

```
stdlib → errx → identity ─┐
                           ├→ every domain package → adapters
              query ───────┘
```

### Typed IDs: `ID[T any]`

All entity identifiers use `identity.ID[T]`, a generic struct wrapping
`uuid.UUID` with a phantom type tag for compile-time discrimination:

```go
type ID[T any] struct{ v uuid.UUID }

// 24 entity types, each with an unexported tag:
type environmentTag struct{}
type userTag        struct{}
// ...

// Public aliases — these are the types used everywhere:
type EnvironmentID  = ID[environmentTag]
type UserID         = ID[userTag]
// ...
```

**Why this design:**
- Compile-time safety: `UserID` and `OrganizationID` cannot be mixed.
- Zero runtime cost: phantom tags are `struct{}`, aliases avoid wrapper overhead.
- Unexported tags: external packages cannot construct arbitrary IDs — they must
  use `ParseXID()` or `NewXID()`.

**API per entity type** (24 sets):
- `NewUserID() UserID` — generate new UUID
- `ParseUserID(raw string) (UserID, error)` — validation boundary
- `MustParseUserID(raw string) UserID` — panics, for tests/static init

**Methods on `ID[T]`:**
- `String() string` — canonical lowercase UUID
- `IsZero() bool` — true for zero value (replaces `id == ""` checks)
- `UUID() uuid.UUID` — unwrap when needed
- `MarshalText() / UnmarshalText()` — JSON support
- `Value() / Scan()` — database/sql support (sqlx struct tags work directly)

**Where parsing happens:**
- HTTP handlers: `identity.ParseUserID(c.Params("id"))` at the boundary
- JWT codec: `mustParseX` helpers at sign/parse boundary
- Services receive typed IDs — no parsing needed

### Other `identity` Exports

| Function | Purpose |
|----------|---------|
| `Email(string) (string, error)` | Normalize + validate email |
| `ValidatePermissions([]string, prefix)` | Permission catalog validation |
| `ValidatePrefix(string)` | Resource prefix format |
| `ValidateRedirects([]string)` | Browser redirect URIs (OAuth redirect/post-logout, application): https, or http on loopback (`LoopbackHTTP`, RFC 8252); `oauth.Client.RedirectRegistered` matches IP-literal loopback on any port and `oauth.Warnings` flags them (`ClientView.Warnings`, `loopback_redirect`) |
| `ValidateHTTPS([]string)` | URLs kept https-only, no loopback exception (back-channel logout, SAML ACS) |
| `Subset(requested, catalog []string)` | Permission subset check |
| `ParseTTL(*string) (time.Duration, error)` | Credential TTL parsing |
| `ValidateMetadata`, `MetadataKey`, `SetMetadata`, `DeleteMetadata`, `MetadataValue` | User/organization metadata limits (64 keys, 4 KiB values, 32 KiB total) and per-key edits |
| `Username(string)`, `Login(string) (email, username, error)` | Normalize + validate a username (3–64 of `[a-z0-9._-]`, no `@`); split a sign-in identifier into email or username |

These are **pure validation functions**, not types. Email is a `string` because
there is only one kind of email — no discrimination problem to solve.

### Shared Domain Structs

`identity.User`, `identity.Membership`, `identity.Access` live in `identity`
because they cross module boundaries (authentication, federation, provisioning
all reference them).

---

## `errx` — The Error System

`internal/errx/` is the **only** error system. Every error in the application
is either an `*errx.Error` or gets wrapped into one before leaving a package.

### Error Types

| Type | HTTP Status | When to use |
|------|------------|-------------|
| `errx.Validation(msg)` | 400 | Bad input from client |
| `errx.Unauthorized(msg)` | 401 | Invalid credentials or token |
| `errx.Forbidden(msg)` | 403 | Valid identity, insufficient permissions |
| `errx.NotFound(msg)` | 404 | Entity does not exist |
| `errx.Conflict(msg)` | 409 | Unique constraint / state conflict |
| `errx.Business(msg)` | 422 | Domain rule violation |
| `errx.Internal(msg)` | 500 | System error (database, IO) |
| `errx.External(msg)` | 502 | Upstream service failure |
| `errx.Wrap(err, msg, type)` | varies | Wrap a cause with context |

### Rules

1. **Every package boundary wraps errors.** Repository methods wrap database
   errors: `errx.Wrap(err, "persistence failed", errx.TypeInternal)`. Services
   return `errx.Validation` for input errors, delegate persistence errors as-is.

2. **The HTTP error middleware** (`internal/server/errors.go`) converts
   `*errx.Error` to JSON responses. It **never** exposes wrapped causes or
   internal details to the client. 500s get a generic message.

3. **`identity` uses `errx`** for all parse/scan/unmarshal errors. This ensures
   a `ParseUserID` failure at the HTTP boundary produces a proper 400, not a
   bare `fmt.Errorf` that would become a 500.

4. **One field → one error message.** Never return "invalid request" for
   multiple fields. Validation errors name the specific field.

---

## `query` — Pagination Foundation Package

`internal/query/` owns the pagination types that appear in domain interfaces.
It is transport-agnostic — no HTTP or framework imports.

```go
package query

// Pagination holds limit/offset for paginated queries.
type Pagination struct {
    Limit  int
    Offset int
}

// Page carries pagination metadata in API responses — the effective
// limit/offset the server applied (after clamping) plus the total match count.
type Page struct {
    Total  int `json:"total"`
    Limit  int `json:"limit"`
    Offset int `json:"offset"`
}

// Paginated is the standard paginated response envelope.
type Paginated[T any] struct {
    Items []T  `json:"items"`
    Page  Page `json:"page"`
}
```

Wire format: `{"items": [...], "page": {"total": N, "limit": N, "offset": N}}`.
This is the one envelope shape for every paginated list endpoint — do not
invent a flatter or differently-named variant per module. The one exception
is the append-only event log (`GET …/events`), a keyset feed: `event.Page`
`{"items": [...], "next": <event id>}` pages by id (`after`/`before`), because
offsets shift as events arrive and a poller needs a stable cursor.

### Dependency Rule

`query` is a foundation package at the same level as `identity` and `errx`.
It imports nothing from `internal/`. Every domain package can import it freely
in `ports.go` without pulling in transport types.

### Paginated Returns Use DB-Level Pagination

List methods that support pagination return `(query.Paginated[T], error)` —
never bare `([]T, int, error)`. The bare `int` is ambiguous (total? page
number? items returned?) at every call site:

```go
// ✗ Bad — ambiguous int
RoleAssignments(ctx context.Context, environment identity.EnvironmentID,
    filter RoleAssignmentFilter, page query.Pagination) ([]RoleAssignmentView, int, error)

// ✓ Good — self-documenting, serializes to JSON directly
RoleAssignments(ctx context.Context, environment identity.EnvironmentID,
    filter RoleAssignmentFilter, page query.Pagination) (query.Paginated[RoleAssignmentView], error)
```

The repository does the pagination — `COUNT(*)` for `Page.Total`, then
`LIMIT`/`OFFSET` for the page of rows — and returns `query.Paginated[T]`
directly. It never loads the full table and slices in memory. The service
and handler pass `query.Paginated[T]` straight through without touching it:

```go
// repository — owns the SQL, assembles the envelope
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID,
    page query.Pagination) (query.Paginated[User], error) {
    var total int
    if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM users WHERE environment_id=$1`, environment); err != nil {
        return query.Paginated[User]{}, failure(err)
    }
    items := []User{}
    err := r.db.SelectContext(ctx, &items,
        `SELECT * FROM users WHERE environment_id=$1 ORDER BY name LIMIT $2 OFFSET $3`,
        environment, page.Limit, page.Offset)
    if err != nil {
        return query.Paginated[User]{}, failure(err)
    }
    return query.Paginated[User]{Items: items, Page: query.Page{Total: total, Limit: page.Limit, Offset: page.Offset}}, nil
}

// handler — no slicing, just forwards the envelope
func (h *Handler) List(c *fiber.Ctx) error {
    out, err := h.queries.List(c.UserContext(), env(c), httpx.PaginationFromCtx(c))
    if err != nil {
        return err
    }
    return c.JSON(out)
}
```

### Filters Stay in Domain Packages

Filter structs are entity-specific — they reference typed IDs, enums, and
field names. They live in the domain package alongside the entity they filter,
**not** in `query`:

```go
// authorization/filter.go — domain-specific, stays here
type RoleAssignmentFilter struct {
    ResourceID     *identity.ResourceID
    OrganizationID *identity.OrganizationID
    UserID         *identity.UserID
}
```

Moving filters to `query` would force it to import `identity` and know about
every domain, destroying its foundation status.

### `httpx` — HTTP Bridge Only

`httpx` keeps only the Fiber-specific helper that parses HTTP query params
into `query.Pagination`. It does **not** build the response envelope — the
repository already returns `query.Paginated[T]` ready to serialize:

```go
// httpx/paginate.go
func PaginationFromCtx(c *fiber.Ctx) query.Pagination { ... }
```

This is the only package that imports both Fiber and `query`. Domain packages
and services never import `httpx`.

---

## Domain Validation Pattern

### `Validate() error` on Domain Structs

Every create/update input struct gets a `Validate() error` method in its
domain file (not in the service):

```go
// application.go
func (c Create) Validate() error {
    if strings.TrimSpace(c.Name) == "" {
        return errx.Validation("application name is required")
    }
    return nil
}
```

Rules:
- Value receiver (no mutation).
- Only validates structural invariants the struct owns (non-empty, format).
- Cross-entity checks (permissions ⊆ catalog, prefix enforcement) stay in services.
- `Update` structs with `*T` fields validate only non-nil fields.
- ID fields are typed (`identity.XID`) so they don't need UUID format validation.

### Where Validation Happens

| Layer | Validates |
|-------|-----------|
| HTTP handler | Parses path/query params via `identity.ParseXID()` |
| Domain struct | `input.Validate()` — field format, required fields |
| Service | Cross-entity rules, business invariants |
| Repository | Nothing — trusts the service layer |

---

## HTTP Adapter Pattern

Every `<mod>http/handler.go` follows the same structure:

```go
type Handler struct {
    commands module.Commands
    queries  module.Queries
    actor    func(*fiber.Ctx) string
}

// env parses the environment path parameter (every handler has this).
func env(c *fiber.Ctx) identity.EnvironmentID {
    id, _ := identity.ParseEnvironmentID(c.Params("environment"))
    return id
}
```

- Parse IDs at the boundary: `identity.ParseXID(c.Params("id"))`
- Pass `c.UserContext()` to services, never `c.Context()` (the fasthttp
  request context): `server.observe` stores the request id and trace span
  there, so queries, outbound calls and log lines join the request's trace
- Return `errx.Validation` / `errx.NotFound` on parse failure
- Delegate to service — never contain business logic
- JSON binding via `c.BodyParser(&input)`
- The OpenAPI document is derived from handler source (`internal/openapigen`):
  answer with `c.JSON(typed value)`, `c.Status(code).JSON(…)` or
  `c.SendStatus(code)` with constant statuses, read query parameters with
  `c.Query`/`httpx.PaginationFromCtx`, and bind bodies with `BodyParser` into a
  typed struct, so the generator sees them. A handler reached through a
  function-typed field set in bootstrap needs an entry in
  `openapigen.Bindings`. After a route or response change run `make openapi`;
  the e2e harness (`App.Test`, `tests/e2e/openapi_contract_test.go`)
  validates every exchange against the document

---

## PostgreSQL Adapter Pattern

Every `<mod>pg/repository.go`:

```go
type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

// Package-level error wrappers
func failure(err error) error { /* wraps with errx.TypeInternal */ }
func conflict(err error) error { /* detects pq constraint violations → errx.Conflict */ }
```

- Scan structs use typed ID fields directly (`identity.UserID` with `db:"id"`)
  because `ID[T]` implements `sql.Scanner`.
- Query parameters use typed IDs directly because `ID[T]` implements
  `driver.Valuer`.
- `var _ module.Repository = (*Repository)(nil)` — compile-time interface check.

---

## Authentication & JWT

Two separate authentication systems exist:

| System | Audience | Transport | Package |
|--------|----------|-----------|---------|
| Application auth | End users | JWT (RS256) | `authentication/`, `apiauth/` |
| Management auth | Operators | Secret-hash / session cookie | `management/` |

**JWT claims use strings** (wire format). Conversion to/from typed IDs happens
at the `Sign`/`parse` boundary in `authjwt/codec.go`:

```go
// Sign: typed ID → string
claims.SessionID = issued.Session.String()

// Parse: string → typed ID
session, err := identity.ParseSessionID(claims.SessionID)
```

**`apiauth` middleware** (`internal/server/apiauth/`) validates JWTs and
stores the token on the Fiber context; `apiauth.Environment(c)` returns its
typed environment. `apiauth.Scope` compares that environment with the
`:environment` path parameter and must sit on the group that binds it
(`/environments/:environment`) — on `/api/v1` the parameter is still empty.
Route families that share a path prefix with another family use `guarded`
(per-route checks), not a prefix group, so one family's permission check never
runs for another's routes (`tests/e2e/scoped_api_test.go`).

**`amr`** (authentication methods) is stored on `sessions.amr`, copied onto
every access token issued for the session (including refreshes) and onto OIDC
ID tokens via `oauth.Authorization.Session` → `oauth.SessionInfo`. First
factors: `pwd`, `email`, `fed` (`authentication.MethodAMR`); a second factor
appends `mfa.AMR(proof)` = `otp` + `mfa` (TOTP, email code), `sms` + `mfa`,
`hwk` + `mfa` (security key, `authentication.Proof.WebAuthn()`), or `mfa`
(recovery); a passkey first factor is `hwk` + `user` + `mfa`. WebAuthn
factors keep their `mfa.Credential` JSON in `user_factors.data` with
`credential_id` unique per environment; a signature counter that goes
backwards refuses the assertion and audits `mfa.clone_detected`. Email/SMS factors store a hashed 6-digit code on
`user_factors` (`config.FactorCodeTTL`, `FactorCodeCooldown`,
`FactorCodesPerHour`); `mfa.Policy.Usable` never offers the email factor after
an email-code first factor. Headless second-factor logins park
as `mfa_logins` rows keyed by the hash of an `ik_mfa_` token (5 min, 5
attempts); no session exists until verification. Wrong codes also count per
user across every factor and path (`user_mfa_state.failed_attempts`, so
switching factor does not reset it): every
`config.MFAFailures` in a row lock it for `mfa.Lockout` (15 min doubling,
24 h max, 429 `MFA_LOCKED` via `errx.TooManyRequests`, audited `mfa.locked`); callers commit the
transaction on a wrong code so the count sticks. Unconfirmed factors expire
for confirmation after `config.MFAEnrollTTL` (`Factor.Enrollable`). `SecondFactor.Complete`
runs the session-issuing callback before committing, so a failed session
never loses recovery codes. Tokens carry `auth_time`
(`sessions.authenticated_at`, written by `CreateSession` from the same
second as the first token and kept across refreshes); the self-service
`/identity/v1/me/factors*` routes (`mfahttp.RegisterSelf`) refuse
impersonated tokens and require a sign-in within `config.MFAFreshAuth` for
changes (`mfa.Fresh`, 403 `REAUTHENTICATION_REQUIRED`).

**End-user passwords** follow the environment's `authentication.PasswordPolicy`
(`Check` for new passwords → 400 `PASSWORD_POLICY`, `errx.Error.Public` details
`rule`/`min_length`; only `Public` details reach clients). Every wrong password
increments `users.failed_logins` (committed before the uniform 401); reaching
`lockout_threshold` sets `locked_until` via `authentication.Lockout` (the
helper `mfa.Lockout` wraps) and audits `user.locked`; a locked account answers
the same 401 and counts nothing. `user.Commands.Unlock` / a reset clears it.
`password_changed_at` older than `max_age_days`: headless `Login` answers 403
`PASSWORD_CHANGE_REQUIRED` until it gets `new_password`, whose hash waits on
`mfa_logins.password_hash` when a second factor follows; hosted parks
`hosted_logins.password_change` and asks last, after MFA. Email-code logins
skip expiry. Expiry uses the member's effective policy (`Service.memberPolicy`:
the shortest `max_age_days` of the environment and their organizations);
existing passwords are never re-checked for composition.

Operator console sessions store their sign-in `method` (`password`/`sso`)
and `authenticated_at` on `operator_sessions`; `management.Principal`
carries them (`Method` = `key` for management keys). `SetPassword` needs
the current password, a key, or a sign-in within `config.OperatorFreshAuth`
when no password is set (or from an SSO session), and revokes every other
session of the operator in the same transaction. A password someone else
chose (`SetTemporaryPassword`, used for `IAMKIT_BOOTSTRAP_PASSWORD`) sets
`operators.password_must_change`: `Login` answers `PASSWORD_CHANGE_REQUIRED`
until it receives `new_password`.

---

## Mutation & Audit Trail

Modules that support audited mutations define a `Mutation` struct:

```go
type Mutation struct {
    Environment identity.EnvironmentID
    Actor       string
    Action      string
    Target      string
}
```

Repository methods accept `Mutation` and insert into `audit_events` within the
same transaction as the data change — through `eventpg.Audit`, which also
writes the classified semantic event. Writes without a `Mutation` (creates,
memberships, SCIM) call `eventpg.Record`/`Emit` in their transaction instead. The HTTP handler constructs `Mutation`
from the authenticated context. Exception: when one command can emit several
actions, the service sets `Action` itself (e.g. `mfasvc` writes `mfa.enrolled`,
`mfa.removed`, `mfa.recovery_regenerated`, `mfa.recovery_used`, `mfa.reset`,
`mfa.locked`, `mfa.clone_detected`).

---

## External Dependencies

| Dependency | Purpose | Import boundary |
|-----------|---------|-----------------|
| `github.com/gofiber/fiber/v2` | HTTP framework | `*http/` adapters + `server/` only |
| `github.com/jmoiron/sqlx` | SQL extensions | `*pg/` adapters + `bootstrap/` only |
| `github.com/lib/pq` | PostgreSQL driver | `*pg/` adapters + `server/errors.go` |
| `github.com/google/uuid` | UUID generation | `identity/` only |
| `github.com/golang-jwt/jwt/v5` | JWT signing/parsing | `authjwt/` only |
| `github.com/ory/fosite` | OAuth2 server | `oauthfosite/` only |
| `github.com/coreos/go-oidc/v3` | OIDC discovery | `fedoidc/` only |
| `github.com/crewjam/saml` | SAML 2.0 service provider and identity provider (and the test IdP/SP) | `fedsaml/`, `samlxml/` only |
| `github.com/go-ldap/ldap/v3` | LDAP client (and the test directory's filter parsing) | `fedldap/` only |
| `github.com/jimlambrt/gldap` | In-process LDAP server for tests | `fedldap/ldaptest/` only |
| `rsc.io/qr` | Enrollment QR code (PNG data URI) | `hostedhttp/` only |
| `github.com/go-webauthn/webauthn` | WebAuthn ceremonies (security keys, passkeys) | `mfawebauthn/` only |
| `github.com/santhosh-tekuri/jsonschema/v6` | User profile schema compilation and validation | `userschema/` only |
| `github.com/getkin/kin-openapi`, `golang.org/x/tools/go/packages` | OpenAPI contract validation (tests) and handler source loading for the generator | `tests/e2e/`, `openapigen/` only |
| `go.opentelemetry.io/otel` (+ sdk, OTLP/HTTP and Prometheus exporters, `otelhttp`), `github.com/XSAM/otelsql` | Tracing and metrics; no-op until `OTEL_*` / `IAMKIT_METRICS_ADDR` | `telemetry/`, `server/`, `bootstrap.OpenDatabase` (otelsql). Adapters record through `telemetry` helpers only (`authpg`/`mfapg` count sign-ins and MFA failures after commit, `authpg` deliveries, `oauthpg` logout deliveries) and wrap outbound clients in `telemetry.Transport`; domain packages and services never import it (`architecture_test.go`) |

| `github.com/redis/go-redis/v9` | Optional shared cache, counters and rate-limit storage (`REDIS_URL`) | `cache/cacheredis/` only |

**Rule:** Domain packages and services never import framework types. They
depend only on `identity`, `query`, `errx`, `cache`, and stdlib.

---

## What NOT to Change

- **Don't add a `Validate()` to repository/adapter code** — they don't validate.
- **Don't move validation helpers** (`Email`, `ValidatePermissions`, etc.) out
  of `identity` — they are shared primitives.
- **Don't make email a type** — there's only one kind of email, no discrimination
  problem. `identity.Email()` is a parse function that returns a clean `string`.
- **Don't rename `identity` to `kernel`/`core`/`base`** — Go names packages
  after content, not architectural role. `identity.UserID` reads correctly;
  `kernel.UserID` does not.
- **Don't import domain packages into `identity`** — it must remain the
  dependency graph leaf.
- **Don't use `fmt.Errorf` for application errors** — always use `errx`. The
  HTTP error middleware only understands `*errx.Error`.
- **Don't merge Commands and Queries into one interface** — they serve different
  consumers and may diverge (e.g. queries could be served from a read replica).
- **Don't let Repository generate IDs** — ID generation is a service
  responsibility. The repository receives the ID and persists it.
- **Don't put filter structs in `query`** — filters are domain-specific (they
  reference typed IDs and entity fields). `query` only owns `Pagination`,
  `Page`, and `Paginated[T]`.
- **Don't return bare `([]T, int, error)` for paginated queries** — use
  `(query.Paginated[T], error)`. The int is ambiguous at every call site.
- **Don't put pagination types in `httpx`** — `httpx` imports Fiber, so
  `ports.go` would need a framework import. Pagination types live in `query`;
  `httpx` only converts a `*fiber.Ctx` into `query.Pagination`.
- **Don't flatten the `page` envelope to a bare `total` field** — the wire
  format is `{"items": [...], "page": {"total", "limit", "offset"}}`. It's
  documented in the SDK reference and consumed by the frontend; don't change
  it while relocating the Go types.
- **Don't paginate by loading the full table and slicing in memory** — every
  paginated repository method runs `COUNT(*)` for `Page.Total` and
  `LIMIT`/`OFFSET` for the page of rows. In-memory slicing doesn't scale and
  makes `Page.Total` wrong once a repository cap is hit.
