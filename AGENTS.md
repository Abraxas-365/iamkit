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
clients/react/           @iamkit/react — headless SignInFlow, hooks, unstyled <SignInForm>/<AcceptInvitation> and account widgets (<UserProfile>/<UserSecurity>/<UserSessions>/<ApiKeys>/<OrganizationSwitcher> + hooks on @iamkit/js createAccount, optional widgets.css)
clients/node/            @iamkit/node — server-side SDK mirroring sdk/ (jose token verification, Connect middleware, OAuthClient, KeyLogin, webhook/action verification, re-exports @iamkit/api)
clients/python/          iamkit (Python ≥3.10, uv/hatchling) — server-side SDK mirroring @iamkit/node: JwtVerifier/IntrospectionVerifier, OAuthClient, KeyLogin, webhook/action verification, APIKeyValidator, IAMKit/AsyncIAMKit management client (`_aresources.py` is generated from `_resources.py` by `scripts/unasync.py`), FastAPI/Flask/Django integrations; tests/contract runs only with IAMKIT_CONTRACT_URL
examples/nextjs-login/   Next.js custom sign-in app + Playwright parity journeys (e2e/run.sh)
examples/mcp-server/     Remote MCP server (Streamable HTTP, @modelcontextprotocol/sdk) protected by @iamkit/node/resource-server; seeded TLS stack for MCP Inspector / Claude Code
sdk/                     Go client SDKs, own go.mod (github.com/Abraxas-365/iamkit/sdk; the server never imports it — TestLayerDependencies); sdk/resourceserver verifies tokens for RFC 9728 resource servers, its testdata/canonical.json is shared with oauth.CanonicalResource and @iamkit/node/resource-server
deploy/compose/          Production Compose (traefik/, caddy/: TLS proxy + IAMKit + PostgreSQL, profiles redis/otel/geoip); setup.sh writes .env + secrets, smoke.sh checks a variant
deploy/helm/iamkit/      Helm chart (migrations as a pre-install/pre-upgrade hook Job, probes on /health, HPA/PDB/ServiceMonitor, optional `geoip` updater sidecar + `geoip.header`); ct.yaml + ci/ for chart-testing on kind (.github/workflows/deploy.yml), pushed to GHCR OCI by release.yml
internal/
  bootstrap/             Composition root — only place concrete types are wired
  config/                Constants (TTLs, limits)
  blob/                  Object storage port (Store: Put never overwrites → Conflict, Get, Stat, Delete; Opener, Target, ValidateKey); adapter blob/adapters/gocloudblob (gocloud.dev/blob: S3 + memblob), only logstreammodule/bootstrap import it (architecture test)
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
| action | `internal/iam/action` | Actions: synchronous hooks to operator endpoints (`action_targets` ≤ `action.MaxTargets` per environment, secret `whsec_` sealed with `action.Cipher` + `previous_sealed` for `config.EventWebhookSecretOverlap`; `action_executions(condition, target_ids uuid[])` ≤ `MaxExecutionTargets`; `action_calls` log pruned after `config.ActionCallRetention` by the `action_call_prune` job). `action.Conditions` is the curated catalog (`function:pre_sign_in`/`pre_registration`/`post_federation`/`pre_access_token`/`pre_id_token`/`pre_userinfo`, `request:user.create`/`user.update`/`membership.create`) with what each accepts (deny, claims, patch fields). `actionsvc.Service.Run` (exposed as `actionmodule.Module.Runner`) calls bound targets in order: `call` applies the answer (`Response.Check`: reserved claims `action.ReservedClaims`, ≤ `config.ActionMaxClaims`), `webhook` needs a 2xx, `async` is detached; deny → 403 `ACTION_DENIED`, a failure of an `interrupt_on_error` target → 502 `ACTION_FAILED`, other failures drop that target's changes; per-target in-memory `action.Breaker` (`config.ActionBreakerFailures` → skip `ActionBreakerOpen`); feature `actions` off skips everything. `actionhook.Caller` signs per Standard Webhooks, dials through `netx.GuardedDialer` (tests: `bootstrap.WithActionTransport`), caps bodies at `config.ActionMaxResponse`, follows no redirects. `actionpg` writes through `eventpg` (`action.failed`, `action_target.*`, `action_execution.*`). Consumers declare one-method `Actions` ports (authentication: `NewSession` → pre_sign_in, `CompleteSignup` → pre_registration; federation: `fedsvc.account` → post_federation, pre_registration only when no user has the email (`Repository.HasUser`); user/organization: request hooks; oauth: `oauthhttp` `tokenHooks` in `finish`/device, `accessHook` on refresh, `userInfoHook`), set via `SetActions`/`Deps.Actions` in bootstrap. Identity-API JWTs are never changed. `actionhttp` at `…/action-*` (management only); receivers use `sdk/action` |
| apikey | `internal/iam/apikey` | Self-service API keys, one credential (`api_keys`, `ik_key_` = `identity.APIKeyPrefix`, SHA-256 `secret_hash`, `last4`, shown once) for three owners (`apikey.OwnerKind`): `user` (a person's key in one organization, capped by their live roles), `organization` (outlives its creator; capped by the organization's reach) and `machine` (a machine user's key, operator-made; the only kind IAMKit's own API accepts and the only one exchangeable for a JWT; `permissions` NULL = everything the user holds). Effective permissions are computed in SQL by `api_key_permissions(owner_kind, permissions, env, org, user, resource)` (key list ∩ the resource's allowlist `resources.api_key_user_permissions`/`api_key_organization_permissions` for the kind ∩ the owner's reach `api_key_reach`), used by creation checks (`Repository.Reach`) and by `authpg` resolution, so a key never acts wider than it was created. `apikeysvc.Service` (Commands + Queries): `Scope` (`EnvironmentScope` operators, `OrganizationScope` org admins, `SelfScope` users; `Scope.Narrow` pins every List/Find/Revoke filter in SQL), policy `api_key_policies` (`user_keys`/`organization_keys` off by default → 403 `API_KEYS_DISABLED`; machine keys ignore it; `max_ttl_days` via `Policy.CheckTTL`; `max_per_user`/`max_per_organization` live-key limits enforced in `apikeypg.Create` under a lock on the organization row → 422 `API_KEY_LIMIT_REACHED`), owner rules (users create only their own key, resource linked to the session's application, fresh sign-in `apikey.FreshAuth` → 403 `REAUTHENTICATION_REQUIRED`; org admins need an account — a `Granter` — and also `api_key_reach` of that admin; operators create organization and machine keys), `Created by` = `created_by_kind/id`. Audited `api_key.create`/`api_key.revoke`/`api_key_policy.update` through `eventpg.AuditSubject` (events `api_key.created`/`.revoked`/`api_key_policy.updated`; user/org keys target `/organizations/<org>/api-keys/<id>` so `…/admin/events` sees them); revoking a machine key also revokes its `sessions.api_key_id` sessions. Triggers end user and machine keys when the membership ends (`api_key.revoked`, `data.reason` `membership_ended`, actor `system`). `apikeyhttp`: operator `…/api-keys[/:key]`, `…/api-key-policy`, `…/users/:id/api-keys` (management; `/api/v1` with `iam:api-keys:read`/`write` and `iam:users:*`), `PUT …/resources/:resource/api-key-permissions` (authorization module; never on the IAM resource), self-service `Self` at `/identity/v1/me/api-keys[/options]` (application tokens of people only; impersonated tokens read-only; rate limited like other `/me` routes), org-admin `…/admin/api-keys[/options]` (`iam:org:api-keys:read`/`write`; setup-link principals and zero-user callers → 403) composed by `orgadminsvc`. Resolution: `authpg/apikey.go` resolves any `ik_key_` by hash in one query (live owner/membership/organization/policy/application/resource) and `authsvc` `Validate`/`ValidateSelf`/`ValidateAPIKey` branch on the prefix: `Purpose` `api_key`, `Token.APIKey` (`APIKeyClaims{id,name,owner{type,id,organization_id},resource_id,permissions,expires_at}`), `Subject` = the user (zero for organization keys), `Audience` = the key's resource audience (a different requested audience → inactive), `ExpiresAt` 0 for keys that never expire; `last_used_at` is written at most every `config.APIKeyUsedInterval`, `users.last_signed_in_at` for machine keys only. `apiauth` accepts `ik_key_` for machine keys only (user/organization keys → 401 "API keys of users and organizations cannot call the IAMKit API"); `ExchangeAPIKey` (`POST /identity/v1/token-exchange`) is machine keys only on one reused `sessions.api_key_id` session; `/identity/v1/me/*` and `/oauth/userinfo` refuse API keys |
| application | `internal/iam/application` | OAuth/OIDC application registration; `application.Filter.Resource` (`GET …/applications?resource_id=`) keeps the applications linked to a resource (`application_resources`) |
| auditlog | `internal/iam/auditlog` | App audit log: events the environment's applications emit about their users, per organization (`audit_log_events`, immutable by trigger; not IAMKit's `events`, which they never enter). `Action` catalog (`audit_log_actions`, ≤ `MaxActions`; `target_types`, `Schema{Metadata, Actor, Targets[type]}` checked by the module's own `SchemaValidator` port — the module wires `userschema.Validator`, the domain never imports it; `Version` bumps when `ActionUpdate.Apply` reports changed rules); action changes go through `eventpg.Audit` (`audit_log_action.*`). `Input.Validate` (limits, `occurred_at` ≤ now+`config.AuditLogFutureSkew` and ≥ now−retention, scalar metadata), `Input.Hash` = SHA-256 of the canonical request. `auditlogsvc.Events.Emit`: idempotency replay first (`Idempotency-Key`, unique `(environment_id, idempotency_key)`; same hash → original receipt, other → 409 `IDEMPOTENCY_KEY_REUSED`; no TTL: a key lives until its event is pruned), `Usage{Admit, Count}` (`LimitAuditEvents` 429, `MetricAuditEvents`), unknown action → 422 `UNKNOWN_AUDIT_ACTION`, version, target types, schemas, organization. `Page{Items, Next}` keyset on `seq` like `event.Page`; `EventQueries.List`/`Export` take `Filter.Organization` (org admin reads). `auditloghttp` at `…/audit-logs/events` (emit, list, `export?format=ndjson|csv` before `/:id`, get) and `…/audit-logs/actions` (management; `/api/v1` read/write for events, read/manage for actions: `iam:audit-logs:*`); body > `config.AuditLogMaxBody` → 413. `Commands.Prune` is the `audit_log_prune` job (`IAMKIT_AUDIT_LOG_RETENTION`, `bootstrap.WithAuditLogRetention`, default `config.AuditLogRetention`), one transaction with `iamkit.audit_log_prune = 'on'` |
| authentication | `internal/iam/authentication` | Password login, sessions, refresh tokens, challenges; self-service sessions `GET`/`DELETE /identity/v1/me/sessions[/:id]` + `POST …/revoke-others` (`authsvc.Tokens.Sessions`/`RevokeSession`/`RevokeOtherSessions`, `authpg/sessions.go`; root sessions only, impersonated tokens read-only). `sessions.ip_address`/`user_agent` (migration 006) come from `identity.ClientInfo` in the request context, set app-wide by `server.clientInfo` (`c.IP()`, so `Server.TrustedProxies` applies) and read by every `INSERT INTO sessions` Stale-hash rehash: when `Passwords.Compare` reports `stale`, `authsvc.Login` (not when the sign-in sets a new password anyway) and `Authenticator.VerifyPassword` call `Transaction.RehashPassword` in the locked sign-in transaction — `UPDATE … WHERE password_hash = old` under a savepoint with transaction-local `iamkit.password_rehash = 'on'`, which migration 009 lets the `user_changed`/`challenges_changed` triggers honour for a `password_hash`-only change (sessions and challenges survive; any other change still fires them). It leaves `password_changed_at`, lockout and events alone, a failure is logged and the sign-in continues, and `telemetry.PasswordRehash` counts it after commit. Sign-up waitlist (migration 015, opt-in `sign_in_policies.waitlist` + `waitlist_auto_approve_domains` + `waitlist_signup_url` — `SignInPolicy.Waitlist`/`WaitlistSignupURL` are pointers and a nil domain list keeps too, so omitted on PUT = keep, read through `WaitlistOn()`/`WaitlistURL()`; `waitlist_entries` pending→approved→completed or rejected, one live entry per email until an operator deletes it, an approval that expired unused returns to pending on a new join, a full list is logged; `CompleteSignup` refuses a sign-up without an entry once the waitlist is on): `authsvc.Signup` gates only password/email-code sign-up — federation `signup`, invitations, SCIM and operator-created users bypass it — and answers `SignupResult{Challenge, Status}` (`code_sent`\|`waitlisted`, same 202 for new entry, existing entry, existing account and a full list); an unapproved address `SignupTransaction.JoinWaitlist`s and gets `waitlist_joined` via `deliverLater` (new entries only) and no code; a valid `ik_wait_` token (`SignupTransaction.WaitlistToken` by hash: approved, unexpired, email matches) runs the normal verified sign-up, `signups.waitlist_entry_id` carries it and `SignupTransaction.Join` marks the entry `completed` in the same transaction. `authsvc.Waitlists` (`WaitlistCommands`/`WaitlistQueries`/`WaitlistRepository`): approve issues the token (`config.WaitlistApprovalTTL`) and emails `waitlist_approved` with `?waitlist=<token>`, reject emails `waitlist_rejected` only with `notify`, bulk approve ≤ `config.WaitlistMaxApprove`; events `waitlist.joined` (actor `system`, `data.email_domain` only), `.approved`/`.rejected`/`.deleted` (operator), `.completed`; `authhttp.WaitlistHandler` at `…/waitlist` (management, `/api/v1` `iam:waitlist:read`/`write`); hosted sign-up shows a waitlisted page and `?waitlist=<token>` prefills the email through `hosted.Flow.WaitlistEmail`; operator surfaces: console `frontend/src/pages/waitlist.tsx` (+ the waitlist fields of `sign-in-policy.tsx`), CLI `iam waitlist` (`cmd/iam/internal/cli/waitlist.go`), `iamclient`/`apiclient` waitlist methods in `sdk/`, `waitlist` resources in `@iamkit/node` and `iamkit` (Python), `signup()` `status` + `waitlistToken` in `@iamkit/js`/`@iamkit/react`; guide `docs/guides/sign-in/waitlist.md`. Phase-8 hardening: `waitlist_signup_url`'s origin (`authentication.URLOrigin`) must be the issuer's (`SignInPolicies.SetIssuer`, passed from `authmodule` `Deps.Issuer`) or in `allowed_origins` of an active OAuth client of an active application of the environment (`SignInPolicyRepository.SignupOriginAllowed`; else 422 on `SetSignInPolicy`, checked only when the URL is set or changed so a stored page never blocks other edits), re-checked on every approval (`Waitlists.linkBase`: a lost origin, or no `signIns` wired, sends the token without link + warning); worker job `waitlist_prune` (`authmodule.Module.Jobs`, hourly, batches of `config.WaitlistPruneBatch`, `FOR UPDATE SKIP LOCKED` + status re-checked on the outer DELETE, partial index `waitlist_entries_prune` from migration 017) deletes `completed`/`rejected` entries older than `IAMKIT_WAITLIST_RETENTION` (`bootstrap.WithWaitlistRetention`, default `config.WaitlistRetention`, ≥ 24h) by `COALESCE(decided_at, created_at)`, never pending/approved, no events; `Signup` answers no sooner than `config.SignupAnswerFloor` (`Service.SetSignupFloor`; the clock restarts after the password hash, which may outlast the floor; errors immediate, ctx cancel ends the wait) so timing does not tell new from existing |
| authorization | `internal/iam/authorization` | Resources, roles, grants, role assignments, group role assignments; resource ownership and grants to organizations (`resources.owner_organization_id`/`require_grant`, `resource_grants`): with `require_grant` the `effective_grants` view keeps only the owner and granted organizations (granted roles only, `role_ids` NULL = all); narrowing, revoking or changing access ends the affected sessions in the same transaction (`authzpg` `endUngranted`/`endOrganization`); the IAM resource is never owned or granted |
| event | `internal/iam/event` | Typed event log / outbox (`events`): `Event{ID, Type, Actor, Subject, Organization, Data}`, catalog `<subject>.<verb>` (`catalog.go`), `Classify(action, target)` derives type/subject/data from a `Mutation`'s audit strings. Writers never go through a service: every `*pg` adapter calls the shared SQL package `eventpg` (documented exception like `authpg.Resolve`, enforced by `architecture_test.go`) inside its own transaction — `Audit`/`AuditWith` (audit row + classified event; `AuditSubject` also names the subject of create routes, whose target is only the collection), `Emit` (explicit actor), `Record` (actor = `event.ActorFrom(ctx)`, set by `mgmthttp`/`apiauth` via `event.WithActor`), `UserCreated`/`Membership` helpers and `Tx`. Triggers write `session.created`/`session.revoked`; `event_actor()` resolves `actor_kind` (`operator`, `user`, `machine` = a machine user, `service_account`, `directory` = SCIM credential, `setup_link` = an organization setup link's session, `system`). Reads: `Queries.List` (keyset by id: `after` oldest first — a feed cursor, else newest first below `before`; `event.Page{Items, Next}`, not `query.Paginated`), served by `eventhttp` at `…/environments/:environment/events` (management) and `/api/v1` (`iam:events:read`). Change history (no event sourcing): `AFTER UPDATE` trigger `record_changes` on users, organizations, applications, oauth_clients, roles and resources diffs the row (`jsonb` object columns per key; hashes, secrets and bookkeeping columns hidden) into the transaction-local setting `iamkit.changes` (≤ 100 rows per transaction), and `BEFORE INSERT` trigger `event_changes` moves the subject's entry into `data.changes` `{field: [old, new]}` — writers change nothing. `eventhttp.Histories` maps collections to subject kinds: `GET …/<collection>/:id/history` (`Filter.SubjectKind` + `Subject`, newest first; `/api/v1` also needs the collection's read permission) and `GET …/events/export` (`Queries.Export`, NDJSON oldest first in `event.ExportBatch` reads, streamed with a request-detached context). `Commands.Prune` is the `event_prune` worker job (`eventmodule.Module.Jobs`), retention `IAMKIT_EVENT_RETENTION` (`bootstrap.WithEventRetention`, default `config.EventRetention`). Webhooks: `event_subscriptions` (≤ `event.MaxSubscriptions` per environment, `types` exact or `family.*`, empty = all; secret `whsec_` sealed with `event.Cipher` → 422 `ENCRYPTION_KEY_REQUIRED` without a key, `previous_sealed` signs too until `previous_expires_at`, `config.EventWebhookSecretOverlap`) and the `event_deliveries` outbox filled by trigger `queue_event_deliveries` in the event's transaction (active subscriptions and those disabled for failing — so re-enabling resumes; an operator's disable stops queuing; `event_id` is not an FK: pruned events deliver as `failed`). `SubscriptionCommands`/`SubscriptionQueries`/`SubscriptionRepository` + `Sender`/`Secrets`/`Dispatcher` ports, `eventsvc.Subscriptions`; `eventhttp.Subscriptions` at `…/webhooks` (management, and `/api/v1` with `iam:webhooks:read`/`write`). Delivery is one in-flight row per subscription, in id order (`ClaimDeliveries`: each active subscription's oldest pending row, leased with `FOR UPDATE SKIP LOCKED`; a round that finished a head reports `more`, so a backlog drains at once); `event.DeliveryRetryAfter` backs off from `first_attempt_at` within `config.EventWebhookRetryWindow`, then `failed` and the next row proceeds; `event_webhook_maintenance` disables subscriptions failing for `config.EventWebhookDisableAfter` (`eventpg.System`: event only, actor `system` — `audit_events.actor_id` is a uuid) and prunes deliveries. `eventhook.Sender` signs per Standard Webhooks (key = base64 part of the secret, one `v1,` per live secret), truncates `data` past `config.EventWebhookMaxPayload`, dials through `netx.GuardedDialer`; tests and `IAMKIT_ALLOW_PRIVATE_DELIVERY` replace it via `bootstrap.WithWebhookTransport`; tests call `Server.WebhookDispatcher`. Receivers verify with `sdk/webhook` |
| logstream | `internal/iam/logstream` | Log streams: `log_streams` (≤ `logstream.MaxStreams` per environment, `MaxOrganizationStreams` per organization; destination `datadog`/`splunk`/`s3`/`https`, `Config.Validate(destination)` per destination, secret sealed with `logstream.Cipher` → 422 `ENCRYPTION_KEY_REQUIRED`, never returned; https secrets are generated `whsec_` with `previous_sealed` overlapping `config.EventWebhookSecretOverlap`). Sources: organization streams are exactly `{audit_logs}`, environment streams `events` and/or `audit_logs`. Triggers `queue_log_stream_events`/`queue_log_stream_audit` fill `log_stream_deliveries`; `logstreampg.ClaimBatches` leases each active stream's oldest pending rows as one batch (`FOR UPDATE SKIP LOCKED`, ≤ `config.LogStreamBatchSize` rows / `LogStreamBatchBytes`, `batch` = first row id and kept on retry), `logstreamsvc` sends through a per-destination `Sender` (adapters `lsdatadog`, `lssplunk`, `lshttps` Standard Webhooks, `lss3` gzip NDJSON via `blob.Store`, Conflict = delivered) with `config.LogStreamTimeout`, `event.DeliveryRetryAfter` backoff then `failed`; jobs `log_stream_delivery` and `log_stream_maintenance` (disable after `config.EventWebhookDisableAfter` via `eventpg.System`, prune after `config.LogStreamDeliveryRetention`). Org-scoped Commands/Queries take `logstream.Scope` (organization filter in every SQL query). `logstreamhttp` at `…/log-streams` (management, `/api/v1` `iam:audit-logs:read`/`manage`); transport `bootstrap.WithLogStreamTransport` (also unguarded by `IAMKIT_ALLOW_PRIVATE_DELIVERY`), tests call `Server.LogStreamDispatcher` |
| feature | `internal/iam/feature` | IAMKit's own feature flags (not a flag service for applications). The registry is `config.Flags` (`config.Flag{Name, Default, Scope, Description}`, scope `deployment` or `environment`); deployment values come from `IAMKIT_FEATURES` (`feature.ParseDeployment`, unknown names logged and ignored, `bootstrap.WithFeatures`); environment-scoped flags are overridden in `environment_features` (rows of removed flags ignored). `feature.Resolve`: override › deployment › default. `Queries.Enabled` is the port features consult (`hosted.Features`: `beta_languages` off narrows an environment without listed languages to `i18n.Stable()` + its chosen default in `hostedsvc.Branded`, which emails and SMS also read through `authentication.Brand.Languages`); deployment-only flags are read in bootstrap (`saml_idp` off leaves `Server.SAML` nil). `featurehttp` at `…/features` (unknown → 404 `UNKNOWN_FEATURE`, deployment-scoped PUT → 400), audited `feature.updated`/`feature.reset` |
| federation | `internal/iam/federation` | External identity provider connections (OIDC, presets Google/Microsoft/GitHub/GitHub Enterprise/GitLab/Apple, generic OAuth 2.0 with a claim mapping, SAML 2.0 and LDAP/AD for organizations), linking by email, profile refresh, IdP group mapping (`federation_group_mappings`: `Connection.GroupMappings` ≤ `MaxGroupMappings`, organization connections only, targets operator-managed non-SCIM groups of the organization — `fedsvc.check` → `Repository.MissingOperatorGroups`; `Claims.Groups` is read per provider (OIDC `options.groups_claim` default `groups`, SAML `attributes.groups` default `groups`/`memberOf`/Microsoft groups claim, LDAP `attributes.groups` default `memberOf`, OAuth 2.0 `claims.groups`) and cleaned by `federation.CleanGroups`; `fedpg.LinkedUser` runs `syncGroups` in its transaction at every sign-in, mapped groups only, emitting `group.members_changed` with source `sso`). SAML drafts: `federation_connections.draft` (migration 016; `CreateConnection.Draft` → inactive, no metadata, issuer/client = the SP entity ID; `Connection.Validate` allows drafts for SAML only; Update works while `active OR draft`, `Enable` of a draft needs metadata, prepares it and clears `draft`; `Repository.FindAny` serves only test/draft flows; unenabled drafts go after `config.SAMLDraftTTL` through the `federation_draft_prune` job). Test connection: `Commands.IssueTest` → `ik_fedtest_` ticket (`federation.TestPrefix`, hash in `federation_tests`, `config.FederationTestTTL`, event `connection.test_requested` via the route classifier), public `GET /identity/v1/federation/test/:environment/:connection?ticket=` renders the hosted interstitial (`fedhttp.TestStartPage` → `hostedhttp.TestStart`, template `test-start`; shape check only, spends nothing, so link scanners cannot burn the ticket) and its form `POST`s the `ticket` field to the same path → `Flows.StartTest` (`UseTest` spends it only for the right connection) → `Callback` renders a result page (`callbackTest`/`fedhttp` `testPage`) with no session, user or link, event `connection.tested` (`success`, no claims); OIDC and SAML only. Wizard UI: `frontend/src/components/library/idp-guides/` (data-driven guides in `guides.ts`, `GuidedSetupDialog` over a `GuidedTransport`, console and portal) |
| hosted | `internal/iam/hosted` | Server-rendered hosted sign-in/invitation pages for `hosted_login` OAuth clients, login branding: environment default ← client style ← organization overrides (`hosted.OrganizationSettings`, `organization_login_settings`; nil fields inherit, `Apply` merges, `Queries.Branded` resolves). `hostedsvc.brandOrganization` picks the organization for a page: the authorize hint (`oauth.FormOrganization`: `organization_id` or `urn:iamkit:org:id:` scope, admitted by `oauthfosite.scopeStrategy`) › the parked login's `Chosen` › a verified domain of the typed email (`Repository.DomainOrganization`); the `connection_id` hint (`oauth.ConnectionHint`/`FormConnection`, kept in the authorize form) makes `hostedhttp.login` skip the identifier step and start that connection (`hostedsvc.hintedConnection`: active, not LDAP, environment connections need `SignIn.Shows`, organization connections need `OrganizationSSO` and the organization hint; unusable hints are ignored, malformed ones are 400 at `ValidateAuthorization`); the organization hint also narrows `hostedsvc.step`'s organizations and `oauthhttp.finish` refuses another organization (`oauth.ErrOrganizationHint`). Invitation pages and emails (`authentication.Message.OrganizationID` → `Branding.Brand`) use the organization's brand; codes stay environment-branded. Custom sign-in texts (`hosted.Texts`, `hosted_texts`: one `texts` jsonb per environment/client/organization × locale; `TextCommands`/`TextQueries`): keys restricted to the `hosted.*` catalog of the locale, plain text, `i18n.SameArgs` placeholders, `TextLimit`; `Queries.Wording` lays environment › client › organization (`LayTexts`, stale keys dropped) for `hosted.Page.Texts`, and `hostedhttp.view.T/N/V` read `i18n.Texts` (custom first, then catalog) — a lookup failure only logs |
| impersonation | `internal/iam/impersonation` | Audited admin impersonation |
| invitation | `internal/iam/invitation` | Email invitations into organizations (token issue, preview, accept) |
| management | `internal/iam/management` | Workspaces, projects, environments, operators, keys |
| mfa | `internal/iam/mfa` | Second factors (TOTP, email and SMS codes, WebAuthn security keys), passkeys, recovery codes, pending MFA logins, per-organization MFA policy and allowed factors |
| oauth | `internal/iam/oauth` | OAuth2/OIDC server (authorization code + PKCE, RFC 8628 device authorization, RFC 8693 token exchange, client_credentials for service accounts, private_key_jwt, UserInfo, RFC 7662 introspection, RP-initiated and back-channel logout, per-client JWT or opaque access tokens; `prompt`/`max_age` (`oauth.ParseInteraction`, checked by `ValidateAuthorization`; discovery `prompt_values_supported`): there is no browser session between authorize requests, so every authorization signs in afresh — `none` answers `login_required` at the redirect URI (JSON `Completion` for `Accept: application/json`) before any ticket, `login`/`max_age=0` make `finish` refuse a custom-UI token older than the request and ask OIDC/Google/Microsoft upstreams for `prompt=login` (`federation.JoinPrompt`, `Flows.StartHosted(…, prompt)`), `select_account` forces the hosted organization chooser, `consent` is a no-op; unknown values and `none`+other are `invalid_request`; `oauth_clients.initiate_login_uri` (`oauth.ValidateInitiateLoginURI`: https or loopback http, migration 003) is the sign-in endpoint SAML IdP-initiated logins are handed to, see the federation `Provider` row). Protected resources (MCP authorization, phase a; migration 018, guide `docs/guides/applications/protect-mcp-server.md`): `oauth.ProtectedResource` registers a resource of an application whose audience is its canonical URL (`oauth.CanonicalResource`, vectors in `sdk/resourceserver/testdata/canonical.json`; `uri` = audience by trigger, unique in the deployment, never the IAM resource), `default_scopes` ⊆ its permissions, `idle_ttl_seconds`/`max_ttl_seconds` (defaults `config.ProtectedResourceIdleTTL`/`MaxTTL`) ≤ the environment's `protected_resource_policies` (`config.ProtectedResourceIdleCeiling`/`LifetimeCeiling`; lowering trims servers in the same transaction); `ProtectedResourceCommands`/`Queries`/`Repository`, `oauthsvc.ProtectedResources`, `oauthpg.ProtectedResources` (events `protected_resource.created`/`.updated`/`.deleted`, `protected_resource_policy.updated`; deactivate/delete end the authorizations' sessions), `oauthhttp.ProtectedResources` at `…/protected-resources` + `…/protected-resource-policy` (management, `/api/v1` `iam:protected-resources:read`/`write`); `iamclient`, `@iamkit/node` `ProtectedResourcesClient` and Python `protected_resources`. RFC 8707: `oauth.ResolveResource` — no `resource` = unchanged OIDC, the client resource's protected URI = resource flow (`Client.Protected`), anything else or repeated = `invalid_target` (`oauth.ErrInvalidTarget`); in the flow scopes are permissions (`ResourceScopes`: none → `default_scopes`; `openid`/`nonce` optional, `state` required, `offline_access` implied with the refresh grant), `aud` = URI, `oauthfosite.Session.Consented` keeps the grant and every refresh issues `EffectiveScopes` = consented ∩ current permissions (D12), the session lives `max_ttl` and each refresh token `idle_ttl`, every refresh holds the grant to `ProtectedTarget.Deadline` = min(stored deadline, `Session.Started` (the session's `created_at`) + current lifetime) so a lowered ceiling cuts grants already issued, and a token request's `resource` must equal the grant's. Resource-flow access tokens carry the marker claim `resource` (`oauth.ClaimResourceIndicator`, = URI; in `action.ReservedClaims`); exchanged tokens do not, and `ExchangeResource` emits no `act`. `GET …/protected-resources/:id/impact` counts the live sessions deactivate/delete would end (console `frontend/src/pages/resource-protected.tsx` warns with it; a resource without one offers **Protect as MCP server**, `resource-protect.tsx`, which posts with the resource's audience and an application from `…/applications?resource_id=`); `GET …/protected-resources/:id/clients/:client/impact` (`oauth.ExternalClientImpact`: live sessions + distinct users) does the same for one external client's block/delete (`resource-clients.tsx`). `/.well-known/oauth-authorization-server` (RFC 8414) is the discovery document; `server/cors.go` opens it and the JWKS to any origin without credentials, and `/oauth/token`/`/oauth/revoke` keep credentialed CORS for configured origins while other origins get an open preflight and a readable answer for public clients only (`oauthhttp.PublicClientLocal`). Resource servers verify with `sdk/resourceserver` / `@iamkit/node/resource-server` (PRM RFC 9728; the `resource` claim is required unless `AllowTokensWithoutResource`/`allowTokensWithoutResource`; permissions = granted scopes minus protocol scopes, never the `permissions` claim; 401/403 `WWW-Authenticate` with `resource_metadata`, `insufficient_scope` challenge = granted ∪ required, `Authorization` stripped before the handler). Client ID Metadata Documents (phase b, migrations 019-021): a `client_id` that is an https URL names an external client (`oauth_clients.source='cimd'`, `oauthcimd` fetcher, `Client.Admitted(now)`); admission is `pending`\|`approved`\|`blocked`, decided per protected resource by `oauthsvc.Admissions` (`AdmissionCommands`/`AdmissionQueries`/`AdmissionRepository`, `oauthpg.Admission`, `oauthhttp.Admissions` at `…/protected-resources/:id/clients|client-templates`, `…/oauth-client-allowlist`, `…/oauth-client-presets`; reuses `iam:protected-resources:read`/`write`, events `oauth_client.approved`/`.blocked`/`.unblocked`/`.forgotten`/`.expired`/`.demoted` (`data.reason` `oauth.Demotion*`), `oauth_client_allowlist.created`/`.deleted`). Approvals by policy follow the policy (migration 022; `admitByPolicy`/`reconcilePolicy`/`demote` in `oauthpg/admission.go`, allowlist/preset/open-mode changes admit or demote with grants revoked), `Client.Disabled` (server `allow_client_metadata` off or feature off) is checked at use by `Client.Admitted`, and the `client_documents_reconcile` job demotes approved clients of environments whose `client_metadata_documents` feature is off. Limits (M-3/M-4): `RequestExternalAccess` counts a user's (`config.ClientAccessRequestsPerUser`) and an organization's (`PerOrg`, `oauth_client_access_requests.organization_id`) live requests for pending clients under advisory locks → `ErrAccessRequestLimit` (429 `CLIENT_ACCESS_REQUEST_LIMIT`); `oauthsvc.admitFetch` takes per-address (`ClientMetadataFetchesPerIPPerMinute`, IPv6 /64), new-client (`ClientMetadataNewFetchesPerMinute`) and environment budgets → `ErrFetchBudget` (429 `CLIENT_METADATA_FETCH_BUDGET`), and `oauthsvc.stale` serves an approved row's stored metadata when the fetch fails with `ErrDocumentUnavailable` or the budget (bounded by `ClientMetadataStaleFor`). Blocking revokes the client's sessions/grants in the same transaction (`oauthpg.revokeClients`), `client_admission_expire` does it for expired approvals, and `liveIntrospection`/`opaqueToken`/`token`/`finish` check `Admitted` at use. Lock order (W4/W5): `protected_resources` row (`FOR NO KEY UPDATE` in Update, `FOR UPDATE` in Delete) → `oauth_clients` rows (`ORDER BY id`) → tickets, token rows (`oauth_requests`), device codes, sessions. Admission changes lock clients `FOR NO KEY UPDATE`, so token inserts (their foreign key's key-share lock) pass; only the deleters in `clientDeleters` (`lockClientForDelete`, `PruneExternal`, `DeleteProtectedResource`) take `FOR UPDATE`, enforced for every adapter by `TestClientRowLocksLetTokenInsertsThrough`. Sign-ins and token transactions of an external client take its row `FOR SHARE` first (`oauthpg` `Complete`; `oauthfosite.Store.BeginTX` when `Bound` is external) and recheck admission in the transaction (`put`/`InvalidateAuthorizeCodeSession`/`RotateRefreshToken` → `oauthfosite.ErrNotAdmitted` → `invalid_grant` via `issueError`; the authorization code is stored in such a transaction too, `oauthhttp.Handler.issueCode`, refused with the hosted page) (`TestExternalClientTokensStopWhenNotAdmitted`; `TestOAuthOutboundUsesGuardedClient` keeps every http.Client of the oauth module on the guarded transport (no default client or `http.Get`, no `Proxy`, `DialContext` = `netx.GuardedDialer`) and `TestExternalClientRowsHaveOneWriter` lets only the functions in `externalWriters` (`oauthpg` external/admission) write non-registered `oauth_clients` rows — every other statement carries `source='registered'`, so `PATCH`/`DELETE /oauth-clients/:id` and the portal never touch a client named by a URL). Presets (`oauth.Presets`) are CIMD allowlist entries or templates (registered public clients, `oauth_clients.preset`); `mcp_inspector` needs feature `development_clients`. Refused external clients get the hosted page `client` (`hostedhttp.Handler.Refusal`, wired with `oauthhttp.Handler.Refusals`), never a redirect. Deleting a protected resource revokes and deletes its external clients' grants first (M2). Dynamic client registration (phase c, migration 023, RFC 7591): `POST /oauth/register` (`oauthhttp.Handler.register`, RFC 7591 error bodies, per-address limiter `config.ClientRegistrationsPerIPPerMinute`) stores a global, immutable, public registration in `oauth_registrations` (`oauth.ClientRegistration.Validate` → `Registered`, `client_id` `dcr_` + 32 hex via `oauth.NewDynamicClientID`, auth `none`, code + refresh grants only; `oauthsvc.Registrations`, `oauthpg` `SaveRegistration` caps unused rows at `config.ClientRegistrationMaxUnused` under an advisory lock → 429). It is 404 and discovery omits `registration_endpoint` unless `Offers.DynamicRegistration` (feature `dynamic_client_registration`, off by default, in an environment with an active server whose `allow_dynamic_registration` is on). A registration writes no client row or event until a signed-in user asks a server that takes it: `oauthsvc.ExternalClient` branches on `dcr_` vs URL (`describe`/`resolve`), `ExternalTarget.Allows(source)` and `sourceOn` gate it (refused → `ErrClientRegisteredOnly`), then it is an external client with `source='dcr'` (`ExternalClientView.Source`, empty `Host`) admitted like documents except that the allowlist never matches it (`Admission(clientID)` matches URL ids only); `insertExternal` marks the registration used (`markRegistrationUsed`). Turning `allow_dynamic_registration` off demotes with `oauth.DemotionRegistrationOff`, `client_documents_reconcile` loops over `oauth.ExternalSources` (`DemoteSource`), and `client_registration_prune` deletes unused registrations after `ClientRegistrationUnusedTTL` and used ones no client row holds after `ClientRegistrationIdleTTL` (`FOR UPDATE OF g SKIP LOCKED`); only `registrationWriters` (`SaveRegistration`, `markRegistrationUsed`, `PruneRegistrations`) write `oauth_registrations` and an update sets `last_used_at` only (`TestDynamicRegistrationsHaveOneWriter`). Operator surfaces: console `frontend/src/pages/resource-clients.tsx` (Clients section: pending/approved/blocked, host first, name "unverified" unless a preset vouches, logo only on the client_id's host), `resource-protected.tsx` (`allow_client_metadata`, `client_admission`, template picker, impact counts), `mcp-clients.tsx` (environment allowlist + preset gallery with public/local badges) and `mcp-presets.tsx` (template dialog with the client config snippet); CLI `iam protected-resources clients|…`, `iam client-allowlist`, `iam client-presets` (`cmd/iam/internal/cli/protected_resources.go`); `iamclient` `external_clients.go`, `@iamkit/node` `ProtectedResourcesClient` and Python `protected_resources` carry the same methods. Incompatible changes go to `CHANGELOG.md` |
| organization | `internal/iam/organization` | Organizations, memberships, org units, positions, groups, verified domains. Domain join (migration 007, `organizations.domain_join` + `domain_join_group_id`, FK to an operator-managed group; `orgsvc.Update` checks it with `Repository.OperatorGroup`): `authentication.Transaction.JoinByDomain` (`authpg.joinByDomain`) inserts the missing membership (+ group member, events `membership.created`/`group.members_changed` with `data.source` `domain_join`) for an active human with a verified email on a verified domain of an active `domain_join` organization of the environment. One hook, run by `authsvc.signIn` (every headless method, federation included), `authsvc.Authenticator.Organizations` (hosted chooser, before the listing) and `SignupTransaction.Join`; `ON CONFLICT DO NOTHING`, so removed (inactive) memberships are never re-added — no exclusion table. The portal `PATCH …/admin` needs `iam:org:settings:write` plus `orgadminsvc.domainJoinAssignable` (`rolesAssignable` for the group) |
| orgadmin | `internal/iam/orgadmin` | Organization-scoped administration for end users (`/api/v1/…/organizations/:organization/admin`): an `orgadmin.Principal` (token user, organization, `iam:org:*` permissions — built by `bootstrap.orgAdminCaller`, zero for impersonated tokens) is checked by `orgadminsvc`, which composes the organization, user, authorization, invitation and federation ports. Rules: users outside the organization are 404; user-record writes need `users.home_organization_id` = the organization; roles are assignable only when the caller holds all their permissions (`Role.Assignable`) or belong to a resource the organization owns or was granted (`Role.Granted`, computed by `orgadminpg.roleColumns`); owners of a resource grant it through `ResourceGrantCommands` after `orgadminsvc.owned` checks ownership (404 otherwise), the `org_owner` built-in role only by owners, and the last direct owner stays (`Owners.KeepsOwner`). `…/admin/directories` (`GET` `iam:org:read`; `POST`/`DELETE` `iam:org:sso:write`) is SCIM self-service: `orgadminsvc` composes `provisioning.ControlCommands`/`ControlQueries` (`Issue` always with `Organization = p.Organization`, `RevokeOrganization` and `OrganizationCredentials` filter by organization in `provpg` SQL, another organization's credential is 404), returns `scim_url` = `<issuer>/scim/v2`, and the mutations classify as `provisioning_credential.created`/`.revoked` with the admin as actor. `…/admin/api-keys[/options|/:key]` (`iam:org:api-keys:read`/`write`; organization keys and members' user keys of the organization — `apikey.OrganizationScope`, machine keys and other organizations' keys are 404; `orgadminsvc.requireKeyAdmin` refuses setup-link principals and zero-user callers such as impersonated tokens with 403, creating needs a `Granter` = the admin's own permissions as an upper bound) and `…/admin/users`/`…/admin/members` leave out machine users (`user.KindHuman` filter, `organization.MemberFilter.HumansOnly`, `orgadminpg.Member` excludes them so reads and writes 404) — machine users are operators' credentials; `…/admin/audit-logs[/export]` (`iam:org:audit:read`; `orgadminsvc.AuditLogs` forces `Filter.Organization`, `export` streams with a request-detached context) and `…/admin/log-streams[/:stream[/test|enable|rotate-secret|deliveries[/:d/retry]]]` (reads `iam:org:audit:read` or `iam:org:log-streams:write`, writes the latter; `logstream.OrganizationScope` → sources forced to `audit_logs`, foreign/environment streams 404; `logstreamsvc.target` gives `log_stream.*` audit rows `/organizations/<org>/log-streams/<id>` so they reach `…/admin/events`) compose the `auditlog`/`logstream` ports. `…/admin/branding` and `…/admin/password-policy` reuse `hosted.Commands`/`Queries` organization settings and `authentication.PasswordPolicyCommands` (`iam:org:read` / `iam:org:settings:write`). Built-in roles are `roles.system_role` rows (`authorization.SystemRoles`, never edited). `audit_events.actor_kind`/`organization_id` are filled by the `audit_event_context` trigger, so writers keep inserting four columns. The opt-in hosted portal (`orgadmin.Portal`, `PortalCommands`/`PortalQueries`/`PortalRepository`, `orgadminsvc.Portals`, `orgadminhttp.Portal`) is IAMKit's own public OAuth client per environment (`oauth_clients.system = 'org_admin'`, on the IAM resource; `oauthsvc` refuses `Update`/`Disable` of system clients with 409); `GET /identity/v1/org-admin/:environment` publishes it, the SPA under `/org-admin` (`frontend/src/org-admin`, own CSP in `server/spa.go`) signs in with code + PKCE and calls the `/admin` routes with the bearer token; disabling revokes its sessions. Setup links (`orgadmin.SetupLink*`, migration 004 `org_setup_links`/`org_setup_sessions`, `orgadminsvc.SetupLinks`, `orgadminpg.SetupLinks`, `orgadminhttp.SetupLinks`): an operator (management, `/api/v1` `iam:orgs:read`/`write`) or an owner (`orgadmin.Principal.RequireOwner`: every `authorization.OrgPermissions`; portal `/admin/setup-links`) issues an `ik_setup_` secret (hash stored; URL `<issuer>/org-admin/<env>/setup#secret`, shown once; `config.SetupLinkTTL` 7d default, max `SetupLinkMaxTTL`, ≤ `SetupLinkMaxPerOrg` live) with intents `sso`/`directory`/`domains`/`log_streams` (`orgadmin.IntentPermissions`; `log_streams` → `iam:org:read` + `iam:org:log-streams:write`, so a setup bearer reaches `…/admin/log-streams` but not the audit-log reads). The public `POST /identity/v1/org-admin/setup` exchanges it for an opaque `ik_setupsess_` bearer (`config.SetupSessionTTL`, never past the link); `apiauth.Middleware.WithSetup` resolves it (`SetupSessions.Session` joins the live link, so revoke/expiry end it at once), `apiauth.Scope` limits it to the grant's own `…/admin` routes, `bootstrap.orgAdminCaller` returns a `Caller` with `Setup` and the intents' permissions (no user; `Principal.Setup()`, `RequireAccount` refuses branding/password-policy reads), actor kind `setup_link` (`event.ActorSetupLink`, resolved by the `audit_event_context`/`event_actor` triggers), `org_setup_link.created`/`.used`/`.revoked` events; frontend `org-admin/portal.tsx` `SetupLink` (setup mode) and `components/library/setup-links.tsx`. SSO setup (`…/admin/connections`, `iam:org:sso:write`): `orgadminsvc` composes the federation ports for SAML draft create (`draft: true`), detail (`GET …/connections/:id` with `draft`, `saml` values or `callback_url`), `PATCH`, `POST …/:id/enable` and `POST …/connections/:connection/test` (federation `IssueTest`); the portal's `ConnectionsPage` runs the shared guided wizard (`components/library/idp-guides`, old form kept as **Advanced**) and the Directory page shows the SCIM guides |
| provisioning | `internal/iam/provisioning` | SCIM user and group provisioning |
| risk | `internal/iam/risk` | Bot protection and risk signals; the domain imports no other IAM package (consumers declare one-method ports over its types: `authentication.Risk`/`Captcha`, `hosted.Risk`/`Captcha`; `action.RiskInput`). CAPTCHA: `captcha_configs` per environment (`turnstile`/`hcaptcha`, secret sealed with `risk.Cipher` → 422 `ENCRYPTION_KEY_REQUIRED`, `HasSecret`, `hosted`/`headless`, ≤ 20 `hostnames`), feature `captcha`; `risksvc` checks the `captcha_token` of headless `login`/`challenges`/`signup`/`federation/ldap/login` (and hosted forms, remembered as `hosted_captcha_passes` bound to the ticket for `config.CaptchaPassTTL` and `config.CaptchaPassUses` credential posts spent atomically by `UsePass`) through the `Verifier` port, missing or refused → 403 `CAPTCHA_REQUIRED` (`details.provider`); a transport error or `config.CaptchaTimeout` fails open (`iamkit.captcha.unavailable`, attempt `captcha=unavailable`), a provider "invalid" never does, and an unreadable configuration is an error (a failed flag lookup keeps the flag on); public `GET /identity/v1/captcha/:environment`, management `…/captcha` + `POST …/captcha/test` (5/min, 422 `CAPTCHA_SECRET_INVALID`). Risk: `risk_policies` (`ip_velocity`/`user_brute_force`/`impossible_travel` off\|log\|challenge\|block, `new_device`/`stale_account` off\|log\|notify\|challenge, thresholds validated in `policy.go`, absent policy = everything off), `risk_restrictions` (`ip`/`country`/`email_domain` allow\|deny, ≤ 1000 → 422 `RESTRICTION_LIMIT_REACHED`, deny → 403 `SIGN_IN_BLOCKED`), `sign_in_attempts` (pruned by the `sign_in_attempt_prune` job after `IAMKIT_SIGN_IN_ATTEMPT_RETENTION`, default `config.SignInAttemptRetention`, ≥ 24h; logins stored only as per-environment HMAC `login_hash`), `user_devices` (≤ `config.MaxUserDevices`, pruned after `config.UserDeviceRetention` by the same job, device id from the `__Host-iamkit-device` cookie or headless `device_id` checked by `risk.ValidDevice`; no id → `new_device` not evaluated). `Evaluator`: `Screen` (restrictions, before any credential), `Assess` (detections after the first factor, plus the deny rules on `Signal.Email` = the account's own email → `Decision.Restricted`; errors assess as nothing), `Record` (attempt + `notify` alerts through the `Notifier` port, at most one email per user per `config.SecurityAlertInterval`); feature `risk_signals`. A `challenge` decision parks the login (`mfa_logins.challenge`, `hosted_logins.risk_challenge`) and answers `mfa_required` with `factors:["email"]` and `reason:"risk_challenge"` (`mfasvc.BeginChallenge`; no verified email → 403 `CHALLENGE_UNAVAILABLE`, the only error that skips the challenge — a send cooldown, cap or delivery failure still parks it; hosted `ChangePassword`/`Enrollment` refuse a parked `RiskChallenge`); `pre_sign_in` actions see `Input.Risk` and may answer `challenge`. `GEOIP_REQUIRED` (422) guards `impossible_travel` and country restrictions when the `Geo` port has no database. Events `captcha.*`, `risk_policy.*`, `risk_restriction.*`, `risk.detected`, `sign_in.blocked` (one per address and reason per `config.SignInBlockedEventInterval`; writers through `eventpg.Audit`/`Emit`); `session.created` data gains `ip`, `user_agent`, `country`, `risk_detections`. Adapters: `riskpg`, `riskcaptcha` (Turnstile/hCaptcha siteverify, guarded transport), `riskgeo` (MaxMind-format reader `IAMKIT_GEOIP_DB`, reloaded when its mtime changes), `riskmail` (security alert), `riskhttp` (management + public, `/api/v1` `iam:security:read`/`write`); `risk_signals`/`captcha` are environment-scoped flags. `TestRiskAdaptersStayInRiskModule`: `oschwald/*` only in `riskgeo`, `riskgeo`/`riskcaptcha` imported only by `riskmodule` and `bootstrap`, the risk domain imports no other `internal/iam` package |
| samlidp | `internal/iam/samlidp` | IAMKit as a SAML 2.0 identity provider for applications: registered service providers (entity ID, ACS URLs, application/resource, NameID format, attribute mapping), SP-initiated SSO through the hosted pages, opt-in single logout (`slo_url`/`slo_binding`/`slo_soap_url`/`certificate`; see the `Protocol` / `Flows` row) |
| serviceaccount | `internal/iam/serviceaccount` | Machine-to-machine credentials |
| signing | `internal/iam/signing` | Per-environment token signing keys (`next`→`active`→`retiring`→`retired`), JWKS, the `Keyring` every token signer/verifier uses |
| usage | `internal/iam/usage` | Limits and daily usage per environment. `usage.Catalog`: totals `users_max`/`organizations_max`/`applications_max` (count query, 422 `QUOTA_EXCEEDED` via `usage.ErrExceeded`, soft under concurrency), daily `emails_per_day`/`sms_per_day` (`usage_daily` + unflushed counts, 429) and per-minute `requests_per_minute`/`action_calls_per_minute` (fixed window through the `usage.Window` port: `cacheredis.Window` shared by the replicas with `REDIS_URL` (falls back to `usagememory`), else `usagememory` per replica; fails open, 429). Deployment caps `IAMKIT_LIMITS` (`usage.ParseDeployment`, `bootstrap.WithLimits`) are ceilings; `environment_limits` (NULL = deployment) only `Tighten`s them; `PUT …/limits` workspace owners only (`usage.Mutation.Owner`), audited `limits.updated`; effective limits cached `config.UsageLimitCacheTTL`. Consumers declare their own ports and get them via `SetQuota`/`SetUsage` + `Deps.Quota`/`Deps.Usage` in bootstrap: `Quota.Admit` (user, organization, application, provisioning, invitation accept, federation first sign-in) and `Usage{Admit, Count}` (authentication: signup, `DeliveryService.Send`, `SMSService.SendSMS`, `Tokens.Issue`; action: `actionsvc.call` skips refused calls as `OutcomeSkipped`; oauth: `oauthhttp.Handler.issued` after fosite token responses). `Commands.Count` keeps counts in memory; `Server.Start` runs `FlushUsage` every `config.UsageFlushInterval` and at shutdown (`Server.WaitFlushed`) on every replica. `usage_rollup` (logins = `session.created` without parent session/impersonation, `users_created`; cursor `usage_rollup_cursor`, events settled `config.UsageRollupSettle`) and `usage_prune` (`config.UsageRetention`) are worker jobs. `usagehttp.Meter` (on `/api/v1/environments/:environment`) admits `requests_per_minute` and counts `api_requests`; `…/limits` (management) and `…/usage?days=` (management + `/api/v1` `iam:usage:read`) |
| user | `internal/iam/user` | End-user CRUD; import (`user.Create` also takes `password_hash`, `email_verified`, `metadata`, operator routes only — `orgadmin.NewUser` has none of them; `password` and `password_hash` are exclusive, ≤ `user.MaxPasswordHash`, human users only; the hash passes the `user.PasswordHashes` port (`CheckHash`, set with `usersvc.SetPasswordHashes` by `usermodule` to the `authpassword.Hasher` sign-in verifies with; nil → 422 "password hash import is not available"), is stored trimmed, skips the password policy and breach check and never reaches `request:user.create` actions; `POST …/users/import` (management, and `/api/v1` with `iam:users:write` + `iam:users:import` — `userhttp.Handler.GuardImports`, wired in bootstrap with `apiauth.Require`, also demands `iam:users:import` for `password_hash`/`email_verified` on `/api/v1` `POST /users`; migration 010 adds the permission to existing IAM resources; `Commands.Import`, 1–`user.MaxImportRows` rows) runs every row as its own `Create` (quota, hook, transaction; `userpg.Create` origin `import` for `user.created`) and answers 200 `ImportResult{results[{index,id|error{code,message}}], created, failed}`); derived `user.State` (`userpg.stateSQL`: suspended › locked › initial › inactive › active — `active` stays the only sign-in gate; `users.last_signed_in_at` is written by `authpg.Transaction.CreateSession`), deactivate/reactivate (audited); incident actions `RevokeSessions` (`POST …/users/:id/revoke-sessions`: every live session ends, audited `user.sessions_revoked` with `data.count`) and `RequirePasswordChange` (`users.password_change_required`: `authentication.PasswordAccount.MustChange` treats it like an expired password; every password write clears it; users without a password → 422); per-key metadata (`identity.ValidateMetadata`/`SetMetadata`, shared with organizations), `users.profile` checked against the environment's `user_schemas` row (`SchemaValidator`), self-service `/identity/v1/me/profile` (`x-iamkit-self`), claims released through `oauth.ProfileClaims` (`x-iamkit-claim`, `profile` scope); `users.avatar_url` (`identity.AvatarURL`: https link only, no uploads) is released as `picture` the same way, set by users via `PATCH /identity/v1/me` (`authentication.ProfileUpdate`) and filled from federation `picture` claims (`fedpg.fillAvatar` only when empty); optional `users.username` (`identity.Username`, never `@`, unique per environment — `userpg.usernameTaken` → 409) is a second login identifier: `identity.Login` splits input into email or username, `authpg.PasswordUser`/`EligibleChallengeUser` match either in one query, `authsvc.requireNoSSOAfter` checks SSO enforcement for username logins only after the password matched, hosted `Identify` sends usernames straight to the password page; released as `preferred_username`; `users.external_id` (`identity.ExternalID`: trimmed, ≤ 255, no control characters; migration 005, partial unique index `users_environment_external_id` → 409 `external_id is taken`) is the operator's own identifier for the user — set on create/update (`user.Update.ExternalID` is a `*string`; `null` or `""` clears, absent keeps, via `Update.UnmarshalJSON`, shared by `orgadmin.UserChange`), filtered with `user.Filter.ExternalID` (`?external_id=`, exact), machine users included, in history through `record_changes`, never in tokens, and unrelated to SCIM's `externalId` (`provisioned_identities`); `users.phone`/`phone_verified` (CHECK `users_phone_verified`: verified needs a number) are verified by users through `PhoneCommands` (`usersvc.Phones`, `/identity/v1/me/phone` + `/verify`, fresh sign-in `user.FreshAuth`, SMS through the one-method `user.SMS` port = `authsvc.SMSService.SendSMS`, purpose `phone_verification`; the pending code lives in `phone_verifications`, limits in `user.PhoneVerification.Send`) or set by operators (`Update.PhoneVerified`, audited `user.phone_verified_set`); released as `phone_number(_verified)` with the `phone` scope (`Queries.Claims` takes the granted scopes); SCIM maps `phoneNumbers[type eq "mobile"]` only when `provisioning_connections.map_phone` (`provisioning.Principal.MapPhone`); `users.kind` `machine` (no email/username/password/phone/OTP by CHECK, trigger `refuse_machine_user` refuses factors, external/provisioned identities and challenges; SCIM group reads/replaces skip them) — machine users authenticate with machine API keys (`apikey` module, `ik_key_`; `…/users/:id/api-keys` GET/POST/DELETE on management and `/api/v1` under `iam:users:read`/`write` go through `apikey.Commands`/`Queries` with `EnvironmentScope`: POST creates machine keys only and needs `application_id`, GET lists the user's keys of every kind). Machine users also sign in with keys (`user_keys`, at most `user.MaxKeys`; `KeyCommands`/`KeyQueries`/`KeyRepository`, `/users/:id/keys`): a public JWK uploaded (`identity.ParsePublicJWK`: RSA ≥ 2048 or EC P-256/384/521, public members only, stored in `identity.MarshalPublicJWK` form) or generated by the `user.KeyPairs` port (`userkeys.RSA`, private PEM returned once). The RFC 7523 grant `oauth.GrantJWTBearer` is dispatched by `oauthhttp.Handler.keyGrant` before fosite (no client) to `authentication.TokenIssuer.KeyGrant`: `TokenCodec.AssertionKey` (kid) → `TokenRepository.MachineKey` (live key, active machine user) → `TokenCodec.VerifyAssertion` (`authjwt`, iss = sub = user, aud = issuer or token endpoint, exp ≤ `config.ClientAssertionMaxAge`) → `TokenRepository.KeySession` (jti spent in `client_assertion_jtis` under a `user_key:` prefix, `authpg.Resolve`, one reused `sessions.user_key_id` session, `amr` `swk`); removing a key revokes its sessions; every refusal is `invalid_grant` |

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
code emails of sign-ups and challenges go out after the answer
(`authsvc.deliverLater`, `Server.WaitDeliveries` at shutdown and in e2e), so
timing never tells an account from an unknown address;
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
| `Passwords` | authentication, management | `Hash(string) (string, error)`; authentication's `Compare(hash, password) (matches, stale bool)`, management's (`mgmtbcrypt`) still `bool`. Authentication's adapter `authpassword.Hasher` hashes with bcrypt `config.BcryptCost` and verifies imported formats by prefix (bcrypt cost 4–14, argon2id/argon2i, pbkdf2 PHC/passlib/Django, Firebase scrypt; parameter caps in `authpassword/format.go` are enforced at verify too — over-cap, unsupported or empty hashes compare a dummy bcrypt and fail). `CheckHash(hash) error` (`errx.Validation`, parse + caps only) validates imports (`user.PasswordHashes`). `stale` = any non-bcrypt format, `$2y$`, or bcrypt below the current cost |
| `Secrets` | authentication, federation, oauth, provisioning, serviceaccount | Token/key generation and hashing |
| `Delivery` | authentication | Send challenge codes and invitations (`Message`); per environment a webhook, SMTP or Resend configuration (`DeliveryConfig.Provider`), else the global one |
| `Mailer` / `Renderer` / `Branding` | authentication | Send a rendered `Email` (SMTP, Resend); render a `Message` in the environment's `Brand` and language (`internal/i18n`); read that brand |
| `Mailer` | invitation | Send invitation mail and build links; `invmail` adapts authentication delivery |
| `Provider` | federation | Provider discovery, authorization and verification (`fedoidc`): OIDC discovery + ID token, or for `github`/`github_enterprise`/`oauth2` (no ID token, no nonce) PKCE + a user API read (`gitHubClaims` at the connection's API base; `oauth2Claims` maps `Options.Claims` dotted paths, email verified only via the mapped member). `federation.Preset` derives the issuer (`base_url`, or the `authorize_url` origin for `oauth2`). `fedsaml` (`github.com/crewjam/saml`) serves `ProviderSAML` (organization connections only): `Prepare` fetches/parses IdP metadata (guarded transport) and sets `Issuer` = IdP entity ID, `Client` = SP entity ID (`federation.SAMLServiceProvider`); `Authorize` builds an HTTP-Redirect AuthnRequest whose ID is `fedsaml.RequestID(nonce)`; `Verify` checks the posted response (signature, `InResponseTo`, audience, ACS, validity) and maps NameID/`Options.Attributes`; `Metadata` serves SP metadata. The SP key is the environment's `signing.Keyring` signer with a self-signed certificate derived from it (stable across replicas). `fedmodule.router` picks `fedoidc` or `fedsaml` by `Connection.Provider`. The ACS (`fedhttp.ACS`) parks the response (`Repository.ParkAssertion`, `saml_responses`, one-time `ik_saml_` handle) and 303s to the ordinary callback, which takes it (`TakeAssertion`) under the binding cookie; `UseAssertion` (`saml_assertions`) refuses replays. `Claims.Groups` carries all values of the groups attribute and `action.IdentityInput.Groups` (read-only) hands them to `post_federation`. IdP-initiated: a POST whose RelayState is not `ik_state_` goes to `Flows.IdPInitiated` (`fedsvc`): `Provider.Hint` (unverified audiences/`InResponseTo`) → `federation.ResponseConnection` (SP entity ID embeds environment+connection, `ParseSAMLEntityID`) → an active SAML connection with `Options.IdPInitiatedClientID` (else 400 `IDP_INITIATED_DISABLED`) → `Provider.VerifyUnsolicited` (same checks with crewjam `AllowIDPInitiated`, so no `InResponseTo`) → `Repository.LoginClient` (active client of the environment with `oauth_clients.initiate_login_uri`, application usable by the organization: resource not `require_grant`, owned or granted; the option is re-checked at create/update by `fedsvc.check`) → `Repository.AcceptInitiated` (spends the assertion ID, emits `connection.idp_initiated` in one transaction). The RelayState is read as a query (`ParseRelayState`): `client_id` only if `LoginClient` accepts it (else the connection's), `redirect_uri` only if registered on it (`target_link_uri`). The ACS 303s to `initiate_login_uri` with `iss`, `connection_id`, `organization_id`; it never looks a user up or creates a session — the application then redirects to `/oauth/authorize?connection_id=…` (hosted `Flow.Hinted`/`hintedConnection`, `oauth.ConnectionHint`). Tests use the in-process IdP `fedsaml/samltest` (`Unsolicited` signs a response with no request) |
| `Directory` | federation | Password check against an organization's LDAP directory (`ProviderLDAP`, organization connections only, no redirect). `fedldap` (`github.com/go-ldap/ldap/v3`) dials `ldaps://` or `ldap://`+StartTLS (plaintext refused by `validLDAP`) through `netx.GuardedDialer` unless the host is in `IAMKIT_LDAP_ALLOWED_HOSTS` (`fedmodule.Deps.LDAPAllowed`; tests replace the dial via `bootstrap.WithLDAPDialer`), binds as `Options.BindDN` (password = the sealed client secret) or anonymously, searches `UserBaseDN` with `UserFilter` (`{email}`/`{username}` escaped; exactly one entry), binds as it and maps `Options.Attributes`. `Discovery.Provider` = `ldap` tells clients to post the password: headless `Flows.Directory` (`POST /identity/v1/federation/ldap/login`, answers like `/login`), hosted `Flows.DirectoryHosted` via `hosted.Flow.Directory` (Route method `ldap`). Entries' `Options.Attributes.Groups` (default `memberOf`) feed `Claims.Groups`. Both reuse `fedsvc` account resolution, so logins are `authentication.MethodSSO` (`amr` `fed`). Issuer = `federation.LDAPServer(url)`, Client = lowercased base DN; neither can change. Tests use the in-process directory `fedldap/ldaptest` (`github.com/jimlambrt/gldap`) |
| `Flows` | federation | Browser login flows (`Discover`, `Start`, `StartHosted`, `Callback`, `Redeem`, `EnvironmentConnections`), separate from Commands/Queries. `Callback` returns an `Outcome`: a session, or for hosted starts (`Continuation` = OAuth ticket) only the `Verified` identity, or for a headless start with `federation.Return` (custom sign-in UI: `return_to` on an origin of an OAuth client of the application — `Repository.ReturnAllowed` — + S256 `code_challenge`) a one-time `ik_fedres_` handle parked in `federation_results` (`ResultTTL`, no token stored) that `fedhttp.Callback` 303s to `return_to`; `POST /identity/v1/federation/result` → `Redeem` (`Result.Verifies`, wrong verifier spends it) issues the session like `/login`. First logins go through `Connection.Admit` → `Repository.Provision` (`Provisioning.Create` = JIT; without it an organization `link_email` connection links only an existing member, origin `email`); `Connection.UpdateProfile` calls `Repository.Refresh` (`Connection.Profile`) on every sign-in, audited `federation.profile_updated` |
| `Authenticator` | authentication | Verify a credential without a session (`VerifyPassword`, `VerifyCode` → `Verified`), list accessible `Organizations` (leaving out those whose methods refuse the `Verified.PolicyMethod()`), then `Issue` the session once the organization is chosen (re-checks SSO enforcement and the method) |
| `Flow` | hosted | The hosted sign-in journey; consumes the `Authorizations` (pending OAuth ticket), `Challenges`, `Federation`, `Invitations` and `SecondFactor` ports declared in `hosted/ports.go` plus `authentication.Authenticator`. The parked `hosted.Login{Verified, Chosen, Attempts}` carries state between pages; `hostedsvc.step` orders: MFA first for an enrolled user with several organizations (non-SSO logins; a factor applies in all of them) → chooser → MFA/enrollment for the chosen organization → `Issue`. Second-factor tries are reserved atomically (`Repository.Attempt`) before the code is checked |
| `SecondFactor` | authentication | Login-time MFA (`Requirement`, `Begin`, `Complete`, `Enroll`), implemented by `mfasvc` (`mfa.Logins`). `Login`/`VerifyChallenge` return `authentication.Result{Issued, MFA}`: `SignIn` commits the credential transaction, then either issues the session or parks a pending `ik_mfa_` login. `authhttp.Respond` renders either shape; federation receives it as the injected `Respond` closure |
| `Logins` | mfa | Everything login flows need from mfa (headless pending logins + hosted `Verify`/`Enrolling` without a pending token) |
| `TOTP` | mfa | RFC 6238 codes/URIs (`mfatotp`, stdlib only, RFC test vectors) |
| `Relying` | mfa | WebAuthn relying party (`mfawebauthn.New(issuer, origins)`: RP ID = issuer host, origins = issuer origin + `IAMKIT_WEBAUTHN_ORIGINS`; zero value disabled). Ceremony state is opaque to `mfasvc` and parked in `webauthn_sessions` (hashed `ik_wa_` id, single use, `config.WebAuthnCeremonyTTL`). Tests drive it with the stdlib software authenticator `mfawebauthn/softkey` |
| `Passkeys` | mfa, authentication, hosted | Discoverable-credential sign-in: `mfa.Passkeys` (`BeginPasskey`/`FinishPasskey` → user) is consumed by `authsvc` as `authentication.Passkeys`, which exposes `PasskeyCommands` (headless `/identity/v1/passkeys/login/*`) and `Authenticator.VerifyPasskey` (hosted); `hosted.Passkeys` starts hosted ceremonies. A passkey is gated by `SignInPolicy.AllowPasskey`, `organizations.allow_passkey` (method `passkey`) and the `webauthn` factor being allowed; its `amr` is `hwk`,`user`,`mfa` (`authentication.FirstFactorAMR`), so `HasMFA` skips the second factor |
| `Sender` | mfa | Deliver email/SMS factor codes; `mfasend.Sender` adapts authentication `Delivery` (purpose `mfa`) and `SMSCommands.SendSMS`, wired by `mfamodule.Module.Deliver` in bootstrap |
| `SMSDelivery` | authentication | Send one `SMS` (`authsms.Twilio`, `authsms.Webhook`, Standard Webhooks-signed) |
| `Store` / `Opener` | blob | Object storage for the S3 log stream destination; `gocloudblob.Opener` builds an S3 client (static credentials, guarded transport) per `blob.Target`; `gocloudblob.NewMemory` for tests |
| `Cipher` | authentication, event, federation, logstream, mfa | Seal/open stored secrets (SMTP password / Resend API key, client secrets, TOTP secrets); implemented by `internal/cryptox.Sealer` (`IAMKIT_ENCRYPTION_KEY`), injected via `bootstrap.WithSealer` |
| `Breaches` | authentication | Breached-password lookup for the policy's `breach_check`; `authhibp` (Have I Been Pwned range API, k-anonymity). Errors and `config.BreachCheckTimeout` fail open; tests replace it via `bootstrap.WithBreaches` (nil disables) |
| `TokenCodec` | authentication | JWT sign/parse (combines `TokenIssuer` + `TokenValidator`) |
| `Keyring` | signing | `Signer(environment)` (the environment's active key, else the deployment key `JWT_PRIVATE_KEY_PATH`; an active key that cannot be opened fails closed), `Verifier(kid)` (`Verifier.Allows(environment)`: environment keys verify only their environment), `JWKS`. `signingsvc` caches published keys `config.SigningKeyCacheTTL` and reloads on an unknown kid at most once per `config.SigningKeyMissInterval`. Consumed by `authjwt.Codec` and `oauthfosite` (`Signer`, `Hints`, provider); private halves sealed with `signing.Cipher` (`IAMKIT_ENCRYPTION_KEY`, else 422 `ENCRYPTION_KEY_REQUIRED`). Retiring needs `config.SigningKeyRetireDelay` after demotion or `force` (409 `KEY_IN_USE`) |
| `Transaction` | authentication, invitation, mfa, oauth | Database transaction handle for multi-step mutations |
| `AccountRepository` | oauth | Service accounts as OAuth clients of `client_credentials` (`FindAccount` → `oauth.Account`: SHA-256 secret hash + `identity.ClientAuth`). `oauthfosite.Accounts.Authenticate` runs fosite's client authentication over it (`digest` hasher, not bcrypt); `oauthhttp.Handler.token` branches `grant_type=client_credentials` to it (set with `Handler.Accounts`) and mints with `authhttp.Tokens.IssueMachine` — the same token as `/identity/v1/machine-token`, which refuses `private_key_jwt` accounts |
| `LogoutCommands` / `LogoutQueries` / `LogoutRepository` / `LogoutSender` / `Dispatcher` | oauth | Back-channel logout. A trigger (`queue_logout_notification`) fills the `logout_notifications` outbox when a session with `oauth_client_id` ends (`revoked_at` set or row deleted) and the client has a `backchannel_logout_uri`. `oauthsvc.Logouts.DispatchLogouts` leases due rows (`ClaimLogouts`, `FOR UPDATE SKIP LOCKED`, safe on every replica), sends through `oauthfosite.LogoutSender` (logout+jwt signed by the environment key, guarded transport) and retries with `oauth.RetryAfter` until `LogoutMaxAttempts`, then `LogoutFailed` audits `oauth.backchannel_failed`. Delivery and pruning are `internal/worker` jobs (`oauthmodule.Module.Jobs`: `logout_delivery` with `Logouts.Lag` → `iamkit.worker.lag`, `logout_prune`), registered on `server.Server.Workers` in bootstrap, started by `Server.Start(ctx)` from `cmd/iamkit` and stopped with the signal context; tests call `Server.LogoutDispatcher` or `Workers.RunOnce` directly. Operators read `…/logout-deliveries` and retry failed ones (`oauthhttp.Logouts`) |
| `SubscriptionCommands` / `SubscriptionQueries` / `SubscriptionRepository` / `Sender` / `Secrets` / `Dispatcher` | event | Event webhooks (see the event module row): subscriptions, the `event_deliveries` outbox, the `event_webhook` / `event_webhook_maintenance` jobs (`eventmodule.Module.Jobs`) and the Standard Webhooks `eventhook.Sender` |
| `Devices` | oauth, hosted | RFC 8628 device authorization grant. `oauth_clients.grant_types` (`oauth.ValidateGrantTypes`: default `authorization_code`+`refresh_token`; `GrantDeviceCode` needs `hosted_login`; redirect URIs only with `authorization_code`). `oauth_device_codes` keeps hashed `ik_device_` and user codes (`UserCodeAlphabet`, 8 consonants); `oauth.Device.Poll` is the polling state machine (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant` as `errx.Error.Code`). `/hosted/device` (`hostedhttp` device pages, `hosted.Devices`) runs the unchanged hosted journey on an `oauth_authorizations` ticket with `device_hash`; `oauthhttp.Handler.finish` branches on `Ticket.Device` to `Authorization.ApproveDevice` (audited `oauth.device_approved`) and renders `hostedhttp.Handler.DeviceApproved` instead of redirecting. At `/oauth/token` fosite authenticates the client, `oauthfosite.deviceGrant` (a custom `TokenEndpointHandler`) checks the request and mints tokens after `Devices.RedeemDevice` fills the session (`Handler.session`, shared with the code flow). Wired in bootstrap with `Handler.Devices` on both HTTP handlers |
| `Exchanges` / `ExchangeRepository` | oauth | RFC 8693 token exchange at `/oauth/token`, handled in `oauthhttp.exchangeToken` before fosite (fosite only authenticates the client via `oauthfosite.AuthenticateClient`); issued tokens are ordinary IAMKit access JWTs signed with `authhttp.Tokens.Sign` (no refresh/ID token). `subject_token_type` `access_token`: a confidential client with `oauth.GrantTokenExchange` (`oauth.ValidateExchangeClient`) exchanges a user token for another resource of its application — `oauthpg.ExchangeSession` recomputes access with `authpg.Resolve` and reuses/creates a child session (`sessions.parent_session_id`, one live child per resource, revoked with its parent by trigger `session_children_ended`; audited `oauth.token_exchanged`). `urn:iamkit:params:oauth:token-type:user_id`: a service account with `service_accounts.can_impersonate` (owner-only `saccthttp` `PUT …/impersonation`, audited `service_account.impersonation`; forbidding revokes its `sessions.actor_account_id` sessions) impersonates a user with a `reason`; the token's `act` claim (`authentication.Token.ActorAccount`) names it and `Token.Impersonated()` covers both actor kinds; audited `oauth.impersonated`. Errors are `errx` with `oauth.Exchange*` codes mapped to OAuth errors by `exchangeError` |
| `Protocol` / `Flows` | samlidp | SAML IdP. `samlxml` (crewjam `IdentityProvider` pieces) builds the IdP metadata at `/saml/:environment/metadata` (entity ID = that URL, SSO `/saml/:environment/sso`, key = the environment's `signing.Keyring` signer + `signing.Signer.Certificate`), decodes AuthnRequests (Redirect or POST) and signs responses + assertions (RSA-SHA256, not encrypted, `SessionIndex` = IAMKit session). `samlidp.AuthnRequest.Check` accepts only a registered issuer (`FindEntity`) and ACS URL; AuthnRequest signatures are not verified. `Flows.Begin` parks it in `saml_sso_requests` (hashed `ik_samlreq_` ticket = `samlidp.TicketPrefix`, browser binding hash, `RequestTTL`, single use) and `samlhttp.SSO` 303s to `/hosted/login`. Bootstrap's `tickets` composite (`internal/bootstrap/saml.go`) implements `hosted.Authorizations`, routing `ik_samlreq_` tickets to `Flows.Target` as an `oauth.Pending` whose `Client` has a zero ID (environment branding and default sign-in options, `hostedsvc.options`); `finisher` routes `Finish` to `samlhttp.Handler.Finish`, which `Flows.Finish`es (audited `saml.assertion_issued`) and renders `hostedhttp.Handler.PostForm` (auto-submit form, nonce'd script). Service providers reference `application_resources`; deleting one is a hard delete. Single logout (opt-in per provider, `samlidp.ValidateLogout`: HTTPS URLs need a PEM `certificate`): `Finish` records `saml_idp_sessions` (`LogoutRepository.RememberSession`) for providers with SLO. `samlhttp.SLO` at `/saml/:environment/slo` (Redirect or POST) → `LogoutFlows.Logout`: `Protocol.DecodeLogout`, unknown/non-SLO issuer or failed `VerifyLogout` all answer the same 401, `LogoutRequest.Check`, `EndSession` (revokes the session named by SessionIndex when asserted to that provider+NameID, with transaction-local `iamkit.saml_logout_origin`/`session_reason`/`session_actor`, audited `saml.logout`) and a signed `LogoutResponse` (`Success`, else `Requester`). `samlxml` refuses SHA-1 and unsigned requests (Redirect: signature over the raw query; POST: enveloped XML, re-parsed after verification against wrapping). Back channel: triggers `session_saml_deleted`/`session_saml_ended` fill `saml_logout_notifications` for providers with `slo_soap_url` (skipping the origin); `LogoutFlows.DispatchLogouts` (`ClaimLogouts` `SKIP LOCKED`) sends signed SOAP LogoutRequests through `samlxml.Sender` (guarded transport, `bootstrap.WithSAMLLogoutTransport`, also unguarded by `IAMKIT_ALLOW_PRIVATE_DELIVERY`), retries with `samlidp.LogoutRetryAfter` up to `LogoutMaxAttempts`, then `saml.logout_failed` (`eventpg.System`). Jobs `saml_logout_delivery`/`saml_logout_prune`, registered only with the `saml_idp` feature. Tests use the in-process SP `samlxml/samltest` (`LogoutRedirect`/`LogoutPost`, `Backchannel()` SOAP double) |
| `SchemaValidator` | user | `Check(schema)` compiles a user schema (draft 2020-12 only, remote `$ref` refused, formats asserted), `Validate(schema, profile)`; `userschema.Validator` (`santhosh-tekuri/jsonschema`). `user.Properties` reads the `x-iamkit-self`/`x-iamkit-claim` annotations; schemas are never applied retroactively (`SaveSchema` only counts `NonConforming`) |
| `ProfileClaims` | oauth | A user's `x-iamkit-claim` attributes (`user.Queries.Claims`, wired in bootstrap with `oauthhttp.Handler.ProfileClaims`), added to ID tokens (`finish`, device grant) and UserInfo when the `profile` (or, for `phone_number(_verified)`, `phone`) scope was granted; a lookup failure leaves them out |
| `Hints` | oauth | Verify an `id_token_hint` for `/oauth/end_session` (`oauthfosite.Hints`: `signing.Keyring` + issuer, expired tokens allowed) → `oauth.IDTokenHint`; `oauthsvc.Logout` ends its `sid` via `Repository.EndSession` (audited `oauth.logout`) |
| `Verifier` | risk | CAPTCHA provider siteverify (`Verify(ctx, provider, secret, CaptchaCheck) (Answer, error)`); `riskcaptcha` (Turnstile, hCaptcha) dials through the guarded transport with `config.CaptchaTimeout`; an error means the provider did not answer and the caller fails open, an `Answer` with `Success` false never does |
| `Geo` | risk | Deployment-wide GeoIP: `Locate(ip, headerCountry) (Location, bool)` and `Status()`; `riskgeo` reads `IAMKIT_GEOIP_DB` (MaxMind format, reloaded on mtime change), falling back to the country a trusted proxy header (`IAMKIT_GEOIP_HEADER`, read by `server.clientInfo` only from `IsProxyTrusted()`) put in `identity.ClientInfo`; without either, `impossible_travel` and country restrictions are unavailable (422 `GEOIP_REQUIRED`) |
| `Notifier` | risk | Emails a user a security alert (`Alert`); `riskmail` adapts authentication `Delivery` (purpose `security_alert`); failures are logged only |
| `Keys` | risk | `Hash(environment, purpose, value)`: per-environment HMAC keys behind `login_hash` and `device_hash`, derived from the deployment secret so stored attempts never hold raw logins |

These follow the same rule: defined in `ports.go`, implemented by adapters,
consumed by services.

### Rules

1. **`ports.go` contains only interfaces.** No structs, no constants, no
   `Validate()` methods. One file, predictable location. Enforced by
   `TestPortsAreInterfaces`.

2. **Domain files are named after the aggregate**, not `models.go` or `types.go`:
   `resource.go`, `grant.go`, `connection.go`, `credential.go`, etc.

3. **Domain structs own their validation.** Every create/update struct gets
   `Validate() error` on a value receiver. One field → one error message.

4. **Services are thin orchestrators.** They call `input.Validate()`, generate
   IDs, enforce cross-entity invariants, and delegate to the repository. A
   `*svc` package exports no constants or variables (statuses, actions and
   purposes live in the domain package; tuning knobs stay unexported):
   `TestServicesExportNoConstants`. Repositories never call
   `identity.New<Entity>ID()`: `TestRepositoriesDoNotGenerateIDs`.

5. **Adapters never import other adapters** (except `authpg.Resolve` which is
   shared SQL reused by `fedpg` and `oauthpg` for session resolution, and
   `eventpg`, the event writer every `*pg` adapter calls in its own
   transaction — only `*pg` packages may import it). The layer rules
   (foundation → domain → svc → module/adapters, only the composition root
   imports assemblers and adapters, domain and `*svc` import no SQL or
   transport) are enforced by `TestLayerDependencies`
   (`internal/architecture/layers_test.go`). Its only exceptions are the
   `sharedSQL` and `siblingAdapters` maps, each entry with its reason
   (`oauthhttp` → `oauthfosite`). Anything a module needs from another
   module's adapter (`authhttp.Tokens`, `mgmthttp.Principal`,
   `authpassword.Hasher`, the `userschema` validator) is declared as a
   consumer-side port or function type and injected through `Deps` by
   bootstrap (`imphttp.Issue`/`Operator`, `oauthhttp.Tokens`,
   `invitation`/`oauth.Passwords`, `usermodule.Passwords`,
   `auditlogmodule.Deps.Schemas`). The same test refuses any import of the
   `sdk/` module from `internal/`: a rule both sides implement (RFC 8707
   canonicalization) is written twice and pinned by shared test vectors.

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
   from another origin. `oauth_clients.allowed_origins` (`oauth.Origins`: https or loopback http, ≤ `oauth.MaxOrigins`,
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
- An exported method of a `*svc` package that takes a type with `Validate()`
  calls `<param>.Validate()` itself, and a `Validate()` calls `Validate()` on
  its fields that have one: `TestServicesValidateInputs`
  (`internal/architecture/validate_test.go`). Exceptions are the
  `validateExempt` map, each with its reason (`authentication.Context` is a
  partial scope by design; the optional `federation.Return`).

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

## Documentation website

- `docs/**/*.md` is the single source for GitHub and the Astro/Starlight site;
  preserve existing page URLs and inbound anchors when editing headings.
- `website/src/sidebar.mjs` groups pages by reader task; every document appears
  exactly once (`website/scripts/docs.test.mjs`). Product entry points live in
  `docs/guides/{sign-in,enterprise,organizations,authorization,platform}/index.md`;
  `docs/reference/sdk/index.md` selects runtimes, separate from API reference.
- Quickstarts explain the outcome, prerequisites, numbered actions, expected
  checks and next steps. Keep endpoint contracts in reference pages; never
  invent supported methods or copy another product's claims.
- Preserve `frontend/src/theme.css` and the Starlight semantic mapping in
  `website/src/styles/theme.css`; editorial/navigation edits do not redesign them.
- Gates: root `python3 scripts/check_docs.py`; in `website`, `npm test`,
  `npm run check`, `npm run build`, then `npm run check:links`.

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
