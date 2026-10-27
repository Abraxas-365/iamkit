# Python SDK

`iamkit` (`clients/python`) is the server-side SDK for Python 3.10 and later. It
is the Python counterpart of the [Node.js SDK](node.md) and the [Go SDK](go.md):
token verification, the OAuth client, machine-user key login, webhook and action
verification, API key validation, a thin management client and optional FastAPI,
Flask and Django integrations. It is hand-written over `httpx` (every network
method has a synchronous form and an `a`-prefixed coroutine twin) and `PyJWT`,
typed (`py.typed`, mypy strict) and not yet published to PyPI: install it from
the directory (`pip install ./clients/python`, extras `[fastapi]`, `[flask]`,
`[django]`).

| Need | Use |
| --- | --- |
| Accept access tokens in an API | `JwtVerifier` (offline, cached JWKS) or `IntrospectionVerifier` (online, sees revocation at once) |
| Authorize a route | `has_permission`, `require_permission`, `require_mfa`, `is_fresh`; the framework guards take `permissions=`, `organization=`, `mfa=` |
| Sign users in to a server-rendered app | `OAuthClient` (`authorization_url`, `exchange_code`, `refresh`, `end_session_url`), `create_pkce`, `verify_id_token` |
| End sessions on back-channel logout | `verify_logout_token` |
| Call APIs as a service | `OAuthClient.client_credentials` (secret or `private_key_jwt`) |
| Sign a machine user in | `KeyLogin` (JWT-bearer grant) |
| Accept customers' [API keys](../../guides/machines/api-keys.md) | `APIKeyValidator` (or `validate_api_key`), or a guard with `allow_api_keys` |
| Act for a user | `OAuthClient.exchange_token`, `OAuthClient.impersonate` |
| Devices without a browser | `OAuthClient.authorize_device` + `wait_for_device` |
| Receive events and actions | `verify_webhook`, `verify_action`, `ActionResponse`, `deny` |
| Administer an environment | `IAMKit` / `AsyncIAMKit` (`X-API-Key` management key) |

## Verification rules

`JwtVerifier(ExpectedToken(issuer, audience, environment_id, application_id,
resource_id))` accepts RS256 tokens of the configured issuer and audience whose
`environment_id`, `application_id` and `resource_id` match. `application` tokens
must carry an organization and a session; `machine` tokens must carry neither;
any other purpose is refused. Other algorithms (including `none` and HMAC) are
refused before any key is used. Failures raise `IAMKitError` 401 `UNAUTHORIZED`;
a JWKS that cannot be fetched is 503 `JWKS_UNAVAILABLE`, which the integrations
answer as 503 rather than 401. API keys (`ik_key_`) and opaque OAuth tokens
(`ory_at_`) are not JWTs: validate API keys through their validator, and resolve
opaque OAuth tokens through a confidential OAuth client's introspection endpoint.

The `KeySet` behind the verifier caches the JWKS for 10 minutes and refetches on
an unknown `kid` at most once every 30 seconds, so a flood of forged `kid`s
cannot hammer IAMKit. Share one verifier per process. `IntrospectionVerifier`
calls `POST /identity/v1/introspect` and fails closed: an outage raises its own
error, never "inactive".

```python
verifier = JwtVerifier(ExpectedToken(
    issuer="https://iam.example.com", audience="https://api.example.com",
    environment_id=ENVIRONMENT, application_id=APPLICATION, resource_id=RESOURCE))
claims = verifier.verify(bearer_token)        # or: await verifier.averify(bearer_token)
require_permission(claims, "invoices:read")   # 403 IAMKitError otherwise
```

The tenant guard takes a fixed ID or a function reading the requested
organization from the request; the token's `organization_id` must match, and a
missing requested organization is refused, so a route parameter is never trusted
on its own. See [token claims](../token-claims.md) and the Go
[middleware](middleware.md) rules, which these mirror.

## Frameworks

```python
# FastAPI / Starlette
guard = require_token(verifier, permissions=["invoices:read"],
                      organization=lambda request: request.path_params["org"])
@app.get("/orgs/{org}/invoices")
async def invoices(org: str, principal: Principal = Depends(guard)): ...

# Flask
iam = IAMKitFlask(verifier)
@app.get("/orgs/<org>/invoices")
@iam.require(permissions=["invoices:read"], organization=lambda: request.view_args["org"])
def invoices(org): ...      # current_principal()

# Django: MIDDLEWARE += ["iamkit.integrations.django.IAMKitMiddleware"], IAMKIT_VERIFIER = verifier
@require_token(permissions=["invoices:read"])
def invoices(request): ...  # principal_of(request)
```

Failures answer IAMKit's envelope: 401 (`UNAUTHORIZED`, `WWW-Authenticate:
Bearer`), 403 (`FORBIDDEN`, or `STEP_UP_REQUIRED` for `mfa=True`, optionally
with `max_age` seconds) and 503 `UNAVAILABLE` when verification is down. An
`ik_key_` bearer is 401 unless you pass `allow_api_keys=APIKeyValidator(...)`
(`IAMKIT_API_KEYS` in Django); the principal then has `api_key` instead of
`claims`, and MFA guards refuse keys (no session).

## API keys

`APIKeyValidator(base_url, environment_id, audience).validate(raw_key)` checks
an `ik_key_` [API key](../../guides/machines/api-keys.md#validate-keys-in-your-backend)
online with `POST /identity/v1/introspect` and returns an `APIKey`: `id`,
`name`, `owner` (`type`, `id`, `organization_id`), `organization_id`,
`resource_id`, the **effective** `permissions` and `expires_at` (Unix seconds,
`0` = never). Unknown, revoked, expired or disabled keys, values that are not
API keys and an audience other than the key's resource raise 401; an unreachable
IAMKit raises its own error, so fail closed.

## Webhooks and actions

`verify_webhook(secret, headers, raw_body)` and `verify_action(...)` check the
[Standard Webhooks](../event-webhooks.md) signature (`webhook-id`,
`webhook-timestamp`, `webhook-signature`; several `v1,` signatures while a
secret rotates; `whsec_` secrets; five minutes of timestamp tolerance; bodies up
to 1 MiB) against the **raw body bytes** and decode the event or `ActionInput`.
Failures raise `WebhookError` (`SIGNATURE`, `TIMESTAMP`, `SECRET`, `BODY`).
Answer an action with `ActionResponse(claims=..., patch=...).to_json()` or
`deny("message")`.

## Management client

```python
with IAMKit("https://iam.example.com", management_key, environment_id=ENVIRONMENT) as iam:
    iam.users.create(email="ada@example.com", name="Ada")
    for user in iam.users.iterate(search="example.com"): ...
    iam.audit_logs.emit(org, "invoice.paid", "2026-01-01T00:00:00Z",
                        actor={"type": "user", "id": uid}, targets=[{"type": "invoice", "id": "1"}],
                        idempotency_key="invoice-1-paid")
    iam.request("GET", iam.environment_path("/features"))   # any other route
```

`IAMKit` (and `AsyncIAMKit`, same arguments, awaitable) wraps
`/management/v1/environments/:env` with the management key in `X-API-Key`:
`users` (create, get, list, update, import, suspend, deactivate, reactivate,
delete, revoke_sessions, unlock, require_password_change, history),
`organizations` (organizations, members, invitations), `roles` (roles,
assignments, grants), `api_keys`, `events` (list, iterate, export),
`webhooks` (subscriptions, deliveries, replay, rotate_secret), `audit_logs`
(emit with `idempotency_key`, list, iterate, export, actions), `risk`
(policy, restrictions, sign-in attempts, CAPTCHA) and `protected_resources`
(list, get, create, update, delete, policy, set_policy; see
[protect an MCP server](../../guides/applications/protect-mcp-server.md)).
Answers are the decoded JSON
documents of the [OpenAPI document](../api/openapi.md); `iterate` walks
offset-paged lists (`{items, page}`) and cursor logs (`{items, next}`) for you
and `paginate(fetch)` does the same for any list endpoint. The management key
is a server-side secret.

## Errors

Every failure is an `IAMKitError` with `status`, `code`, `message` and
`details`. IAMKit envelopes keep their code (`PASSWORD_CHANGE_REQUIRED`,
`QUOTA_EXCEEDED`, …); OAuth endpoints keep the OAuth `error`
(`invalid_grant`, `authorization_pending`, …). Requests time out after 10 s
(`timeout=`), follow no redirects and read at most 1 MiB; network failures raise
the `httpx` error.

Usage examples are in the [package README](../../../clients/python/README.md).
Build and test: `cd clients/python && uv sync && uv run ruff check . && uv run mypy && uv run pytest -q`.
