# iamkit (Python)

Server-side IAMKit SDK for Python (≥ 3.10), sync and async over `httpx`: verify access tokens, protect
routes (FastAPI, Flask, Django), run OAuth flows as a confidential client, sign machine users in with keys,
verify webhooks and actions, validate API keys and call the management API.

```sh
pip install iamkit               # not published to PyPI yet: install from this directory
pip install "iamkit[fastapi]"    # or [flask], [django]
```

| Area | API |
| --- | --- |
| Access tokens | `JwtVerifier` (offline, JWKS), `IntrospectionVerifier` (online), `KeySet`, `AccessClaims`, `has_permission`, `require_permission`, `has_mfa`, `is_fresh`, `require_mfa`, `is_impersonated` |
| OAuth / OIDC | `OAuthClient` (authorize URL + PKCE, code, refresh, revoke, UserInfo, introspection, client_credentials, private_key_jwt, token exchange, impersonation, device flow), `create_pkce`, `random_token`, `discover`, `verify_id_token`, `verify_logout_token` |
| Machine users | `KeyLogin` (RFC 7523 JWT-bearer grant), API keys via `APIKeyValidator` |
| Webhooks and actions | `verify_webhook`, `verify_action`, `ActionResponse`, `deny`, `Conditions` |
| Management | `IAMKit` / `AsyncIAMKit`: `users`, `organizations`, `roles`, `api_keys`, `events`, `webhooks`, `audit_logs`, `risk`, `waitlist`, generic `request()`, `paginate` |
| Frameworks | `iamkit.integrations.fastapi.require_token`, `iamkit.integrations.flask.IAMKitFlask`, `iamkit.integrations.django.IAMKitMiddleware` |
| Errors | `IAMKitError` (`status`, `code`, `message`, `details`) |

Every network method has an `a`-prefixed coroutine twin (`averify`, `aexchange_code`, `avalidate`, …);
`AsyncIAMKit` mirrors `IAMKit`.

## Protect an API

```python
from iamkit import ExpectedToken, JwtVerifier

verifier = JwtVerifier(
    ExpectedToken(
        issuer="https://iam.example.com",
        audience="https://api.example.com",
        environment_id=ENVIRONMENT,
        application_id=APPLICATION,
        resource_id=RESOURCE,
    )
)
claims = verifier.verify(bearer_token)  # raises IAMKitError (401, or 503 when the JWKS is unreachable)
if not claims.has_permission("invoices:read"):
    ...
```

The key set (`KeySet`) needs an https issuer (http only for localhost), refetches at most once per `cooldown`
(30 s) and, while IAMKit is unreachable, keeps verifying with cached keys for `stale_grace` (1 h) past `max_age`.

Create one verifier per process: it caches the signing keys (10 minutes, refetched on an unknown `kid` at most
every 30 s). Offline verification does not see logout or suspension before the token expires; use
`IntrospectionVerifier(expected, base_url)` where that must take effect at once — it fails closed.
Always compare `claims.organization_id` with the tenant the request touches.

```python
from fastapi import Depends, FastAPI
from iamkit.integrations.fastapi import require_token

app = FastAPI()


@app.get("/orgs/{org}/invoices")
async def invoices(
    org: str,
    principal=Depends(
        require_token(verifier, permissions=["invoices:read"], organization=lambda request: request.path_params["org"])
    ),
):
    return {"user": principal.claims.sub}
```

## Sign users in (authorization code + PKCE)

```python
from iamkit import KeySet, OAuthClient, create_pkce, random_token, verify_id_token

oauth = OAuthClient("https://iam.example.com", client_id, client_secret=client_secret)
pkce, state, nonce = create_pkce(), random_token(), random_token()
url = oauth.authorization_url(redirect_uri=REDIRECT, state=state, nonce=nonce, code_challenge=pkce.challenge)
# ... redirect the browser, then on the callback (after comparing state):
tokens = oauth.exchange_code(code, REDIRECT, pkce.verifier)
id_claims = verify_id_token(
    tokens.id_token, issuer=ISSUER, client_id=client_id, keys=KeySet(issuer=ISSUER), nonce=nonce
)
```

## Webhooks and actions

```python
from iamkit import ActionResponse, verify_action, verify_webhook

event = verify_webhook(secret, request.headers, raw_body)  # raw bytes, before any JSON parsing
action = verify_action(secret, request.headers, raw_body)
reply = ActionResponse(claims={"tier": "pro"}).to_json()  # or ActionResponse.denied("Account under review")
```

`verify_webhook` accepts a delivery within 5 minutes of its `webhook-timestamp`; to drop retries and replays,
remember the `webhook-id` of handled events (deliveries are at least once).

## Management

```python
from iamkit import IAMKit

with IAMKit("https://iam.example.com", management_key, environment_id=ENVIRONMENT) as iam:
    user = iam.users.create(email="ada@example.com", name="Ada")
    for u in iam.users.iterate(search="example.com"):
        ...
    iam.audit_logs.emit(
        org,
        "invoice.paid",
        "2026-01-01T00:00:00Z",
        actor={"type": "user", "id": uid},
        targets=[{"type": "invoice", "id": "1"}],
        idempotency_key="invoice-1-paid",
    )
    iam.request("GET", iam.environment_path("/features"))  # any other route
```

## Develop

```sh
cd clients/python
uv sync
uv run python scripts/unasync.py   # regenerates iamkit/_aresources.py after editing _resources.py
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q
IAMKIT_CONTRACT_URL=... uv run pytest tests/contract   # against a real stack, see tests/contract/README
```
