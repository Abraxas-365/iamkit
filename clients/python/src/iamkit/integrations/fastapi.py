"""FastAPI / Starlette integration (``pip install iamkit[fastapi]``).

.. code-block:: python

    verifier = JwtVerifier(ExpectedToken(...))
    app = FastAPI()

    @app.get("/orgs/{org}/invoices")
    guard = require_token(verifier, permissions=["invoices:read"], organization=lambda r: r.path_params["org"])

    async def invoices(org: str, principal: Principal = Depends(guard)):
        return {"user": principal.claims.sub}

Failures answer IAMKit's envelope ``{"error": {"code", "message"}}`` with 401 (``WWW-Authenticate: Bearer``),
403 or 503 — never a request without verified claims.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from fastapi import HTTPException, Request

from ..apikeys import APIKeyValidator
from ..errors import IAMKitError
from ..tokens import TokenVerifier
from ._common import Authenticator, Principal, bearer, check, error_body

__all__ = ["Principal", "require_token"]


def _http_error(error: IAMKitError) -> HTTPException:
    headers = {"Cache-Control": "no-store"}
    if error.status == 401:
        headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return HTTPException(status_code=error.status, detail=error_body(error)["error"], headers=headers)


def require_token(
    verifier: TokenVerifier,
    *,
    permissions: Iterable[str] = (),
    organization: str | Callable[[Request], str | None] | None = None,
    mfa: bool = False,
    max_age: float | None = None,
    allow_api_keys: APIKeyValidator | None = None,
) -> Callable[[Request], Awaitable[Principal]]:
    """A FastAPI dependency: verifies the bearer token (``averify``) and checks the requirements.

    Returns the :class:`Principal`. ``organization`` is a fixed ID or a function reading the requested
    organization from the request (compared with the token's); ``allow_api_keys`` opts in to ``ik_key_``
    keys, validated online (off by default: a key is then 401). ``mfa`` demands a second factor,
    optionally passed within ``max_age`` seconds; API keys carry no session, so they fail it.
    """
    auth = Authenticator(verifier, allow_api_keys)
    wanted = tuple(permissions)

    async def dependency(request: Request) -> Principal:
        try:
            principal = await auth.aauthenticate(bearer(request.headers.get("authorization")))
            tenant = organization(request) if callable(organization) else organization
            check(
                principal,
                permissions=wanted,
                organization=None if organization is None else (tenant or ""),
                mfa=mfa,
                max_age=max_age,
            )
        except IAMKitError as exc:
            raise _http_error(exc) from exc
        request.state.iamkit = principal
        return principal

    return dependency


def principal_of(request: Request) -> Principal | None:
    """The principal :func:`require_token` stored on the request, or ``None``."""
    value: Any = getattr(request.state, "iamkit", None)
    return value if isinstance(value, Principal) else None
