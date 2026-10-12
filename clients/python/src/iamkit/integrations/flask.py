"""Flask integration (``pip install iamkit[flask]``).

.. code-block:: python

    guard = IAMKitFlask(verifier)

    @app.get("/orgs/<org>/invoices")
    @guard.require(permissions=["invoices:read"], organization=lambda: request.view_args["org"])
    def invoices(org):
        return {"user": current_principal().claims.sub}

Failures answer IAMKit's envelope with 401 (``WWW-Authenticate: Bearer``), 403 or 503.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterable
from typing import Any, TypeVar, cast

from flask import Response, g, jsonify, request

from ..apikeys import APIKeyValidator
from ..errors import IAMKitError
from ..tokens import TokenVerifier
from ._common import Authenticator, Principal, bearer, check, error_body

__all__ = ["IAMKitFlask", "Principal", "current_principal"]

F = TypeVar("F", bound=Callable[..., Any])


def _response(error: IAMKitError) -> Response:
    response = jsonify(error_body(error))
    response.status_code = error.status
    response.headers["Cache-Control"] = "no-store"
    if error.status == 401:
        response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return response


def current_principal() -> Principal | None:
    """The principal the guard stored for this request, or ``None``."""
    value: Any = g.get("iamkit")
    return value if isinstance(value, Principal) else None


class IAMKitFlask:
    """Builds route decorators around one verifier (share it across the app)."""

    def __init__(self, verifier: TokenVerifier, *, allow_api_keys: APIKeyValidator | None = None) -> None:
        self._auth = Authenticator(verifier, allow_api_keys)

    def require(
        self,
        *,
        permissions: Iterable[str] = (),
        organization: str | Callable[[], str | None] | None = None,
        mfa: bool = False,
        max_age: float | None = None,
    ) -> Callable[[F], F]:
        """Decorates a view: verifies the bearer token, checks the requirements and stores the
        :class:`Principal` (``current_principal()``). ``organization`` is a fixed ID or a function reading
        the requested one (e.g. from ``request.view_args``)."""
        wanted = tuple(permissions)

        def decorator(view: F) -> F:
            @functools.wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    principal = self._auth.authenticate(bearer(request.headers.get("Authorization")))
                    tenant = organization() if callable(organization) else organization
                    check(
                        principal,
                        permissions=wanted,
                        organization=None if organization is None else (tenant or ""),
                        mfa=mfa,
                        max_age=max_age,
                    )
                except IAMKitError as exc:
                    return _response(exc)
                g.iamkit = principal
                return view(*args, **kwargs)

            return cast(F, wrapper)

        return decorator
