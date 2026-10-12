"""Django integration (``pip install iamkit[django]``).

Settings::

    MIDDLEWARE = [..., "iamkit.integrations.django.IAMKitMiddleware"]
    IAMKIT_VERIFIER = verifier                # a JwtVerifier / IntrospectionVerifier, or a dotted path to one
    IAMKIT_API_KEYS = validator               # optional: an APIKeyValidator (or dotted path) to accept ik_key_ keys

The middleware reads ``Authorization: Bearer``; a valid token sets ``request.iamkit`` (a
:class:`Principal`); a presented but invalid token is answered 401 (503 when IAMKit cannot be reached)
at once; requests without credentials pass through. Protect views with :func:`require_token`, which
answers 401 when there is no principal.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterable
from typing import Any, TypeVar, cast

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.module_loading import import_string

from ..errors import IAMKitError, unauthorized
from ._common import Authenticator, Principal, bearer, check, error_body

__all__ = ["IAMKitMiddleware", "Principal", "principal_of", "require_token"]

F = TypeVar("F", bound=Callable[..., Any])


def _response(error: IAMKitError) -> JsonResponse:
    response = JsonResponse(error_body(error), status=error.status)
    response["Cache-Control"] = "no-store"
    if error.status == 401:
        response["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return response


def _setting(name: str) -> Any:
    value = getattr(settings, name, None)
    return import_string(value) if isinstance(value, str) else value


def principal_of(request: HttpRequest) -> Principal | None:
    """The principal the middleware stored on the request, or ``None``."""
    value: Any = getattr(request, "iamkit", None)
    return value if isinstance(value, Principal) else None


class IAMKitMiddleware:
    """Authenticates bearer tokens (see the module docs for settings)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        verifier = _setting("IAMKIT_VERIFIER")
        if verifier is None:
            raise RuntimeError("IAMKIT_VERIFIER must be set to use IAMKitMiddleware")
        self.get_response = get_response
        self._auth = Authenticator(verifier, _setting("IAMKIT_API_KEYS"))

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request.iamkit = None
        header = request.headers.get("Authorization")
        if header:
            try:
                request.iamkit = self._auth.authenticate(bearer(header))
            except IAMKitError as exc:
                return _response(exc)
        return self.get_response(request)


def require_token(
    *,
    permissions: Iterable[str] = (),
    organization: str | Callable[..., str | None] | None = None,
    mfa: bool = False,
    max_age: float | None = None,
) -> Callable[[F], F]:
    """Decorates a view: needs the middleware's principal (401 without) and checks the requirements.

    ``organization`` is a fixed ID or a function ``(request, *args, **kwargs)`` returning the requested
    organization (e.g. from the URL kwargs).
    """
    wanted = tuple(permissions)

    def decorator(view: F) -> F:
        @functools.wraps(view)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            principal = principal_of(request)
            try:
                if principal is None:
                    raise unauthorized("missing or invalid bearer token")
                tenant = organization(request, *args, **kwargs) if callable(organization) else organization
                check(
                    principal,
                    permissions=wanted,
                    organization=None if organization is None else (tenant or ""),
                    mfa=mfa,
                    max_age=max_age,
                )
            except IAMKitError as exc:
                return _response(exc)
            return view(request, *args, **kwargs)

        return cast(F, wrapper)

    return decorator
