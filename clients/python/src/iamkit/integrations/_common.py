"""Framework-independent parts of the integrations: bearer parsing, principals and permission checks."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ..apikeys import APIKey, APIKeyValidator, has_api_key_permission, is_api_key
from ..errors import IAMKitError, unauthorized
from ..tokens import AccessClaims, has_permission, has_recent_mfa


@dataclass(frozen=True)
class Principal:
    """Who made the request: an access token's ``claims`` or an ``api_key`` (never both)."""

    claims: AccessClaims | None = None
    api_key: APIKey | None = None

    @property
    def organization_id(self) -> str | None:
        """The tenant: the token's organization (application tokens) or the key's."""
        if self.api_key is not None:
            return self.api_key.organization_id or None
        if self.claims is not None and self.claims.purpose == "application":
            return self.claims.organization_id
        return None

    def has_permission(self, *permissions: str) -> bool:
        if self.api_key is not None:
            return has_api_key_permission(self.api_key, *permissions)
        return self.claims is not None and has_permission(self.claims, *permissions)


def bearer(header: str | None) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` header, or ``None``."""
    parts = (header or "").split()
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None


def check(
    principal: Principal,
    *,
    permissions: Iterable[str] = (),
    organization: str | None = None,
    mfa: bool = False,
    max_age: float | None = None,
) -> None:
    """Raises a 403 :class:`IAMKitError` unless the principal meets every requirement.

    ``organization`` is the tenant the request touches, from a trusted source; a route parameter is never
    authority on its own. Machine tokens have no organization and are refused when one is required.
    """
    wanted = tuple(permissions)
    if wanted and not principal.has_permission(*wanted):
        raise IAMKitError(403, "FORBIDDEN", "missing permission")
    if organization is not None and (not organization or principal.organization_id != organization):
        raise IAMKitError(403, "FORBIDDEN", "organization mismatch")
    if mfa and (principal.claims is None or not has_recent_mfa(principal.claims, max_age)):
        raise IAMKitError(403, "STEP_UP_REQUIRED", "a recent second factor is required")


def error_body(error: IAMKitError) -> dict[str, Any]:
    return {"error": {"code": error.code, "message": error.message}}


def public_error(error: IAMKitError) -> IAMKitError:
    """What a client may see: a 5xx from verification is an outage (503), not a detail."""
    if error.status >= 500:
        return IAMKitError(503, "UNAVAILABLE", "token verification unavailable")
    if error.status == 401:
        return unauthorized("invalid or expired token")
    return error


class Authenticator:
    """Resolves a bearer value to a :class:`Principal` with a verifier (sync and async)."""

    def __init__(self, verifier: Any, api_keys: APIKeyValidator | None = None) -> None:
        self.verifier = verifier
        self.api_keys = api_keys

    def _refuse_key(self) -> IAMKitError:
        return unauthorized("invalid or expired token")

    def authenticate(self, token: str | None) -> Principal:
        if not token:
            raise unauthorized("missing or invalid bearer token")
        try:
            if is_api_key(token):
                if self.api_keys is None:
                    raise self._refuse_key()
                return Principal(api_key=self.api_keys.validate(token))
            return Principal(claims=self.verifier.verify(token))
        except IAMKitError as exc:
            raise public_error(exc) from exc

    async def aauthenticate(self, token: str | None) -> Principal:
        if not token:
            raise unauthorized("missing or invalid bearer token")
        try:
            if is_api_key(token):
                if self.api_keys is None:
                    raise self._refuse_key()
                return Principal(api_key=await self.api_keys.avalidate(token))
            return Principal(claims=await self.verifier.averify(token))
        except IAMKitError as exc:
            raise public_error(exc) from exc


Resolver = Callable[..., str | None]
