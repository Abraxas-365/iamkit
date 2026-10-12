"""API key validation: ``ik_key_`` values are not JWTs, they are validated online by introspection."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from ._http import Transport
from .errors import IAMKitError, invalid_argument, unauthorized

#: Every API key value starts with this prefix.
API_KEY_PREFIX = "ik_key_"


def is_api_key(value: str) -> bool:
    """Whether ``value`` looks like an API key (not that it is valid)."""
    return value.startswith(API_KEY_PREFIX)


@dataclass(frozen=True)
class APIKeyOwner:
    """Whose key it is: a person (``user``), an ``organization`` or a ``machine`` user."""

    type: str
    #: The user; absent on organization keys.
    id: str | None = None
    organization_id: str = ""


@dataclass(frozen=True)
class APIKey:
    """An API key IAMKit confirmed on a request."""

    id: str
    name: str
    owner: APIKeyOwner
    organization_id: str
    resource_id: str
    #: Effective permissions right now: never empty on a valid key.
    permissions: tuple[str, ...]
    #: Unix seconds when the key stops working; 0 = never.
    expires_at: int

    def has_permission(self, *permissions: str) -> bool:
        return has_api_key_permission(self, *permissions)


def has_api_key_permission(key: APIKey, *permissions: str) -> bool:
    """Whether the key carries every one of ``permissions`` (exact strings)."""
    return len(permissions) > 0 and all(p != "" and p in key.permissions for p in permissions)


class APIKeyValidator:
    """Validates API key values online with ``POST /identity/v1/introspect``, sending the environment and
    audience: revocation, expiry, the policy and the owner's standing take effect at once.

    Non-``ik_key_`` values are refused locally; an inactive key raises 401 ``UNAUTHORIZED``; an unreachable
    IAMKit raises its own error — fail closed.
    """

    def __init__(
        self,
        base_url: str,
        environment_id: str,
        audience: str,
        *,
        client: httpx.Client | None = None,
        async_client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not (environment_id and audience):
            raise invalid_argument("environment_id and audience are required")
        self.environment_id = environment_id
        self.audience = audience
        self._http = Transport(base_url, client=client, async_client=async_client, timeout=timeout)

    def _body(self) -> dict[str, str]:
        return {"environment_id": self.environment_id, "audience": self.audience}

    def validate(self, value: str) -> APIKey:
        if not is_api_key(value):
            raise unauthorized("invalid API key")
        try:
            answer = self._http.request("POST", "/identity/v1/introspect", json=self._body(), token=value)
        except IAMKitError as exc:
            raise (unauthorized("inactive API key") if exc.status == 401 else exc) from exc
        return self._key(answer)

    async def avalidate(self, value: str) -> APIKey:
        if not is_api_key(value):
            raise unauthorized("invalid API key")
        try:
            answer = await self._http.arequest("POST", "/identity/v1/introspect", json=self._body(), token=value)
        except IAMKitError as exc:
            raise (unauthorized("inactive API key") if exc.status == 401 else exc) from exc
        return self._key(answer)

    def _key(self, answer: Any) -> APIKey:
        invalid = unauthorized("invalid or inactive API key")
        claims = answer.get("claims") if isinstance(answer, dict) else None
        if not isinstance(claims, dict) or not answer.get("active"):
            raise invalid
        key = claims.get("api_key")
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
        permissions = key.get("permissions") if isinstance(key, dict) else None
        if (
            not isinstance(key, dict)
            or claims.get("purpose") != "api_key"
            or claims.get("environment_id") != self.environment_id
            or self.audience not in audiences
            or not key.get("id")
            or not isinstance(permissions, list)
            or not permissions
        ):
            raise invalid
        expires_at = key.get("expires_at") or 0
        if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
            raise invalid
        if expires_at > 0 and expires_at <= time.time():
            raise invalid
        raw_owner = key.get("owner")
        owner_raw: dict[str, Any] = raw_owner if isinstance(raw_owner, dict) else {}
        organization = owner_raw.get("organization_id") or claims.get("organization_id") or ""
        return APIKey(
            id=str(key["id"]),
            name=str(key.get("name") or ""),
            owner=APIKeyOwner(
                type=str(owner_raw.get("type") or ""),
                id=owner_raw.get("id") or None,
                organization_id=organization,
            ),
            organization_id=organization,
            resource_id=str(key.get("resource_id") or claims.get("resource_id") or ""),
            permissions=tuple(str(p) for p in permissions),
            expires_at=int(expires_at),
        )

    def close(self) -> None:
        self._http.close()

    async def aclose(self) -> None:
        await self._http.aclose()


def validate_api_key(
    value: str,
    base_url: str,
    environment_id: str,
    audience: str,
    *,
    client: httpx.Client | None = None,
) -> APIKey:
    """One-shot form of ``APIKeyValidator(...).validate(value)``."""
    validator = APIKeyValidator(base_url, environment_id, audience, client=client)
    try:
        return validator.validate(value)
    finally:
        validator.close()


async def avalidate_api_key(
    value: str,
    base_url: str,
    environment_id: str,
    audience: str,
    *,
    async_client: httpx.AsyncClient | None = None,
) -> APIKey:
    validator = APIKeyValidator(base_url, environment_id, audience, async_client=async_client)
    try:
        return await validator.avalidate(value)
    finally:
        await validator.aclose()
