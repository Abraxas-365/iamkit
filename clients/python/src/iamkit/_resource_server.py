"""Resource server (synchronous): verifies the access tokens IAMKit issued for your MCP server or API.

``_aresource_server.py`` (``AsyncResourceServer``) is generated from this file by ``scripts/unasync.py``."""

from __future__ import annotations

from ._resource_core import ResourceClaims, ResourceError, ResourceServerBase
from .errors import IAMKitError


class ResourceServer(ResourceServerBase):
    """A protected resource of IAMKit's OAuth 2.1 authorization server (RFC 9728 / RFC 8707).

    .. code-block:: python

        rs = ResourceServer(
            issuer="https://iam.example.com",
            resource="https://mcp.example.com/mcp",
            environment_id=environment_id,
            scopes_supported=["notes:read"],
        )
        claims = rs.verify(token)          # ResourceClaims, or raises ResourceError
        rs.require(claims, "notes:write")  # 403 insufficient_scope unless granted

    :meth:`verify` raises :class:`ResourceError`; answer it with :meth:`denial` (or :meth:`challenge` for just the
    ``WWW-Authenticate`` value) and serve :meth:`metadata` at ``metadata_paths``. The ASGI and WSGI
    middlewares in :mod:`iamkit.integrations` do all of it.
    """

    def verify(self, token: str) -> ResourceClaims:
        """The claims of an access token for this resource, else a :class:`ResourceError`:
        ``unauthorized`` (no token), ``invalid_token`` (401) or ``temporarily_unavailable`` (503: the signing
        keys or the introspection could not be reached; the token was not judged)."""
        if not token:
            raise self.fail("unauthorized")
        try:
            key = self._keys.get_key(token)
        except IAMKitError as exc:
            raise self._key_failure(exc) from exc
        claims = self._claims(token, key)
        self._check_live(token, claims)
        return claims

    def _check_live(self, token: str, claims: ResourceClaims) -> None:
        """Introspection, when configured: after every local check, and only for tokens that passed them."""
        if self._oauth is None or self._cache is None:
            return
        digest = self._cache.key(token)
        if self._cache.fresh(digest):
            return
        try:
            answer = self._oauth.introspect(token)
        except Exception as exc:  # network, timeout, non-2xx, refused credentials, unreadable answer: fail closed
            raise self.fail("temporarily_unavailable") from exc
        if not self._describes(answer, claims):
            raise self.fail("invalid_token")
        self._cache.keep(digest, claims.exp)

    def close(self) -> None:
        """Closes the HTTP clients this server created (not the ones you passed in)."""
        if self._own_keys:
            self._keys.close()
        if self._oauth is not None:
            self._oauth.close()


__all__ = ["ResourceError", "ResourceServer"]
