"""ASGI integration for MCP servers and APIs: Starlette, FastAPI, FastMCP (``mcp``) and any ASGI app.

.. code-block:: python

    rs = AsyncResourceServer(issuer=..., resource="https://mcp.example.com/mcp", environment_id=...)
    app = ResourceServerMiddleware(starlette_app, rs, public_paths=["/health"])

The middleware serves the RFC 9728 metadata at ``/.well-known/oauth-protected-resource[/path]``, answers requests
without a valid token for the resource with the 401 challenge (``resource_metadata``) and passes the others on with
the verified :class:`ResourceClaims` in ``scope["state"]["iamkit"]`` (``request.state.iamkit`` in Starlette) and the
``Authorization`` header removed: the app never sees, and cannot forward, the client's token. ``OPTIONS`` requests
pass through unchecked (CORS preflights carry no token). No third-party dependency.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

from .._aresource_server import AsyncResourceServer
from .._resource_core import HttpReply, ResourceClaims, ResourceError, bearer_token

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

__all__ = ["ResourceServerMiddleware", "claims_of", "send_reply"]


def claims_of(scope: Scope) -> ResourceClaims | None:
    """The verified claims the middleware stored for this request, or ``None``."""
    value = (scope.get("state") or {}).get("iamkit")
    return value if isinstance(value, ResourceClaims) else None


async def send_reply(send: Send, reply: HttpReply, *, head: bool = False) -> None:
    """Sends a complete :class:`HttpReply` (``head`` drops the body)."""
    headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in reply.headers]
    await send({"type": "http.response.start", "status": reply.status, "headers": headers})
    await send({"type": "http.response.body", "body": b"" if head else reply.body})


async def deny(
    server: AsyncResourceServer, error: ResourceError, scope: Scope, send: Send, scopes: Iterable[str] = ()
) -> None:
    """Answers ``error`` as an HTTP response (or closes a WebSocket with policy violation, 1008)."""
    if scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": 1008})
        return
    await send_reply(send, server.denial(error, scopes))


class ResourceServerMiddleware:
    """Protects an ASGI app as a resource server.

    ``required_scopes`` must all be granted on every protected request (finer rules, per route or per tool, call
    ``server.require`` with :func:`claims_of`). ``public_paths`` are served without a token (a health check).
    """

    def __init__(
        self,
        app: ASGIApp,
        server: AsyncResourceServer,
        *,
        required_scopes: Iterable[str] = (),
        public_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.server = server
        self.required_scopes = tuple(required_scopes)
        self.public_paths = frozenset(public_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind not in ("http", "websocket"):  # lifespan
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        method = scope.get("method", "GET") if kind == "http" else "GET"
        if kind == "http" and path in self.server.metadata_paths:
            await send_reply(send, self.server.metadata_reply(method), head=method == "HEAD")
            return
        if path in self.public_paths or method == "OPTIONS":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        authorization = next((v.decode("latin-1") for k, v in headers if k == b"authorization"), None)
        try:
            claims = await self.server.verify(bearer_token(authorization) or "")
            self.server.require(claims, *self.required_scopes)
        except ResourceError as exc:
            await deny(self.server, exc, scope, send, self.required_scopes)
            return
        inner = dict(scope)
        inner["headers"] = [(k, v) for k, v in headers if k != b"authorization"]
        inner["state"] = {**(scope.get("state") or {}), "iamkit": claims}
        await self.app(inner, receive, send)
