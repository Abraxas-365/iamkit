"""The scope each tool needs, and an ASGI layer that checks it before the MCP transport runs.

A tool that needs more than the token grants must answer ``403 insufficient_scope`` with the scopes to ask for, so
the client authorizes again (step-up). That is an HTTP answer, so it is decided here, on the JSON-RPC body of the
``tools/call`` request, not inside the tool.
"""

from __future__ import annotations

import json
from typing import Any

from iamkit.integrations.asgi import Receive, Scope, Send, claims_of, send_reply
from iamkit.resource_server import AsyncResourceServer, ResourceError

TOOL_SCOPES: dict[str, str] = {
    "list_notes": "notes:read",
    "add_note": "notes:write",
}

MAX_BODY = 1 << 20


def scopes_for(body: Any) -> list[str]:
    """The scopes a JSON-RPC message (or batch) needs beyond a valid token."""
    messages = body if isinstance(body, list) else [body]
    needed: dict[str, None] = {}
    for message in messages:
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            continue
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if isinstance(name, str) and name in TOOL_SCOPES:
            needed[TOOL_SCOPES[name]] = None
    return list(needed)


class ToolScopes:
    """Requires, for each ``tools/call``, the scopes of the tool. Runs behind ``ResourceServerMiddleware``."""

    def __init__(self, app: Any, server: AsyncResourceServer) -> None:
        self.app = app
        self.server = server

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        claims = claims_of(scope)
        if scope["type"] != "http" or scope.get("method") != "POST" or claims is None:
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":  # disconnect
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            chunks.append(chunk)
            more = message.get("more_body", False)
            if size > MAX_BODY:
                await self.app(scope, _replay(chunks, receive), send)  # the transport rejects what is too large
                return
        body = b"".join(chunks)
        try:
            needed = scopes_for(json.loads(body))
        except ValueError:
            needed = []  # not JSON: the transport answers the protocol error
        try:
            self.server.require(claims, *needed)
        except ResourceError as exc:
            await send_reply(send, self.server.denial(exc, needed))
            return
        await self.app(scope, _replay([body], receive), send)


def _replay(chunks: list[bytes], receive: Receive) -> Receive:
    """A ``receive`` that hands the body that was read, then whatever the client sends next (disconnect)."""
    pending = list(chunks)

    async def replay() -> Any:
        if pending:
            body = pending.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(pending)}
        return await receive()

    return replay
