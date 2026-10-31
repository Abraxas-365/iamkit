from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from iamkit.integrations.asgi import ResourceServerMiddleware
from iamkit.resource_server import AsyncResourceServer, ResourceClaims

from scopes import ToolScopes, scopes_for


def call(name: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}}


def test_scopes_for() -> None:
    assert scopes_for(call("list_notes")) == ["notes:read"]
    assert scopes_for(call("add_note")) == ["notes:write"]
    assert scopes_for(call("whoami")) == []
    assert scopes_for({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) == []
    assert scopes_for([call("list_notes"), call("add_note"), call("list_notes")]) == ["notes:read", "notes:write"]


@pytest.mark.parametrize(
    "body", [None, 3, "x", [], [None], {"method": "tools/call"}, {"method": "tools/call", "params": 1}]
)
def test_scopes_for_ignores_what_is_not_a_tool_call(body: Any) -> None:
    assert scopes_for(body) == []


async def test_tool_scopes_middleware_replays_the_body() -> None:
    rs = AsyncResourceServer("https://iam.test", "http://localhost:3333/mcp", "env-1")
    granted = ResourceClaims("u", "env-1", "o", "a", "r", "s", ("notes:read",), ("notes:read",), 0)
    seen: list[bytes] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        message = await receive()
        seen.append(message["body"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    guarded = ToolScopes(inner, rs)

    async def with_claims(scope: Any, receive: Any, send: Any) -> None:
        scope["state"] = {"iamkit": granted}  # what ResourceServerMiddleware does after verifying the token
        await guarded(scope, receive, send)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=with_claims), base_url="http://t") as http:
        ok = await http.post("/mcp", content=json.dumps(call("list_notes")))
        assert ok.status_code == 200
        assert json.loads(seen[0]) == call("list_notes")
        denied = await http.post("/mcp", content=json.dumps(call("add_note")))
        assert denied.status_code == 403
        assert denied.json() == {"error": "insufficient_scope"}
        assert 'scope="notes:read notes:write"' in denied.headers["www-authenticate"]
        assert len(seen) == 1  # the transport never saw the refused call
        assert (await http.post("/mcp", content="not json")).status_code == 200


async def test_whole_stack_without_token_is_401() -> None:
    from mcp.server.fastmcp import FastMCP

    rs = AsyncResourceServer("https://iam.test", "http://localhost:3333/mcp", "env-1")
    mcp = FastMCP("t", stateless_http=True, streamable_http_path="/mcp")
    app = ResourceServerMiddleware(ToolScopes(mcp.streamable_http_app(), rs), rs)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:3333") as http:
        res = await http.post("/mcp", json=call("whoami"))
        assert res.status_code == 401
        assert "resource_metadata" in res.headers["www-authenticate"]
        meta = await http.get("/.well-known/oauth-protected-resource/mcp")
        assert meta.json()["authorization_servers"] == ["https://iam.test"]
