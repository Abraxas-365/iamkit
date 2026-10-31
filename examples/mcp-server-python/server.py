"""A remote MCP server (Streamable HTTP, stateless) protected by IAMKit.

IAMKit is the OAuth 2.1 authorization server. This server publishes its protected resource metadata (RFC 9728),
accepts only access tokens issued for its URL (RFC 8707 ``aud``) and asks for more scope with a 403
``insufficient_scope`` challenge when a tool needs it. Scopes are the IAMKit permissions of the resource:
``notes:read`` and ``notes:write``.

    IAMKIT_ISSUER=https://iam.example.com IAMKIT_ENVIRONMENT_ID=... uv run python server.py
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

import uvicorn
from iamkit import KeySet
from iamkit.integrations.asgi import ResourceServerMiddleware, claims_of
from iamkit.resource_server import AsyncResourceServer, IntrospectionOptions, ResourceClaims
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from scopes import ToolScopes

# Notes per organization: what a user sees follows the token's tenant.
NOTES: dict[str, list[dict[str, str]]] = {}


def setting(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def claims(ctx: Context) -> ResourceClaims:
    """The verified claims of the request the tool runs for (the middleware put them there)."""
    request = ctx.request_context.request
    assert isinstance(request, Request)
    found = claims_of(request.scope)
    if found is None:  # unreachable behind the middleware
        raise PermissionError("no verified token")
    return found


def build_mcp(path: str, allowed_host: str) -> FastMCP:
    mcp = FastMCP(
        "iamkit-notes",
        # Stateless: every POST stands alone, bound to the claims of its own token.
        stateless_http=True,
        json_response=True,
        streamable_http_path=path,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", allowed_host],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "https://*"],
        ),
    )

    @mcp.tool()
    def list_notes(ctx: Context) -> str:
        """List the notes of your organization (scope notes:read)."""
        notes = NOTES.get(claims(ctx).organization_id, [])
        if not notes:
            return "No notes yet."
        return "\n".join(f"- {n['text']} ({n['by']}, {n['at']})" for n in notes)

    @mcp.tool()
    def add_note(text: str, ctx: Context) -> str:
        """Add a note to your organization (scope notes:write)."""
        who = claims(ctx)
        text = text.strip()
        if not 0 < len(text) <= 500:
            raise ValueError("text must have 1 to 500 characters")
        notes = NOTES.setdefault(who.organization_id, [])
        notes.append({"by": who.sub, "text": text, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        return f"Added. {len(notes)} note(s) now."

    @mcp.tool()
    def whoami(ctx: Context) -> dict[str, object]:
        """Show the token's subject, organization and scopes (any valid token)."""
        who = claims(ctx)
        return {
            "user": who.sub,
            "organization": who.organization_id,
            "client": who.oauth_client_id,
            "scopes": list(who.scopes),
        }

    return mcp


def create_app() -> ResourceServerMiddleware:
    issuer = setting("IAMKIT_ISSUER")
    resource_url = setting("MCP_RESOURCE_URL", "http://localhost:3333/mcp")
    introspection = None
    if os.environ.get("IAMKIT_INTROSPECTION_CLIENT_ID"):
        # Also ask IAMKit whether each token is still live: a disconnected client stops at once (fails closed).
        introspection = IntrospectionOptions(
            client_id=setting("IAMKIT_INTROSPECTION_CLIENT_ID"),
            client_secret=setting("IAMKIT_INTROSPECTION_CLIENT_SECRET"),
            cache_ttl=float(os.environ.get("IAMKIT_INTROSPECTION_CACHE_TTL", "0")),
            base_url=os.environ.get("IAMKIT_INTROSPECTION_URL"),
        )
    jwks_url = os.environ.get("IAMKIT_JWKS_URL")
    rs = AsyncResourceServer(
        issuer=issuer,
        resource=resource_url,
        environment_id=setting("IAMKIT_ENVIRONMENT_ID"),
        # The scopes a client asks for first (the protected resource's default_scopes): notes:write comes later,
        # by step-up.
        scopes_supported=["notes:read"],
        resource_name="IAMKit notes (example MCP server)",
        # Where this server reaches IAMKit's keys, when that differs from the issuer.
        keys=KeySet(jwks_url=jwks_url) if jwks_url else None,
        introspection=introspection,
    )
    parts = urlsplit(rs.resource)
    mcp = build_mcp(parts.path or "/", parts.netloc)
    app = mcp.streamable_http_app()

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    app.add_route("/health", health)
    # Outermost: metadata, then the token, then the scope the tool needs, then the MCP transport.
    return ResourceServerMiddleware(ToolScopes(app, rs), rs, public_paths=["/health"])


if __name__ == "__main__":
    app = create_app()
    port = int(setting("PORT", "3333"))
    print(f"MCP server on http://127.0.0.1:{port}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
