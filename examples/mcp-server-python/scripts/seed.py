"""Seeds a disposable IAMKit for the example MCP server through the management API and prints the fixture JSON.

    IAMKIT_URL=... MGMT=... MCP_RESOURCE_URL=... python scripts/seed.py > fixture.json

Standard library only: it runs with any Python 3.10+ (trust a self-signed IAMKit with SSL_CERT_FILE).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

BASE = os.environ["IAMKIT_URL"].rstrip("/")
KEY = os.environ["MGMT"]
RESOURCE_URL = os.environ["MCP_RESOURCE_URL"]
PASSWORD = "Mcp-example-password-2026!"


def call(method: str, path: str, body: Any = None) -> Any:
    request = urllib.request.Request(
        f"{BASE}/management/v1{path}",
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"X-API-Key": KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw and "json" in response.headers.get("content-type", "") else None
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} {path}: {error.code} {error.read().decode()}") from error


def created(response: Any) -> str:
    return str(response.get("id") or response.get("client_id"))


def main() -> None:
    project = created(call("POST", "/projects", {"name": "MCP example (Python)"}))
    environment = created(call("POST", f"/projects/{project}/environments", {"name": "Development"}))
    env = f"/environments/{environment}"
    organization = created(call("POST", f"{env}/organizations", {"name": "Acme"}))

    # The MCP server is a resource whose audience is its URL, with one permission per scope, registered as a
    # protected resource of the application its clients belong to.
    application = created(call("POST", f"{env}/applications", {"name": "Notes MCP"}))
    resource = created(
        call(
            "POST",
            f"{env}/resources",
            {
                "name": "Notes MCP server",
                "prefix": "notes",
                "audience": RESOURCE_URL,
                "permissions": ["notes:read", "notes:write"],
            },
        )
    )
    call("POST", f"{env}/application-resources", {"application_id": application, "resource_id": resource})
    protected_resource = created(
        call(
            "POST",
            f"{env}/protected-resources",
            {
                "application_id": application,
                "resource_id": resource,
                "name": "Notes",
                "default_scopes": ["notes:read"],
            },
        )
    )

    def client(name: str, redirects: list[str]) -> str:
        return created(
            call(
                "POST",
                f"{env}/oauth-clients",
                {
                    "name": name,
                    "application_id": application,
                    "resource_id": resource,
                    "redirect_uris": redirects,
                    "public": True,
                    "hosted_login": True,
                },
            )
        )

    # Pre-registered public clients: MCP Inspector's default callback and a fixed Claude Code callback port.
    inspector = client(
        "MCP Inspector",
        ["http://127.0.0.1:6276/oauth/callback", "http://localhost:6274/oauth/callback"],
    )
    claude = client("Claude Code", ["http://localhost:19876/callback", "http://127.0.0.1:19876/callback"])

    # A confidential client lets the server introspect tokens (IAMKIT_INTROSPECTION_CLIENT_ID / _SECRET).
    confidential = call(
        "POST",
        f"{env}/oauth-clients",
        {
            "name": "Notes MCP introspection",
            "application_id": application,
            "resource_id": resource,
            "redirect_uris": ["https://localhost/unused"],
        },
    )

    def user(name: str, email: str, permissions: list[str]) -> str:
        user_id = created(call("POST", f"{env}/users", {"name": name, "email": email, "password": PASSWORD}))
        call("POST", f"{env}/memberships", {"organization_id": organization, "user_id": user_id})
        call(
            "PUT",
            f"{env}/grants",
            {
                "organization_id": organization,
                "user_id": user_id,
                "resource_id": resource,
                "permissions": permissions,
            },
        )
        return user_id

    reader = user("Riley Reader", "reader@mcp.example", ["notes:read"])
    writer = user("Wren Writer", "writer@mcp.example", ["notes:read", "notes:write"])

    json.dump(
        {
            "environment": environment,
            "organization": organization,
            "application": application,
            "resource": resource,
            "protectedResource": protected_resource,
            "inspectorClientId": inspector,
            "claudeClientId": claude,
            "introspectionClientId": confidential["client_id"],
            "introspectionClientSecret": confidential["client_secret"],
            "reader": reader,
            "writer": writer,
            "email": "reader@mcp.example",
            "writerEmail": "writer@mcp.example",
            "password": PASSWORD,
        },
        sys.stdout,
        indent=2,
    )


if __name__ == "__main__":
    main()
