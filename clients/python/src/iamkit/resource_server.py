"""Protect an MCP server or API as an OAuth 2.1 resource server of IAMKit (RFC 9728 metadata, RFC 8707 audience).

.. code-block:: python

    from iamkit.resource_server import AsyncResourceServer
    from iamkit.integrations.asgi import ResourceServerMiddleware

    rs = AsyncResourceServer(
        issuer="https://iam.example.com",
        resource="https://mcp.example.com/mcp",
        environment_id=environment_id,
        scopes_supported=["notes:read"],
    )
    app = ResourceServerMiddleware(app, rs)      # metadata, 401 challenges, claims in request.state.iamkit

:class:`ResourceServer` (synchronous, for WSGI) and :class:`AsyncResourceServer` (ASGI) are the same server; the
Go SDK (``sdk/resourceserver``) and ``@iamkit/node/resource-server`` behave identically and share the
canonicalization test vectors.
"""

from __future__ import annotations

from ._aresource_server import AsyncResourceServer
from ._resource_core import (
    METADATA_PATH,
    PROTOCOL_SCOPES,
    HttpReply,
    IntrospectionOptions,
    ResourceClaims,
    ResourceError,
    bearer_token,
    canonical_resource,
    metadata_url,
    permissions_of,
)
from ._resource_server import ResourceServer

__all__ = [
    "METADATA_PATH",
    "PROTOCOL_SCOPES",
    "AsyncResourceServer",
    "HttpReply",
    "IntrospectionOptions",
    "ResourceClaims",
    "ResourceError",
    "ResourceServer",
    "bearer_token",
    "canonical_resource",
    "metadata_url",
    "permissions_of",
]
