"""WSGI integration for Flask, Django and any WSGI app (``ResourceServer``, synchronous).

.. code-block:: python

    rs = ResourceServer(issuer=..., resource="https://api.example.com/mcp", environment_id=...)
    app.wsgi_app = ResourceServerWSGIMiddleware(app.wsgi_app, rs)            # Flask
    application = ResourceServerWSGIMiddleware(get_wsgi_application(), rs)   # Django (wsgi.py)

Same contract as the ASGI middleware: it serves the RFC 9728 metadata, answers the 401/403/503 itself, removes
``Authorization`` and puts the :class:`ResourceClaims` in ``environ["iamkit.claims"]`` (``request.environ`` in
Flask, ``request.META`` in Django): :func:`claims_of` reads them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from .._resource_core import HttpReply, ResourceClaims, ResourceError, bearer_token
from .._resource_server import ResourceServer

Environ = dict[str, Any]
StartResponse = Callable[..., Any]
WSGIApp = Callable[[Environ, StartResponse], Iterable[bytes]]

__all__ = ["ResourceServerWSGIMiddleware", "claims_of"]

ENVIRON_KEY = "iamkit.claims"


def claims_of(environ: Environ) -> ResourceClaims | None:
    """The verified claims the middleware stored for this request, or ``None``."""
    value = environ.get(ENVIRON_KEY)
    return value if isinstance(value, ResourceClaims) else None


def _respond(start_response: StartResponse, reply: HttpReply, *, head: bool = False) -> list[bytes]:
    start_response(reply.status_line, list(reply.headers))
    return [] if head or not reply.body else [reply.body]


class ResourceServerWSGIMiddleware:
    """Protects a WSGI app as a resource server (see the module docstring)."""

    def __init__(
        self,
        app: WSGIApp,
        server: ResourceServer,
        *,
        required_scopes: Iterable[str] = (),
        public_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.server = server
        self.required_scopes = tuple(required_scopes)
        self.public_paths = frozenset(public_paths)

    def __call__(self, environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        if path in self.server.metadata_paths:
            return _respond(start_response, self.server.metadata_reply(method), head=method == "HEAD")
        if path in self.public_paths or method == "OPTIONS":
            return self.app(environ, start_response)
        try:
            claims = self.server.verify(bearer_token(environ.get("HTTP_AUTHORIZATION")) or "")
            self.server.require(claims, *self.required_scopes)
        except ResourceError as exc:
            return _respond(start_response, self.server.denial(exc, self.required_scopes))
        inner = dict(environ)
        inner.pop("HTTP_AUTHORIZATION", None)
        inner[ENVIRON_KEY] = claims
        return self.app(inner, start_response)
