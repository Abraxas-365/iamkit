"""Optional framework integrations; import the one you use (each needs its extra):

* :mod:`iamkit.integrations.fastapi` — ``iamkit[fastapi]``
* :mod:`iamkit.integrations.flask` — ``iamkit[flask]``
* :mod:`iamkit.integrations.django` — ``iamkit[django]``

For resource servers (MCP servers, APIs that accept tokens issued for them):

* :mod:`iamkit.integrations.asgi` — ``ResourceServerMiddleware`` (Starlette, FastAPI, FastMCP); no extra
* :mod:`iamkit.integrations.fastapi` — also ``require_scopes``, a dependency for resource servers
* :mod:`iamkit.integrations.wsgi` — ``ResourceServerWSGIMiddleware`` (Flask, Django); no extra
"""
