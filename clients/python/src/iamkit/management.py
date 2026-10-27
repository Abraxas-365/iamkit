"""The management clients: :class:`IAMKit` (sync) and :class:`AsyncIAMKit`, over ``/management/v1``.

Authenticated with a management key (``ik_mgmt_…``, sent as ``X-API-Key``): keep it server-side. Resources
hang off the client (``iam.users``, ``iam.organizations``, ``iam.roles``, ``iam.api_keys``, ``iam.events``,
``iam.webhooks``, ``iam.audit_logs``, ``iam.risk``, ``iam.waitlist``) and
:meth:`IAMKit.request` reaches any other route.
Answers are the decoded JSON documents (fields as in ``api/openapi.json``).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from types import TracebackType
from typing import Any

import httpx

from . import _aresources as a
from . import _resources as r
from ._core import AsyncCore, Core
from ._http import Transport
from .errors import invalid_argument


class IAMKit:
    """Synchronous management client.

    ``environment_id`` selects the environment of the resources below (a deployment can serve several);
    pass ``client=`` to reuse an ``httpx.Client`` (proxies, mTLS, tests).
    """

    def __init__(
        self,
        base_url: str,
        management_key: str,
        *,
        environment_id: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not management_key:
            raise invalid_argument("management_key is required")
        self._core = Core(Transport(base_url, client=client, timeout=timeout), management_key, environment_id)
        self.users = r.Users(self._core)
        self.organizations = r.Organizations(self._core)
        self.roles = r.Roles(self._core)
        self.api_keys = r.APIKeys(self._core)
        self.events = r.Events(self._core)
        self.webhooks = r.Webhooks(self._core)
        self.audit_logs = r.AuditLogs(self._core)
        self.risk = r.Risk(self._core)
        self.waitlist = r.Waitlist(self._core)
        self.protected_resources = r.ProtectedResources(self._core)

    @property
    def environment_id(self) -> str | None:
        return self._core.environment_id

    @environment_id.setter
    def environment_id(self, value: str | None) -> None:
        self._core.environment_id = value

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Calls any route: ``path`` is relative to the deployment (``/management/v1/...``); ``X-API-Key`` is added.

        Answers the decoded JSON (``None`` for 204). Use :meth:`environment_path` for environment routes.
        """
        return self._core.request(method, path, params=params, json=json, headers=headers)

    def environment_path(self, suffix: str = "") -> str:
        """``/management/v1/environments/<environment_id>`` + ``suffix``."""
        return self._core.env() + suffix

    def close(self) -> None:
        self._core.t.close()

    def __enter__(self) -> IAMKit:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()


class AsyncIAMKit:
    """Asynchronous management client (same resources and arguments as :class:`IAMKit`, awaitable)."""

    def __init__(
        self,
        base_url: str,
        management_key: str,
        *,
        environment_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not management_key:
            raise invalid_argument("management_key is required")
        self._core = AsyncCore(
            Transport(base_url, async_client=client, timeout=timeout), management_key, environment_id
        )
        self.users = a.Users(self._core)
        self.organizations = a.Organizations(self._core)
        self.roles = a.Roles(self._core)
        self.api_keys = a.APIKeys(self._core)
        self.events = a.Events(self._core)
        self.webhooks = a.Webhooks(self._core)
        self.audit_logs = a.AuditLogs(self._core)
        self.risk = a.Risk(self._core)
        self.waitlist = a.Waitlist(self._core)
        self.protected_resources = a.ProtectedResources(self._core)

    @property
    def environment_id(self) -> str | None:
        return self._core.environment_id

    @environment_id.setter
    def environment_id(self, value: str | None) -> None:
        self._core.environment_id = value

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        return await self._core.request(method, path, params=params, json=json, headers=headers)

    def environment_path(self, suffix: str = "") -> str:
        return self._core.env() + suffix

    async def aclose(self) -> None:
        await self._core.t.aclose()

    async def __aenter__(self) -> AsyncIAMKit:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.aclose()


def paginate(fetch: Callable[[int, int], Mapping[str, Any]], *, page_size: int = 200) -> Iterator[Any]:
    """Walks any offset-paged list endpoint: ``fetch(limit, offset)`` returns ``{"items", "page": {"total"}}``.

    >>> list(paginate(lambda limit, offset: iam.users.list(limit=limit, offset=offset)))  # doctest: +SKIP
    """
    offset = 0
    while True:
        page = fetch(page_size, offset)
        items = page.get("items") or []
        yield from items
        offset += len(items)
        if not items or offset >= (page.get("page") or {}).get("total", 0):
            return
