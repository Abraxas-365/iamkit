"""Request cores behind the management clients (sync and async)."""

from __future__ import annotations

import builtins
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any

from ._common import seg
from ._http import Transport
from .errors import invalid_argument

JSON = dict[str, Any]
JSONList = builtins.list[dict[str, Any]]


class _Base:
    def __init__(self, transport: Transport, key: str, environment_id: str | None) -> None:
        self.t = transport
        self.key = key
        self.environment_id = environment_id

    def env(self, environment_id: str | None = None) -> str:
        """``/management/v1/environments/<id>`` of the client's (or the given) environment."""
        chosen = environment_id or self.environment_id
        if not chosen:
            raise invalid_argument("environment_id is required for environment resources")
        return f"/management/v1/environments/{seg(chosen, 'environment id')}"

    def headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        return {"X-API-Key": self.key, **(extra or {})}


class Core(_Base):
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        return self.t.request(method, path, params=params, json=json, headers=self.headers(headers))

    def stream(self, path: str, params: Mapping[str, Any] | None = None) -> Iterator[str]:
        return self.t.stream_lines(path, params=params, headers=self.headers())


class AsyncCore(_Base):
    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        return await self.t.arequest(method, path, params=params, json=json, headers=self.headers(headers))

    def stream(self, path: str, params: Mapping[str, Any] | None = None) -> AsyncIterator[str]:
        return self.t.astream_lines(path, params=params, headers=self.headers())
