"""HTTP transport shared by the SDK: sync and async over httpx, no redirects, 1 MiB cap."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any
from urllib.parse import quote

import httpx

from .errors import IAMKitError

#: Response bodies larger than this are refused (1 MiB).
MAX_BODY = 1 << 20

DEFAULT_TIMEOUT = 10.0

Params = Mapping[str, Any]


def segment(value: str, what: str = "id") -> str:
    """A path segment: URL-encoded, never empty and never a traversal."""
    if not value or value in (".", ".."):
        raise IAMKitError(400, "VALIDATION", f"invalid {what}")
    return quote(value, safe="")


def clean_params(params: Params | None) -> dict[str, str]:
    """Query parameters without empty values; booleans as ``true``/``false``."""
    out: dict[str, str] = {}
    for key, value in (params or {}).items():
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            out[key] = "true" if value else "false"
        elif isinstance(value, (list, tuple)):
            out[key] = ",".join(str(v) for v in value)
        else:
            out[key] = str(value)
    return out


def _decode(response: httpx.Response) -> Any:
    length = response.headers.get("content-length", "0")
    if length.isdigit() and int(length) > MAX_BODY:
        raise IAMKitError.from_response(response.status_code if response.status_code >= 400 else 502, None)
    content = response.content
    if len(content) > MAX_BODY:
        raise IAMKitError.from_response(response.status_code if response.status_code >= 400 else 502, None)
    body: Any = None
    if content:
        try:
            body = json.loads(content)
        except ValueError:
            body = None
    if response.status_code < 200 or response.status_code >= 300:
        raise IAMKitError.from_response(response.status_code, body)
    return body


class Transport:
    """Sends requests to ``base_url + path`` and decodes JSON answers (``None`` for 204).

    Pass ``client`` / ``async_client`` to reuse your own httpx clients (proxies,
    mTLS, tests); otherwise one is created lazily and closed by :meth:`close` /
    :meth:`aclose`. Credentials never follow redirects.
    """

    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.Client | None = None,
        async_client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client
        self._aclient = async_client
        self._own_client = client is None
        self._own_aclient = async_client is None

    # -- clients ----------------------------------------------------------------------------
    def _sync(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, follow_redirects=False)
        return self._client

    def _async(self) -> httpx.AsyncClient:
        if self._aclient is None:
            self._aclient = httpx.AsyncClient(timeout=self.timeout, follow_redirects=False)
        return self._aclient

    def close(self) -> None:
        if self._client is not None and self._own_client:
            self._client.close()
            self._client = None

    async def aclose(self) -> None:
        if self._aclient is not None and self._own_aclient:
            await self._aclient.aclose()
            self._aclient = None

    # -- requests ---------------------------------------------------------------------------
    def _build(
        self,
        method: str,
        path: str,
        params: Params | None,
        json_body: Any,
        form: Mapping[str, str] | None,
        headers: Mapping[str, str] | None,
        token: str | None,
    ) -> dict[str, Any]:
        merged: dict[str, str] = {"Accept": "application/json"}
        if token:
            merged["Authorization"] = f"Bearer {token}"
        merged.update(headers or {})
        kwargs: dict[str, Any] = {"headers": merged}
        query = clean_params(params)
        if query:
            kwargs["params"] = query
        if json_body is not None:
            kwargs["json"] = json_body
        if form is not None:
            kwargs["data"] = dict(form)
        kwargs["method"] = method
        kwargs["url"] = self.base_url + path
        return kwargs

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Params | None = None,
        json: Any = None,
        form: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
    ) -> Any:
        response = self._sync().request(**self._build(method, path, params, json, form, headers, token))
        return _decode(response)

    async def arequest(
        self,
        method: str,
        path: str,
        *,
        params: Params | None = None,
        json: Any = None,
        form: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
    ) -> Any:
        response = await self._async().request(**self._build(method, path, params, json, form, headers, token))
        return _decode(response)

    def stream_lines(
        self,
        path: str,
        *,
        params: Params | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
    ) -> Iterator[str]:
        """GETs a streamed body (exports) line by line; no read timeout applies to the body."""
        kwargs = self._build("GET", path, params, None, None, headers, token)
        with self._sync().stream(**kwargs) as response:
            if response.status_code < 200 or response.status_code >= 300:
                response.read()
                _decode(response)
            for line in response.iter_lines():
                if line.strip():
                    yield line

    async def astream_lines(
        self,
        path: str,
        *,
        params: Params | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
    ) -> AsyncIterator[str]:
        kwargs = self._build("GET", path, params, None, None, headers, token)
        async with self._async().stream(**kwargs) as response:
            if response.status_code < 200 or response.status_code >= 300:
                await response.aread()
                _decode(response)
            async for line in response.aiter_lines():
                if line.strip():
                    yield line
