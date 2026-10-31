from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from iamkit import AsyncIAMKit, IAMKit

BASE = "https://iam.test"
KEY = "ik_mgmt_" + "x" * 8
URL = f"{BASE}/management/v1/environments/env-1/event-retention"
ANSWER = {
    "security_retention_seconds": 2592000,
    "default_retention_seconds": None,
    "ceilings": {"security": 31536000, "default": 7776000},
    "effective": {"security": 2592000, "default": 7776000},
}


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.read())


@respx.mock
def test_get_and_set() -> None:
    iam = IAMKit(BASE, KEY, environment_id="env-1")
    respx.get(URL).respond(200, json=ANSWER)
    assert iam.event_retention.get()["effective"]["security"] == 2592000
    put = respx.put(URL).respond(200, json=ANSWER)
    iam.event_retention.set(security_retention_seconds=2592000)
    assert body(put) == {"security_retention_seconds": 2592000, "default_retention_seconds": None}


@respx.mock
@pytest.mark.asyncio
async def test_async_get_and_set() -> None:
    iam = AsyncIAMKit(BASE, KEY, environment_id="env-1")
    respx.get(URL).respond(200, json=ANSWER)
    assert (await iam.event_retention.get())["ceilings"]["default"] == 7776000
    put = respx.put(URL).respond(200, json=ANSWER)
    await iam.event_retention.set(default_retention_seconds=86400)
    assert body(put) == {"security_retention_seconds": None, "default_retention_seconds": 86400}
