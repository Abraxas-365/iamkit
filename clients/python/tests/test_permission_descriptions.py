from __future__ import annotations

import json
from typing import Any

import respx

from iamkit import AsyncIAMKit, IAMKit

BASE = "https://iam.test"
KEY = "ik_mgmt_" + "x" * 8
URL = f"{BASE}/management/v1/environments/env-1/resources/r1/permission-descriptions"


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.read())


@respx.mock
def test_get_and_set() -> None:
    iam = IAMKit(BASE, KEY, environment_id="env-1")
    respx.get(URL).respond(200, json={"items": [{"permission": "a:read", "locale": "es", "display_name": "Leer"}]})
    assert iam.permission_descriptions.get("r1")[0]["display_name"] == "Leer"

    put = respx.put(URL).respond(204)
    iam.permission_descriptions.set(
        "r1", [{"permission": "a:read", "display_name": "Read"}, {"permission": "a:read", "locale": "es"}]
    )
    assert body(put) == {
        "items": [
            {"permission": "a:read", "locale": "", "display_name": "Read", "description": ""},
            {"permission": "a:read", "locale": "es", "display_name": "", "description": ""},
        ]
    }
    iam.permission_descriptions.set("r1", [])
    assert body(put) == {"items": []}


@respx.mock
async def test_async_get_and_set() -> None:
    iam = AsyncIAMKit(BASE, KEY, environment_id="env-1")
    respx.get(URL).respond(200, json={"items": None})
    assert await iam.permission_descriptions.get("r1") == []
    put = respx.put(URL).respond(204)
    await iam.permission_descriptions.set("r1", [{"permission": "a:read", "display_name": "Read"}])
    assert body(put)["items"][0]["display_name"] == "Read"
