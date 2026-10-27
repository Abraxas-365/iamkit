from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from iamkit import AsyncIAMKit, IAMKit

BASE = "https://iam.test"
KEY = "ik_mgmt_" + "x" * 8
P = f"{BASE}/management/v1/environments/env-1/protected-resources"
POLICY = f"{BASE}/management/v1/environments/env-1/protected-resource-policy"


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.read())


@pytest.fixture
def iam() -> IAMKit:
    return IAMKit(BASE, KEY, environment_id="env-1")


@respx.mock
def test_crud_and_policy(iam: IAMKit) -> None:
    create = respx.post(P).respond(201, json={"id": "p1", "uri": "https://mcp.example/mcp"})
    assert iam.protected_resources.create("a1", "r1", "Notes", default_scopes=["notes:read"])["id"] == "p1"
    assert body(create) == {
        "application_id": "a1",
        "resource_id": "r1",
        "name": "Notes",
        "default_scopes": ["notes:read"],
    }

    update = respx.patch(f"{P}/p1").respond(200, json={"id": "p1", "active": False})
    assert iam.protected_resources.update("p1", active=False)["active"] is False
    assert body(update) == {"active": False}

    respx.get(P).respond(200, json={"items": [{"id": "p1"}], "page": {"total": 1}})
    assert [p["id"] for p in iam.protected_resources.iterate()] == ["p1"]

    policy = respx.put(POLICY).respond(200, json={"max_idle_ttl_seconds": 600, "max_lifetime_ttl_seconds": 7200})
    iam.protected_resources.set_policy(max_idle_ttl_seconds=600, max_lifetime_ttl_seconds=7200)
    assert body(policy) == {"max_idle_ttl_seconds": 600, "max_lifetime_ttl_seconds": 7200}

    delete = respx.delete(f"{P}/p1").respond(204)
    iam.protected_resources.delete("p1")
    assert delete.called


@respx.mock
async def test_async_twin() -> None:
    aiam = AsyncIAMKit(BASE, KEY, environment_id="env-1")
    respx.get(POLICY).respond(200, json={"max_idle_ttl_seconds": 1, "max_lifetime_ttl_seconds": 2})
    assert (await aiam.protected_resources.policy())["max_lifetime_ttl_seconds"] == 2
