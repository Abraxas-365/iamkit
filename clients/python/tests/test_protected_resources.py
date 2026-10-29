from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from iamkit import AsyncIAMKit, IAMKit, IAMKitError

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
def test_external_clients_allowlist_and_presets(iam: IAMKit) -> None:
    respx.get(f"{P}/p1/impact").respond(200, json={"active_sessions": 3, "external_clients": 2})
    assert iam.protected_resources.impact("p1")["external_clients"] == 2

    listing = respx.get(f"{P}/p1/clients").respond(200, json={"items": [{"id": "c1"}], "page": {"total": 1}})
    assert iam.protected_resources.clients("p1", admission="pending", limit=5)["items"][0]["id"] == "c1"
    assert dict(listing.calls.last.request.url.params) == {"admission": "pending", "limit": "5"}
    assert [c["id"] for c in iam.protected_resources.iterate_clients("p1", admission="pending")] == ["c1"]

    respx.get(f"{P}/p1/clients/c1").respond(200, json={"id": "c1"})
    assert iam.protected_resources.client("p1", "c1")["id"] == "c1"
    respx.get(f"{P}/p1/clients/c1/requests").respond(200, json={"items": [], "page": {"total": 0}})
    assert iam.protected_resources.client_requests("p1", "c1")["items"] == []

    approve = respx.post(f"{P}/p1/clients/c1/approve").respond(200, json={"admission": "approved"})
    iam.protected_resources.approve_client("p1", "c1", metadata_hash="h1", expires_at="2027-01-01T00:00:00Z")
    assert body(approve) == {"metadata_hash": "h1", "expires_at": "2027-01-01T00:00:00Z"}
    iam.protected_resources.approve_client("p1", "c1", metadata_hash="h1")
    assert body(approve) == {"metadata_hash": "h1"}
    respx.post(f"{P}/p1/clients/c1/block").respond(200, json={"admission": "blocked"})
    assert iam.protected_resources.block_client("p1", "c1")["admission"] == "blocked"
    respx.post(f"{P}/p1/clients/c1/unblock").respond(200, json={"admission": "pending"})
    assert iam.protected_resources.unblock_client("p1", "c1")["admission"] == "pending"
    forget = respx.delete(f"{P}/p1/clients/c1").respond(204)
    iam.protected_resources.forget_client("p1", "c1")
    assert forget.called

    template = respx.post(f"{P}/p1/client-templates").respond(201, json={"client": {"client_id": "3f1e"}})
    assert iam.protected_resources.create_client_from_template("p1", "gemini_cli")["client"]["client_id"] == "3f1e"
    assert body(template) == {"preset": "gemini_cli"}

    allow = f"{BASE}/management/v1/environments/env-1/oauth-client-allowlist"
    respx.get(allow).respond(200, json={"items": [], "page": {"total": 0}})
    iam.protected_resources.allowlist(protected_resource_id="p1")
    create = respx.post(allow).respond(201, json={"id": "e1"})
    iam.protected_resources.create_allowlist_entry(origin="https://tools.example", path_prefix="/oauth")
    assert body(create) == {"origin": "https://tools.example", "path_prefix": "/oauth"}
    removed = respx.delete(f"{allow}/e1").respond(204)
    iam.protected_resources.delete_allowlist_entry("e1")
    assert removed.called

    presets = f"{BASE}/management/v1/environments/env-1/oauth-client-presets"
    respx.get(presets).respond(200, json={"items": [{"key": "claude"}]})
    assert iam.protected_resources.presets()["items"][0]["key"] == "claude"
    apply = respx.post(presets).respond(201, json={"preset": "claude_code"})
    iam.protected_resources.apply_preset("claude_code")
    assert body(apply) == {"preset": "claude_code"}

    patch = respx.patch(f"{P}/p1").respond(200, json={"id": "p1"})
    iam.protected_resources.update("p1", allow_client_metadata=True, client_admission="open")
    assert body(patch) == {"allow_client_metadata": True, "client_admission": "open"}
    with pytest.raises(IAMKitError):
        iam.protected_resources.client("p1", "..")


@respx.mock
async def test_async_twin() -> None:
    aiam = AsyncIAMKit(BASE, KEY, environment_id="env-1")
    respx.get(POLICY).respond(200, json={"max_idle_ttl_seconds": 1, "max_lifetime_ttl_seconds": 2})
    assert (await aiam.protected_resources.policy())["max_lifetime_ttl_seconds"] == 2
    respx.get(f"{P}/p1/clients").respond(200, json={"items": [{"id": "c1"}], "page": {"total": 1}})
    assert [c["id"] async for c in aiam.protected_resources.iterate_clients("p1")] == ["c1"]
    respx.post(f"{P}/p1/clients/c1/block").respond(200, json={"admission": "blocked"})
    assert (await aiam.protected_resources.block_client("p1", "c1"))["admission"] == "blocked"
