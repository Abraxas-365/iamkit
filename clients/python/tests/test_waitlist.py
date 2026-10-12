from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from iamkit import AsyncIAMKit, IAMKit, IAMKitError

BASE = "https://iam.test"
KEY = "ik_mgmt_" + "x" * 8
W = f"{BASE}/management/v1/environments/env-1/waitlist"


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.read())


@pytest.fixture
def iam() -> IAMKit:
    return IAMKit(BASE, KEY, environment_id="env-1")


@respx.mock
def test_list_get_and_decisions(iam: IAMKit) -> None:
    lst = respx.get(W).respond(200, json={"items": [], "page": {"total": 0, "limit": 5, "offset": 0}})
    iam.waitlist.list(status="pending", email="ana", limit=5, offset=10)
    assert dict(lst.calls.last.request.url.params) == {
        "status": "pending",
        "email": "ana",
        "limit": "5",
        "offset": "10",
    }

    respx.get(f"{W}/w1").respond(200, json={"id": "w1", "status": "pending"})
    assert iam.waitlist.get("w1")["status"] == "pending"

    approve = respx.post(f"{W}/w1/approve").respond(200, json={"id": "w1", "status": "approved"})
    assert iam.waitlist.approve("w1")["status"] == "approved"
    assert approve.called

    reject = respx.post(f"{W}/w1/reject").respond(200, json={"id": "w1", "status": "rejected"})
    iam.waitlist.reject("w1")
    assert body(reject) == {"notify": False}
    iam.waitlist.reject("w1", notify=True)
    assert body(reject) == {"notify": True}

    delete = respx.delete(f"{W}/w1").respond(204)
    iam.waitlist.delete("w1")
    assert delete.called


@respx.mock
def test_not_pending_is_an_error(iam: IAMKit) -> None:
    respx.post(f"{W}/w1/approve").respond(409, json={"error": {"code": "WAITLIST_ENTRY_NOT_PENDING", "message": "no"}})
    with pytest.raises(IAMKitError) as exc:
        iam.waitlist.approve("w1")
    assert (exc.value.status, exc.value.code) == (409, "WAITLIST_ENTRY_NOT_PENDING")


@respx.mock
def test_approve_many_and_all_pending(iam: IAMKit) -> None:
    route = respx.post(f"{W}/approve").respond(200, json={"approved": 2, "skipped": 0, "more": False})
    iam.waitlist.approve_many(["a", "b"])
    assert body(route) == {"ids": ["a", "b"]}
    iam.waitlist.approve_many(all_pending=True)
    assert body(route) == {"all_pending": True}

    route.side_effect = [
        respx.MockResponse(200, json={"approved": 500, "skipped": 1, "more": True}),
        respx.MockResponse(200, json={"approved": 3, "skipped": 0, "more": False}),
    ]
    assert iam.waitlist.approve_all_pending() == {"approved": 503, "skipped": 1}


@respx.mock
def test_approve_all_pending_stops_when_nothing_moves(iam: IAMKit) -> None:
    route = respx.post(f"{W}/approve").respond(200, json={"approved": 0, "skipped": 4, "more": True})
    assert iam.waitlist.approve_all_pending() == {"approved": 0, "skipped": 4}
    assert route.call_count == 1


@respx.mock
def test_iterate_pages(iam: IAMKit) -> None:
    route = respx.get(W).respond(200, json={"items": [{"id": "a"}, {"id": "b"}], "page": {"total": 2}})
    assert [e["id"] for e in iam.waitlist.iterate()] == ["a", "b"]
    assert route.call_count == 1


@respx.mock
async def test_async_twin() -> None:
    aiam = AsyncIAMKit(BASE, KEY, environment_id="env-1")
    route = respx.post(f"{W}/approve").respond(200, json={"approved": 1, "skipped": 0, "more": False})
    assert await aiam.waitlist.approve_all_pending() == {"approved": 1, "skipped": 0}
    assert body(route) == {"all_pending": True}
    respx.post(f"{W}/w1/reject").respond(200, json={"id": "w1"})
    await aiam.waitlist.reject("w1", notify=True)
