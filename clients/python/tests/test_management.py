from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from iamkit import AsyncIAMKit, IAMKit, IAMKitError, paginate

BASE = "https://iam.test"
KEY = "ik_mgmt_" + "x" * 8
E = f"{BASE}/management/v1/environments/env-1"
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def iam() -> IAMKit:
    return IAMKit(BASE, KEY, environment_id="env-1")


@pytest.fixture
def aiam() -> AsyncIAMKit:
    return AsyncIAMKit(BASE, KEY, environment_id="env-1")


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.read())


def query(route: respx.Route) -> dict[str, str]:
    return dict(route.calls.last.request.url.params)


# Each case: (name, call(client), method, path suffix, expected query, expected body, response status)
Case = tuple[str, Callable[[Any], Any], str, str, dict[str, str] | None, Any, int]

CASES: list[Case] = [
    (
        "users.list",
        lambda c: c.users.list(search="a", limit=5, offset=10),
        "GET",
        "/users",
        {"search": "a", "limit": "5", "offset": "10"},
        None,
        200,
    ),
    ("users.get", lambda c: c.users.get("u1"), "GET", "/users/u1", None, None, 200),
    (
        "users.create",
        lambda c: c.users.create(email="a@b.c", name="A", password_hash="h"),
        "POST",
        "/users",
        None,
        {"email": "a@b.c", "name": "A", "password_hash": "h"},
        201,
    ),
    (
        "users.import",
        lambda c: c.users.import_([{"email": "a@b.c"}]),
        "POST",
        "/users/import",
        None,
        {"users": [{"email": "a@b.c"}]},
        200,
    ),
    (
        "users.update",
        lambda c: c.users.update("u1", name="B", external_id=None),
        "PATCH",
        "/users/u1",
        None,
        {"name": "B", "external_id": None},
        204,
    ),
    ("users.deactivate", lambda c: c.users.deactivate("u1"), "POST", "/users/u1/deactivate", None, None, 204),
    ("users.reactivate", lambda c: c.users.reactivate("u1"), "POST", "/users/u1/reactivate", None, None, 204),
    ("users.suspend", lambda c: c.users.suspend("u1"), "DELETE", "/users/u1", None, None, 204),
    ("users.delete", lambda c: c.users.delete("u1"), "DELETE", "/users/u1/permanent", None, None, 204),
    (
        "users.revoke_sessions",
        lambda c: c.users.revoke_sessions("u1"),
        "POST",
        "/users/u1/revoke-sessions",
        None,
        None,
        200,
    ),
    (
        "users.require_password_change",
        lambda c: c.users.require_password_change("u1"),
        "POST",
        "/users/u1/require-password-change",
        None,
        None,
        204,
    ),
    ("users.unlock", lambda c: c.users.unlock("u1"), "POST", "/users/u1/unlock", None, None, 204),
    ("users.history", lambda c: c.users.history("u1", limit=3), "GET", "/users/u1/history", {"limit": "3"}, None, 200),
    ("orgs.list", lambda c: c.organizations.list(search="x"), "GET", "/organizations", {"search": "x"}, None, 200),
    ("orgs.get", lambda c: c.organizations.get("o1"), "GET", "/organizations/o1", None, None, 200),
    ("orgs.create", lambda c: c.organizations.create("Acme"), "POST", "/organizations", None, {"name": "Acme"}, 201),
    (
        "orgs.update",
        lambda c: c.organizations.update("o1", name="B"),
        "PATCH",
        "/organizations/o1",
        None,
        {"name": "B"},
        204,
    ),
    (
        "orgs.members",
        lambda c: c.organizations.members("o1", active=True),
        "GET",
        "/organizations/o1/members",
        {"active": "true"},
        None,
        200,
    ),
    (
        "orgs.add_member",
        lambda c: c.organizations.add_member("o1", "u1"),
        "POST",
        "/memberships",
        None,
        {"organization_id": "o1", "user_id": "u1"},
        204,
    ),
    (
        "orgs.remove_member",
        lambda c: c.organizations.remove_member("o1", "u1"),
        "DELETE",
        "/organizations/o1/members/u1",
        None,
        None,
        204,
    ),
    (
        "orgs.invitations",
        lambda c: c.organizations.invitations("o1", status="pending"),
        "GET",
        "/organizations/o1/invitations",
        {"status": "pending"},
        None,
        200,
    ),
    (
        "orgs.invite",
        lambda c: c.organizations.invite("o1", "a@b.c", role_ids=["r1"]),
        "POST",
        "/organizations/o1/invitations",
        None,
        {"email": "a@b.c", "role_ids": ["r1"]},
        201,
    ),
    (
        "orgs.get_invitation",
        lambda c: c.organizations.get_invitation("o1", "i1"),
        "GET",
        "/organizations/o1/invitations/i1",
        None,
        None,
        200,
    ),
    (
        "orgs.revoke_invitation",
        lambda c: c.organizations.revoke_invitation("o1", "i1"),
        "DELETE",
        "/organizations/o1/invitations/i1",
        None,
        None,
        204,
    ),
    (
        "orgs.resend_invitation",
        lambda c: c.organizations.resend_invitation("o1", "i1"),
        "POST",
        "/organizations/o1/invitations/i1/resend",
        None,
        None,
        200,
    ),
    ("roles.list", lambda c: c.roles.list(limit=2), "GET", "/roles", {"limit": "2"}, None, 200),
    ("roles.get", lambda c: c.roles.get("r1"), "GET", "/roles/r1", None, None, 200),
    (
        "roles.create",
        lambda c: c.roles.create("admin", "res", ["a:b"]),
        "POST",
        "/roles",
        None,
        {"name": "admin", "resource_id": "res", "permissions": ["a:b"]},
        201,
    ),
    (
        "roles.update",
        lambda c: c.roles.update("r1", "admin", "res", ["a:b"]),
        "PUT",
        "/roles/r1",
        None,
        {"name": "admin", "resource_id": "res", "permissions": ["a:b"]},
        204,
    ),
    ("roles.delete", lambda c: c.roles.delete("r1"), "DELETE", "/roles/r1", None, None, 204),
    (
        "roles.assignments",
        lambda c: c.roles.assignments(user_id="u1"),
        "GET",
        "/role-assignments",
        {"user_id": "u1"},
        None,
        200,
    ),
    (
        "roles.assign",
        lambda c: c.roles.assign("r1", "o1", "u1"),
        "POST",
        "/role-assignments",
        None,
        {"role_id": "r1", "organization_id": "o1", "user_id": "u1"},
        204,
    ),
    (
        "roles.unassign",
        lambda c: c.roles.unassign("r1", "o1", "u1"),
        "DELETE",
        "/role-assignments/r1/o1/u1",
        None,
        None,
        204,
    ),
    (
        "roles.grants",
        lambda c: c.roles.grants(user_id="u1", limit=1),
        "GET",
        "/grants",
        {"user_id": "u1", "limit": "1"},
        None,
        200,
    ),
    (
        "roles.put_grant",
        lambda c: c.roles.put_grant("u1", "o1", "res", ["p"]),
        "PUT",
        "/grants",
        None,
        {"user_id": "u1", "organization_id": "o1", "resource_id": "res", "permissions": ["p"]},
        200,
    ),
    ("roles.delete_grant", lambda c: c.roles.delete_grant("g1"), "DELETE", "/grants/g1", None, None, 204),
    (
        "keys.list",
        lambda c: c.api_keys.list(owner_type="organization", state="active"),
        "GET",
        "/api-keys",
        {"owner_type": "organization", "state": "active"},
        None,
        200,
    ),
    ("keys.get", lambda c: c.api_keys.get("k1"), "GET", "/api-keys/k1", None, None, 200),
    (
        "keys.create_org",
        lambda c: c.api_keys.create_organization_key("o1", "res", "ci", expires_in=60),
        "POST",
        "/api-keys",
        None,
        {"organization_id": "o1", "resource_id": "res", "name": "ci", "expires_in": 60},
        201,
    ),
    ("keys.revoke", lambda c: c.api_keys.revoke("k1"), "DELETE", "/api-keys/k1", None, None, 204),
    ("keys.user_keys", lambda c: c.api_keys.user_keys("u1"), "GET", "/users/u1/api-keys", None, None, 200),
    (
        "keys.create_machine",
        lambda c: c.api_keys.create_machine_key("u1", "res", "n", "app"),
        "POST",
        "/users/u1/api-keys",
        None,
        {"application_id": "app", "resource_id": "res", "name": "n"},
        201,
    ),
    (
        "keys.revoke_user_key",
        lambda c: c.api_keys.revoke_user_key("u1", "k1"),
        "DELETE",
        "/users/u1/api-keys/k1",
        None,
        None,
        204,
    ),
    ("keys.policy", lambda c: c.api_keys.policy(), "GET", "/api-key-policy", None, None, 200),
    (
        "keys.save_policy",
        lambda c: c.api_keys.save_policy({"user_keys": True}),
        "PUT",
        "/api-key-policy",
        None,
        {"user_keys": True},
        204,
    ),
    (
        "events.list",
        lambda c: c.events.list(type="user.created", after=5, limit=10),
        "GET",
        "/events",
        {"type": "user.created", "after": "5", "limit": "10"},
        None,
        200,
    ),
    ("webhooks.list", lambda c: c.webhooks.list(), "GET", "/webhooks", None, None, 200),
    ("webhooks.get", lambda c: c.webhooks.get("w1"), "GET", "/webhooks/w1", None, None, 200),
    (
        "webhooks.create",
        lambda c: c.webhooks.create("https://x.test/h", name="n", types=["user.*"]),
        "POST",
        "/webhooks",
        None,
        {"url": "https://x.test/h", "name": "n", "types": ["user.*"]},
        201,
    ),
    (
        "webhooks.update",
        lambda c: c.webhooks.update("w1", active=False),
        "PATCH",
        "/webhooks/w1",
        None,
        {"active": False},
        200,
    ),
    ("webhooks.delete", lambda c: c.webhooks.delete("w1"), "DELETE", "/webhooks/w1", None, None, 204),
    (
        "webhooks.rotate",
        lambda c: c.webhooks.rotate_secret("w1"),
        "POST",
        "/webhooks/w1/rotate-secret",
        None,
        None,
        200,
    ),
    ("webhooks.test", lambda c: c.webhooks.test("w1"), "POST", "/webhooks/w1/test", None, None, 200),
    (
        "webhooks.deliveries",
        lambda c: c.webhooks.deliveries("w1", status="failed"),
        "GET",
        "/webhooks/w1/deliveries",
        {"status": "failed"},
        None,
        200,
    ),
    (
        "webhooks.retry",
        lambda c: c.webhooks.retry_delivery("w1", "d1"),
        "POST",
        "/webhooks/w1/deliveries/d1/retry",
        None,
        None,
        200,
    ),
    ("webhooks.replay", lambda c: c.webhooks.replay("w1", 42), "POST", "/webhooks/w1/replay", None, {"from": 42}, 202),
    ("audit.get", lambda c: c.audit_logs.get("e1"), "GET", "/audit-logs/events/e1", None, None, 200),
    ("audit.actions", lambda c: c.audit_logs.actions(), "GET", "/audit-logs/actions", None, None, 200),
    (
        "audit.create_action",
        lambda c: c.audit_logs.create_action("invoice.paid", target_types=["invoice"]),
        "POST",
        "/audit-logs/actions",
        None,
        {"name": "invoice.paid", "target_types": ["invoice"]},
        201,
    ),
    ("risk.policy", lambda c: c.risk.policy(), "GET", "/risk-policy", None, None, 200),
    (
        "risk.save_policy",
        lambda c: c.risk.save_policy({"ip_velocity": "log"}),
        "PUT",
        "/risk-policy",
        None,
        {"ip_velocity": "log"},
        200,
    ),
    ("risk.reset_policy", lambda c: c.risk.reset_policy(), "DELETE", "/risk-policy", None, None, 204),
    ("risk.status", lambda c: c.risk.status(), "GET", "/risk/status", None, None, 200),
    (
        "risk.restrictions",
        lambda c: c.risk.restrictions(kind="ip"),
        "GET",
        "/risk-restrictions",
        {"kind": "ip"},
        None,
        200,
    ),
    (
        "risk.add_restriction",
        lambda c: c.risk.add_restriction("ip", "deny", "1.2.3.4", note="n"),
        "POST",
        "/risk-restrictions",
        None,
        {"kind": "ip", "action": "deny", "value": "1.2.3.4", "note": "n"},
        201,
    ),
    (
        "risk.delete_restriction",
        lambda c: c.risk.delete_restriction("r1"),
        "DELETE",
        "/risk-restrictions/r1",
        None,
        None,
        204,
    ),
    (
        "risk.attempts",
        lambda c: c.risk.sign_in_attempts(limit=5),
        "GET",
        "/sign-in-attempts",
        {"limit": "5"},
        None,
        200,
    ),
    ("risk.captcha", lambda c: c.risk.captcha(), "GET", "/captcha", None, None, 200),
    (
        "risk.save_captcha",
        lambda c: c.risk.save_captcha({"provider": "turnstile", "site_key": "k"}),
        "PUT",
        "/captcha",
        None,
        {"provider": "turnstile", "site_key": "k"},
        200,
    ),
    ("risk.delete_captcha", lambda c: c.risk.delete_captcha(), "DELETE", "/captcha", None, None, 204),
    ("risk.test_captcha", lambda c: c.risk.test_captcha(), "POST", "/captcha/test", None, None, 204),
]

IDS = [c[0] for c in CASES]


def mock(method: str, suffix: str, status: int) -> respx.Route:
    route = respx.route(method=method, url__regex=rf"^{E}{suffix}(\?.*)?$")
    if status == 204:
        return route.respond(204)
    return route.respond(status, json={"ok": True})


@pytest.mark.parametrize("case", CASES, ids=IDS)
@respx.mock
def test_sync_routes(iam: IAMKit, case: Case) -> None:
    _, call, method, suffix, want_query, want_body, status = case
    route = mock(method, suffix, status)
    result = call(iam)
    assert route.call_count == 1
    request = route.calls.last.request
    assert request.headers["x-api-key"] == KEY
    assert "authorization" not in request.headers
    if want_query is not None:
        assert query(route) == want_query
    if want_body is not None:
        assert body(route) == want_body
    elif request.method != "GET":
        assert request.read() == b""
    if status == 204:
        assert result is None


@pytest.mark.parametrize("case", CASES, ids=IDS)
@respx.mock
async def test_async_routes(aiam: AsyncIAMKit, case: Case) -> None:
    _, call, method, suffix, want_query, want_body, status = case
    route = mock(method, suffix, status)
    result = await call(aiam)
    assert route.call_count == 1
    assert route.calls.last.request.headers["x-api-key"] == KEY
    if want_query is not None:
        assert query(route) == want_query
    if want_body is not None:
        assert body(route) == want_body
    if status == 204:
        assert result is None


def test_environment_required_and_ids_escaped() -> None:
    bare = IAMKit(BASE, KEY)
    with pytest.raises(IAMKitError):
        bare.users.list()
    with pytest.raises(IAMKitError):
        bare.environment_path()
    bare.environment_id = "env-1"
    assert bare.environment_path("/x") == "/management/v1/environments/env-1/x"
    with respx.mock:
        route = respx.get(f"{E}/users/a%2Fb").respond(200, json={})
        bare.users.get("a/b")
        assert route.call_count == 1
    for bad in ("", "..", "."):
        with pytest.raises(IAMKitError):
            bare.users.get(bad)
    with pytest.raises(IAMKitError):
        IAMKit(BASE, "")
    with pytest.raises(IAMKitError):
        AsyncIAMKit(BASE, "")


@respx.mock
def test_error_envelope(iam: IAMKit) -> None:
    respx.get(f"{E}/users/u1").respond(
        404,
        json={
            "error": {"code": "NOT_FOUND", "message": "user not found", "type": "not_found", "details": {"id": "u1"}}
        },
    )
    with pytest.raises(IAMKitError) as exc:
        iam.users.get("u1")
    assert (exc.value.status, exc.value.code, exc.value.message, exc.value.details) == (
        404,
        "NOT_FOUND",
        "user not found",
        {"id": "u1"},
    )


@respx.mock
def test_generic_request(iam: IAMKit) -> None:
    route = respx.post(f"{BASE}/management/v1/anything").respond(200, json={"a": 1})
    assert iam.request(
        "POST", "/management/v1/anything", json={"x": 1}, params={"q": "1"}, headers={"X-Extra": "1"}
    ) == {"a": 1}
    r = route.calls.last.request
    assert (r.headers["x-api-key"], r.headers["x-extra"], r.url.params["q"]) == (KEY, "1", "1")


@respx.mock
async def test_generic_request_async(aiam: AsyncIAMKit) -> None:
    respx.get(f"{BASE}/management/v1/x").respond(200, json={"a": 2})
    assert await aiam.request("GET", "/management/v1/x") == {"a": 2}
    assert aiam.environment_path("/y").endswith("/env-1/y")


@respx.mock
def test_users_iterate_pages(iam: IAMKit) -> None:
    pages = {
        "0": {"items": [{"id": "a"}, {"id": "b"}], "page": {"total": 3, "limit": 2, "offset": 0}},
        "2": {"items": [{"id": "c"}], "page": {"total": 3, "limit": 2, "offset": 2}},
    }
    route = respx.get(f"{E}/users").mock(side_effect=lambda r: httpx.Response(200, json=pages[r.url.params["offset"]]))
    got = [u["id"] for u in iam.users.iterate(page_size=2, search="x")]
    assert got == ["a", "b", "c"]
    assert route.call_count == 2 and query(route)["search"] == "x"


@respx.mock
async def test_users_iterate_async_and_empty(aiam: AsyncIAMKit) -> None:
    respx.get(f"{E}/organizations").respond(200, json={"items": [], "page": {"total": 0}})
    assert [o async for o in aiam.organizations.iterate()] == []
    respx.get(f"{E}/organizations/o1/members").respond(200, json={"items": [{"id": "m"}], "page": {"total": 1}})
    assert [m async for m in aiam.organizations.iterate_members("o1")] == [{"id": "m"}]


@respx.mock
def test_paginate_helper() -> None:
    seen: list[tuple[int, int]] = []

    def fetch(limit: int, offset: int) -> dict[str, Any]:
        seen.append((limit, offset))
        data = list(range(5))[offset : offset + limit]
        return {"items": data, "page": {"total": 5}}

    assert list(paginate(fetch, page_size=2)) == [0, 1, 2, 3, 4]
    assert seen == [(2, 0), (2, 2), (2, 4)]


@respx.mock
def test_events_cursor_iteration(iam: IAMKit) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.params
        if "after" in p:
            after = int(p["after"])
            return httpx.Response(
                200, json={"items": [{"id": after + 1}] if after < 2 else [], "next": after + 1 if after < 2 else 0}
            )
        before = p.get("before")
        if before is None:
            return httpx.Response(200, json={"items": [{"id": 9}, {"id": 8}], "next": 8})
        return httpx.Response(200, json={"items": [{"id": 7}], "next": 0})

    respx.get(f"{E}/events").mock(side_effect=handler)
    assert [e["id"] for e in iam.events.iterate()] == [9, 8, 7]  # newest first, `next` becomes `before`
    assert [e["id"] for e in iam.events.iterate(after=0)] == [1, 2]  # feed oldest first, `next` becomes `after`


@respx.mock
async def test_events_iterate_async(aiam: AsyncIAMKit) -> None:
    respx.get(f"{E}/audit-logs/events").respond(200, json={"items": [{"id": 1}], "next": 0})
    assert [e async for e in aiam.audit_logs.iterate(organization_id="o1")] == [{"id": 1}]


@respx.mock
def test_exports(iam: IAMKit) -> None:
    respx.get(f"{E}/events/export").respond(200, content=b'{"id":1}\n{"id":2}\n')
    assert [e["id"] for e in iam.events.export(type="user.created")] == [1, 2]
    respx.get(f"{E}/audit-logs/events/export", params={"format": "ndjson"}).respond(200, content=b'{"a":1}\n')
    assert list(iam.audit_logs.export()) == [{"a": 1}]
    csv = respx.get(f"{E}/audit-logs/events/export", params={"format": "csv"}).respond(200, content=b"a,b\n1,2\n")
    assert list(iam.audit_logs.export(format="csv")) == ["a,b", "1,2"]
    assert csv.call_count == 1
    respx.get(f"{E}/events/export").respond(403, json={"error": {"code": "FORBIDDEN", "message": "no"}})
    with pytest.raises(IAMKitError):
        list(iam.events.export())


@respx.mock
async def test_exports_async(aiam: AsyncIAMKit) -> None:
    respx.get(f"{E}/events/export").respond(200, content=b'{"id":1}\n')
    assert [e async for e in aiam.events.export()] == [{"id": 1}]
    respx.get(f"{E}/audit-logs/events/export").respond(200, content=b'{"a":1}\n')
    assert [e async for e in aiam.audit_logs.export()] == [{"a": 1}]


@respx.mock
def test_audit_log_emit_and_list(iam: IAMKit) -> None:
    emit = respx.post(f"{E}/audit-logs/events").respond(201, json={"id": "ev1", "seq": 1})
    out = iam.audit_logs.emit(
        "o1",
        "invoice.paid",
        "2026-01-01T00:00:00Z",
        {"type": "user", "id": "u1"},
        [{"type": "invoice", "id": "i1"}],
        metadata={"amount": 5},
        idempotency_key="idem-1",
    )
    assert out["id"] == "ev1"
    r = emit.calls.last.request
    assert r.headers["idempotency-key"] == "idem-1" and r.headers["x-api-key"] == KEY
    assert body(emit) == {
        "organization_id": "o1",
        "action": "invoice.paid",
        "occurred_at": "2026-01-01T00:00:00Z",
        "actor": {"type": "user", "id": "u1"},
        "targets": [{"type": "invoice", "id": "i1"}],
        "metadata": {"amount": 5},
    }
    iam.audit_logs.emit("o1", "a", "2026-01-01T00:00:00Z", {"type": "user", "id": "u"}, [])
    assert "idempotency-key" not in emit.calls.last.request.headers
    emit.respond(409, json={"error": {"code": "IDEMPOTENCY_KEY_REUSED", "message": "reused"}})
    with pytest.raises(IAMKitError) as exc:
        iam.audit_logs.emit("o1", "a", "t", {}, [], idempotency_key="idem-1")
    assert (exc.value.status, exc.value.code) == (409, "IDEMPOTENCY_KEY_REUSED")
    lst = respx.get(f"{E}/audit-logs/events").respond(200, json={"items": [], "next": 0})
    iam.audit_logs.list(organization_id="o1", action=["a.b", "c.d"], occurred_after="2026-01-01T00:00:00Z", limit=5)
    assert query(lst) == {
        "organization_id": "o1",
        "action": "a.b,c.d",
        "occurred_after": "2026-01-01T00:00:00Z",
        "limit": "5",
    }


@respx.mock
async def test_audit_emit_async(aiam: AsyncIAMKit) -> None:
    route = respx.post(f"{E}/audit-logs/events").respond(201, json={"id": "e"})
    await aiam.audit_logs.emit("o", "a", "t", {"type": "user", "id": "u"}, [], idempotency_key="k")
    assert route.calls.last.request.headers["idempotency-key"] == "k"


def test_context_managers_and_close() -> None:
    with IAMKit(BASE, KEY, environment_id="env-1") as client:
        assert client.environment_id == "env-1"


async def test_async_context_manager() -> None:
    async with AsyncIAMKit(BASE, KEY, environment_id="env-1") as client:
        assert client.environment_id == "env-1"


@respx.mock
def test_reuses_provided_client() -> None:
    respx.get(f"{E}/webhooks").respond(200, json={"items": []})
    with httpx.Client() as http:
        IAMKit(BASE, KEY, environment_id="env-1", client=http).webhooks.list()
        assert not http.is_closed


def test_async_resources_are_generated_and_current() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "unasync.py"), "--check"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_every_sync_resource_method_has_an_async_twin() -> None:
    import inspect

    from iamkit import _aresources as a
    from iamkit import _resources as r

    for name, sync_cls in inspect.getmembers(r, inspect.isclass):
        if sync_cls.__module__ != r.__name__ or name.startswith("_"):
            continue
        async_cls = getattr(a, name)
        for meth, fn in inspect.getmembers(sync_cls, inspect.isfunction):
            if meth.startswith("__"):
                continue
            twin = getattr(async_cls, meth)
            if meth.startswith("iterate") or meth in ("export",):
                assert inspect.isasyncgenfunction(twin) or not inspect.iscoroutinefunction(twin), meth
            elif not meth.startswith("_") and "yield" not in inspect.getsource(fn):
                assert inspect.iscoroutinefunction(twin), meth
