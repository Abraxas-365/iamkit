from __future__ import annotations

import time
from typing import Any

import pytest
import respx

from iamkit import (
    APIKeyValidator,
    IAMKitError,
    avalidate_api_key,
    has_api_key_permission,
    is_api_key,
    validate_api_key,
)

from .conftest import AUDIENCE, ENV, ISSUER

URL = f"{ISSUER}/identity/v1/introspect"
KEYVAL = "ik_key_" + "a" * 10


def key_claims(**over: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "purpose": "api_key",
        "environment_id": ENV,
        "aud": [AUDIENCE],
        "organization_id": "org-1",
        "resource_id": "res-1",
        "api_key": {
            "id": "key-1",
            "name": "ci",
            "owner": {"type": "organization", "organization_id": "org-1"},
            "resource_id": "res-1",
            "permissions": ["invoices:read"],
            "expires_at": 0,
        },
    }
    key_over = over.pop("api_key", None)
    claims.update(over)
    if key_over is not None:
        claims["api_key"] = {**claims["api_key"], **key_over} if isinstance(key_over, dict) else key_over
    return {k: v for k, v in claims.items() if v is not None}


def validator() -> APIKeyValidator:
    return APIKeyValidator(ISSUER, ENV, AUDIENCE)


def test_prefix() -> None:
    assert is_api_key(KEYVAL) and not is_api_key("eyJ.x.y")


@respx.mock
def test_validate_ok() -> None:
    route = respx.post(URL).respond(200, json={"active": True, "claims": key_claims()})
    key = validator().validate(KEYVAL)
    assert key.id == "key-1" and key.name == "ci"
    assert key.owner.type == "organization" and key.owner.id is None
    assert key.organization_id == "org-1" and key.resource_id == "res-1"
    assert key.permissions == ("invoices:read",) and key.expires_at == 0
    assert key.has_permission("invoices:read") and not key.has_permission("x")
    assert has_api_key_permission(key, "invoices:read") and not has_api_key_permission(key)
    req = route.calls.last.request
    assert req.headers["authorization"] == f"Bearer {KEYVAL}"
    assert b'"environment_id"' in req.read()


@respx.mock
def test_user_owner_and_future_expiry() -> None:
    owner = {"type": "user", "id": "u1", "organization_id": "org-1"}
    exp = int(time.time()) + 100
    respx.post(URL).respond(
        200, json={"active": True, "claims": key_claims(api_key={"owner": owner, "expires_at": exp})}
    )
    key = validator().validate(KEYVAL)
    assert key.owner.id == "u1" and key.expires_at == exp


@respx.mock
def test_validate_rejections() -> None:
    route = respx.post(URL)
    v = validator()
    bad: list[Any] = [
        {"active": False},
        {"active": True, "claims": key_claims(purpose="application")},
        {"active": True, "claims": key_claims(environment_id="other")},
        {"active": True, "claims": key_claims(aud=["x"])},
        {"active": True, "claims": key_claims(api_key={"permissions": []})},
        {"active": True, "claims": key_claims(api_key={"permissions": None})},
        {"active": True, "claims": key_claims(api_key={"id": ""})},
        {"active": True, "claims": key_claims(api_key={"expires_at": int(time.time()) - 5})},
        {"active": True, "claims": key_claims(api_key={"expires_at": "soon"})},
        {"active": True, "claims": key_claims(api_key="nope")},
        {"active": True, "claims": []},
        [],
    ]
    for body in bad:
        route.respond(200, json=body)
        with pytest.raises(IAMKitError) as exc:
            v.validate(KEYVAL)
        assert exc.value.status == 401, body
    for notkey in ("eyJhbGciOi.x.y", ""):
        with pytest.raises(IAMKitError):
            v.validate(notkey)


@respx.mock
async def test_outage_and_async() -> None:
    route = respx.post(URL).respond(503)
    v = validator()
    with pytest.raises(IAMKitError) as exc:
        v.validate(KEYVAL)
    assert exc.value.status == 503
    with pytest.raises(IAMKitError) as exc2:
        await v.avalidate(KEYVAL)
    assert exc2.value.status == 503
    route.respond(401, json={"error": {"code": "UNAUTHORIZED", "message": "x"}})
    with pytest.raises(IAMKitError) as exc3:
        v.validate(KEYVAL)
    assert exc3.value.status == 401
    with pytest.raises(IAMKitError) as exc4:
        await v.avalidate(KEYVAL)
    assert exc4.value.status == 401
    with pytest.raises(IAMKitError):
        await v.avalidate("nope")
    route.respond(200, json={"active": True, "claims": key_claims()})
    assert (await v.avalidate(KEYVAL)).id == "key-1"
    assert validate_api_key(KEYVAL, ISSUER, ENV, AUDIENCE).id == "key-1"
    assert (await avalidate_api_key(KEYVAL, ISSUER, ENV, AUDIENCE)).id == "key-1"
    v.close()
    await v.aclose()


def test_validator_requires_boundary() -> None:
    with pytest.raises(IAMKitError):
        APIKeyValidator(ISSUER, "", AUDIENCE)
