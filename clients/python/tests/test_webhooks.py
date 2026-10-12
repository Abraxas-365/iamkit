from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from iamkit import (
    ActionInput,
    ActionResponse,
    Conditions,
    WebhookError,
    deny,
    verify_action,
    verify_signature,
    verify_webhook,
)

KEY = b"k" * 32
SECRET = "whsec_" + base64.b64encode(KEY).decode()
OLD_SECRET = "whsec_" + base64.b64encode(b"o" * 32).decode()


def sign(key: bytes, msg_id: str, ts: str, body: bytes) -> str:
    mac = hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def headers(body: bytes, *, key: bytes = KEY, ts: int | None = None, extra: str = "") -> dict[str, str]:
    stamp = str(int(time.time()) if ts is None else ts)
    return {
        "webhook-id": "msg_1",
        "webhook-timestamp": stamp,
        "webhook-signature": (extra + " " + sign(key, "msg_1", stamp, body)).strip(),
    }


EVENT = json.dumps(
    {
        "id": 7,
        "environment_id": "env-1",
        "type": "user.created",
        "actor": {"kind": "operator"},
        "subject": {"kind": "user", "id": "u1"},
        "occurred_at": "2026-01-01T00:00:00Z",
        "organization_id": "org-1",
        "data": {"truncated": True},
    }
).encode()


def test_verify_webhook() -> None:
    event = verify_webhook(SECRET, headers(EVENT), EVENT)
    assert (event.id, event.type, event.organization_id, event.subject["id"]) == (7, "user.created", "org-1", "u1")
    assert event.data == {"truncated": True}
    assert verify_webhook(SECRET, headers(EVENT), EVENT.decode()).id == 7  # str body


def test_mixed_case_headers_and_httpx_style_mapping() -> None:
    h = {k.title(): v for k, v in headers(EVENT).items()}
    assert verify_webhook(SECRET, h, EVENT).id == 7
    list_valued = {k: [v] for k, v in headers(EVENT).items()}
    assert verify_webhook(SECRET, list_valued, EVENT).id == 7


def test_rotation_multiple_signatures() -> None:
    old = sign(b"o" * 32, "msg_1", str(int(time.time())), EVENT)
    h = headers(EVENT, extra=old)
    assert verify_webhook(SECRET, h, EVENT).id == 7
    assert verify_webhook(OLD_SECRET, h, EVENT).id == 7
    with pytest.raises(WebhookError):
        verify_webhook("whsec_" + base64.b64encode(b"z" * 32).decode(), h, EVENT)


def test_bad_signature_and_tamper() -> None:
    h = headers(EVENT)
    with pytest.raises(WebhookError) as exc:
        verify_webhook(SECRET, h, EVENT + b" ")
    assert exc.value.code == "SIGNATURE"
    bad = {**h, "webhook-signature": "v1,!!!notbase64 v2,abc v1, garbage"}
    with pytest.raises(WebhookError) as exc2:
        verify_webhook(SECRET, bad, EVENT)
    assert exc2.value.code == "SIGNATURE"
    missing = {k: v for k, v in h.items() if k != "webhook-signature"}
    with pytest.raises(WebhookError):
        verify_webhook(SECRET, missing, EVENT)
    other_id = {**h, "webhook-id": "msg_2"}
    with pytest.raises(WebhookError):
        verify_webhook(SECRET, other_id, EVENT)


def test_timestamp_tolerance() -> None:
    now = int(time.time())
    for ts in (now - 6 * 60, now + 6 * 60):
        with pytest.raises(WebhookError) as exc:
            verify_webhook(SECRET, headers(EVENT, ts=ts), EVENT)
        assert exc.value.code == "TIMESTAMP"
    assert verify_webhook(SECRET, headers(EVENT, ts=now - 4 * 60), EVENT).id == 7
    # custom tolerance and clock
    assert verify_webhook(SECRET, headers(EVENT, ts=1000), EVENT, now=1100, tolerance=200).id == 7
    for junk in ("", "abc", "-5", "12.5", "١٢٣"):
        h = {**headers(EVENT), "webhook-timestamp": junk}
        with pytest.raises(WebhookError) as exc2:
            verify_webhook(SECRET, h, EVENT)
        assert exc2.value.code == "TIMESTAMP"


def test_secret_validation() -> None:
    for secret in ("", "whsec_", "whsec_%%%", "not base64!"):
        with pytest.raises(WebhookError) as exc:
            verify_signature(secret, headers(EVENT), EVENT)
        assert exc.value.code == "SECRET"
    # the prefix is optional
    verify_signature(base64.b64encode(KEY).decode(), headers(EVENT), EVENT)


def test_body_limits_and_shape() -> None:
    big = b"x" * ((1 << 20) + 1)
    with pytest.raises(WebhookError) as exc:
        verify_webhook(SECRET, headers(big), big)
    assert exc.value.code == "BODY"
    for body in (b"not json", b"[1]"):
        with pytest.raises(WebhookError) as exc2:
            verify_webhook(SECRET, headers(body), body)
        assert exc2.value.code == "BODY"


def test_action_input() -> None:
    body = json.dumps(
        {
            "condition": Conditions.PRE_ACCESS_TOKEN,
            "environment_id": "env-1",
            "organization_id": "org-1",
            "client_id": "c1",
            "user": {"id": "u1", "email": "a@b.c"},
            "amr": ["pwd"],
            "scopes": ["openid"],
            "identity": {"provider": "google"},
            "request": {"x": 1},
        }
    ).encode()
    action = verify_action(SECRET, headers(body), body)
    assert isinstance(action, ActionInput)
    assert action.condition == "function:pre_access_token"
    assert action.user == {"id": "u1", "email": "a@b.c"}
    assert (action.amr, action.scopes, action.client_id) == (["pwd"], ["openid"], "c1")
    assert action.identity == {"provider": "google"} and action.request == {"x": 1}
    with pytest.raises(WebhookError):
        verify_action(SECRET, headers(body, key=b"x" * 32), body)


def test_action_response() -> None:
    assert ActionResponse().to_dict() == {}
    assert ActionResponse(claims={"tier": "pro"}).to_dict() == {"claims": {"tier": "pro"}}
    assert json.loads(ActionResponse(patch={"name": "A"}).to_json()) == {"patch": {"name": "A"}}
    denied = deny("Account under review")
    assert denied.to_dict() == {"deny": True, "message": "Account under review"}
    assert ActionResponse.denied("x").deny
    assert ActionResponse(claims={"a": 1}).to_json() == '{"claims":{"a":1}}'


def test_conditions_values() -> None:
    assert Conditions.USER_CREATE == "request:user.create"
    assert Conditions.MEMBERSHIP_CREATE == "request:membership.create"
