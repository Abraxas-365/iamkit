from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from iamkit import APIKeyValidator, ExpectedToken, IntrospectionVerifier, JwtVerifier
from iamkit.integrations._common import Principal, bearer, check
from iamkit.integrations.fastapi import principal_of as fastapi_principal_of
from iamkit.integrations.fastapi import require_token as fastapi_require

from .conftest import AUDIENCE, ENV, ISSUER, Signer, make_claims
from .test_apikeys import KEYVAL, key_claims

JWKS = f"{ISSUER}/.well-known/jwks.json"
INTROSPECT = f"{ISSUER}/identity/v1/introspect"


@pytest.fixture
def verifier(signer: Signer, expected: ExpectedToken) -> JwtVerifier:
    respx.get(JWKS).respond(200, json={"keys": [signer.jwk]})
    return JwtVerifier(expected)


def auth(signer: Signer, **over: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {signer.sign(make_claims(**over))}"}


def test_bearer_parsing() -> None:
    assert bearer("Bearer abc") == "abc"
    assert bearer("bearer abc") == "abc"
    for bad in (None, "", "Basic abc", "Bearer", "Bearer a b", "abc"):
        assert bearer(bad) is None


def test_check_rules() -> None:
    from iamkit import AccessClaims, IAMKitError

    app_claims = AccessClaims.from_payload(make_claims())
    p = Principal(claims=app_claims)
    check(p, permissions=["invoices:read"], organization="org-1", mfa=True, max_age=60)
    for kwargs, code in (
        ({"permissions": ["x"]}, "FORBIDDEN"),
        ({"organization": "org-2"}, "FORBIDDEN"),
        ({"organization": ""}, "FORBIDDEN"),
        ({"mfa": True, "max_age": 0.0001}, "STEP_UP_REQUIRED"),
    ):
        if "max_age" in kwargs:
            time.sleep(0.01)
        with pytest.raises(IAMKitError) as exc:
            check(p, **kwargs)
        assert exc.value.status == 403 and exc.value.code == code
    machine = Principal(
        claims=AccessClaims.from_payload(make_claims(purpose="machine", organization_id=None, sid=None))
    )
    assert machine.organization_id is None
    with pytest.raises(IAMKitError):
        check(machine, organization="org-1")
    with pytest.raises(IAMKitError):
        check(Principal(api_key=None, claims=None), permissions=["a"])


# -- FastAPI ------------------------------------------------------------------------------------


def fastapi_app(verifier: Any, **kw: Any) -> TestClient:
    app = FastAPI()
    guard = fastapi_require(
        verifier, permissions=["invoices:read"], organization=lambda r: r.query_params.get("org"), **kw
    )

    @app.get("/invoices")
    async def invoices(principal: Principal = Depends(guard)) -> dict[str, Any]:
        return {"sub": principal.claims.sub if principal.claims else None, "key": bool(principal.api_key)}

    mfa = fastapi_require(verifier, mfa=True, max_age=60)

    @app.get("/sensitive")
    async def sensitive(principal: Principal = Depends(mfa)) -> dict[str, bool]:
        return {"ok": True}

    open_ = fastapi_require(verifier)

    @app.get("/me")
    async def me(request: Request, principal: Principal = Depends(open_)) -> dict[str, bool]:
        return {"same": fastapi_principal_of(request) is principal}

    return TestClient(app)


@respx.mock
def test_fastapi_flow(signer: Signer, verifier: JwtVerifier) -> None:
    c = fastapi_app(verifier)
    ok = c.get("/invoices?org=org-1", headers=auth(signer))
    assert ok.status_code == 200 and ok.json() == {"sub": "user-1", "key": False}
    missing = c.get("/invoices?org=org-1")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"].startswith("Bearer")
    assert missing.json()["detail"]["code"] == "UNAUTHORIZED"
    assert c.get("/invoices?org=org-1", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert c.get("/invoices?org=org-1", headers=auth(signer, exp=1)).status_code == 401
    wrong_org = c.get("/invoices?org=org-2", headers=auth(signer))
    assert wrong_org.status_code == 403 and wrong_org.json()["detail"]["message"] == "organization mismatch"
    no_org = c.get("/invoices", headers=auth(signer))
    assert no_org.status_code == 403
    lacking = c.get("/invoices?org=org-1", headers=auth(signer, permissions=["other"]))
    assert lacking.status_code == 403 and lacking.json()["detail"]["code"] == "FORBIDDEN"
    assert c.get("/me", headers=auth(signer)).json() == {"same": True}


@respx.mock
def test_fastapi_step_up(signer: Signer, verifier: JwtVerifier) -> None:
    c = fastapi_app(verifier)
    assert c.get("/sensitive", headers=auth(signer)).status_code == 200
    stale = c.get("/sensitive", headers=auth(signer, auth_time=int(time.time()) - 3600))
    assert stale.status_code == 403 and stale.json()["detail"]["code"] == "STEP_UP_REQUIRED"
    no_mfa = c.get("/sensitive", headers=auth(signer, amr=["pwd"]))
    assert no_mfa.status_code == 403


@respx.mock
def test_fastapi_outage_is_503(signer: Signer, expected: ExpectedToken) -> None:
    respx.get(JWKS).respond(500)
    c = fastapi_app(JwtVerifier(expected))
    r = c.get("/invoices?org=org-1", headers=auth(signer))
    assert r.status_code == 503 and r.json()["detail"]["code"] == "UNAVAILABLE"
    # no JWKS detail leaks to the client
    assert "JWKS" not in r.text


@respx.mock
def test_fastapi_api_keys_are_opt_in(signer: Signer, verifier: JwtVerifier) -> None:
    route = respx.post(INTROSPECT).respond(200, json={"active": True, "claims": key_claims()})
    refused = fastapi_app(verifier).get("/invoices?org=org-1", headers={"Authorization": f"Bearer {KEYVAL}"})
    assert refused.status_code == 401 and route.call_count == 0
    c = fastapi_app(verifier, allow_api_keys=APIKeyValidator(ISSUER, ENV, AUDIENCE))
    ok = c.get("/invoices?org=org-1", headers={"Authorization": f"Bearer {KEYVAL}"})
    assert ok.status_code == 200 and ok.json() == {"sub": None, "key": True}
    assert c.get("/invoices?org=org-9", headers={"Authorization": f"Bearer {KEYVAL}"}).status_code == 403
    assert (
        c.get("/sensitive", headers={"Authorization": f"Bearer {KEYVAL}"}).status_code == 401
    )  # mfa path: no key validator
    route.respond(200, json={"active": False})
    assert c.get("/invoices?org=org-1", headers={"Authorization": f"Bearer {KEYVAL}"}).status_code == 401


@respx.mock
def test_fastapi_with_introspection(expected: ExpectedToken) -> None:
    respx.post(INTROSPECT).respond(200, json={"active": True, "claims": make_claims()})
    c = fastapi_app(IntrospectionVerifier(expected, ISSUER))
    assert c.get("/invoices?org=org-1", headers={"Authorization": "Bearer opaque"}).status_code == 200
    respx.post(INTROSPECT).respond(502)
    assert c.get("/invoices?org=org-1", headers={"Authorization": "Bearer opaque"}).status_code == 503


# -- Flask --------------------------------------------------------------------------------------


def flask_client(verifier: Any, **kw: Any) -> Any:
    from flask import Flask, jsonify, request

    from iamkit.integrations.flask import IAMKitFlask, current_principal

    app = Flask(__name__)
    guard = IAMKitFlask(verifier, **kw)

    @app.get("/invoices/<org>")
    @guard.require(permissions=["invoices:read"], organization=lambda: request.view_args["org"])  # type: ignore[index]
    def invoices(org: str) -> Any:
        p = current_principal()
        assert p is not None
        return jsonify(sub=p.claims.sub if p.claims else None)

    @app.get("/sensitive")
    @guard.require(mfa=True, max_age=60)
    def sensitive() -> Any:
        return jsonify(ok=True)

    @app.get("/fixed")
    @guard.require(organization="org-1")
    def fixed() -> Any:
        return jsonify(ok=True)

    @app.get("/none")
    def none() -> Any:
        return jsonify(principal=current_principal() is None)

    return app.test_client()


@respx.mock
def test_flask_flow(signer: Signer, verifier: JwtVerifier) -> None:
    c = flask_client(verifier)
    ok = c.get("/invoices/org-1", headers=auth(signer))
    assert ok.status_code == 200 and ok.get_json() == {"sub": "user-1"}
    miss = c.get("/invoices/org-1")
    assert miss.status_code == 401 and miss.headers["WWW-Authenticate"].startswith("Bearer")
    assert miss.get_json()["error"]["code"] == "UNAUTHORIZED"
    assert c.get("/invoices/org-2", headers=auth(signer)).status_code == 403
    assert c.get("/invoices/org-1", headers=auth(signer, permissions=["x"])).status_code == 403
    assert c.get("/invoices/org-1", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert c.get("/sensitive", headers=auth(signer)).status_code == 200
    assert c.get("/sensitive", headers=auth(signer, auth_time=1)).get_json()["error"]["code"] == "STEP_UP_REQUIRED"
    assert c.get("/fixed", headers=auth(signer)).status_code == 200
    assert c.get("/fixed", headers=auth(signer, organization_id="org-2")).status_code == 403
    assert c.get("/none").get_json() == {"principal": True}


@respx.mock
def test_flask_outage_and_keys(signer: Signer, expected: ExpectedToken, verifier: JwtVerifier) -> None:
    respx.get(JWKS).respond(500)
    r = flask_client(JwtVerifier(expected)).get("/invoices/org-1", headers=auth(signer))
    assert r.status_code == 503 and r.get_json()["error"]["code"] == "UNAVAILABLE"
    respx.post(INTROSPECT).respond(200, json={"active": True, "claims": key_claims()})
    hdr = {"Authorization": f"Bearer {KEYVAL}"}
    assert flask_client(verifier).get("/invoices/org-1", headers=hdr).status_code == 401
    keyed = flask_client(verifier, allow_api_keys=APIKeyValidator(ISSUER, ENV, AUDIENCE))
    assert keyed.get("/invoices/org-1", headers=hdr).status_code == 200


# -- Django -------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def django_ready() -> None:
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=False,
            SECRET_KEY="test-only-" + "x" * 30,
            ALLOWED_HOSTS=["*"],
            ROOT_URLCONF=__name__,
            USE_TZ=True,
            INSTALLED_APPS=[],
            MIDDLEWARE=[],
        )
        django.setup()


def django_get(verifier: Any, view_kwargs: dict[str, Any], headers: dict[str, str], api_keys: Any = None) -> Any:
    from django.http import JsonResponse
    from django.test import RequestFactory, override_settings

    from iamkit.integrations.django import IAMKitMiddleware, principal_of, require_token

    @require_token(**view_kwargs)
    def view(request: Any, org: str = "") -> Any:
        p = principal_of(request)
        return JsonResponse({"sub": p.claims.sub if p and p.claims else None, "org": org})

    request = RequestFactory().get("/x", headers=headers)
    with override_settings(IAMKIT_VERIFIER=verifier, IAMKIT_API_KEYS=api_keys):
        middleware = IAMKitMiddleware(lambda r: view(r, org="org-1"))
        return middleware(request)


@respx.mock
@pytest.mark.usefixtures("django_ready")
def test_django_flow(signer: Signer, verifier: JwtVerifier) -> None:
    import json

    def run(headers: dict[str, str], **view: Any) -> Any:
        return django_get(verifier, view, headers)

    ok = run(auth(signer), permissions=["invoices:read"], organization=lambda request, org: org)
    assert ok.status_code == 200 and json.loads(ok.content) == {"sub": "user-1", "org": "org-1"}
    anon = run({}, permissions=["invoices:read"])
    assert anon.status_code == 401 and json.loads(anon.content)["error"]["code"] == "UNAUTHORIZED"
    bad = run({"Authorization": "Bearer junk"})
    assert bad.status_code == 401 and bad["WWW-Authenticate"].startswith("Bearer")
    assert run(auth(signer), organization="org-2").status_code == 403
    assert run(auth(signer), permissions=["nope"]).status_code == 403
    assert run(auth(signer, auth_time=1), mfa=True, max_age=60).status_code == 403
    assert run(auth(signer), mfa=True, max_age=60).status_code == 200


@respx.mock
@pytest.mark.usefixtures("django_ready")
def test_django_outage_keys_and_settings(signer: Signer, expected: ExpectedToken, verifier: JwtVerifier) -> None:
    from django.test import override_settings

    from iamkit.integrations.django import IAMKitMiddleware

    respx.get(JWKS).respond(500)
    r = django_get(JwtVerifier(expected), {}, auth(signer))
    assert r.status_code == 503
    respx.post(INTROSPECT).respond(200, json={"active": True, "claims": key_claims()})
    hdr = {"Authorization": f"Bearer {KEYVAL}"}
    assert django_get(verifier, {}, hdr).status_code == 401
    assert django_get(verifier, {}, hdr, APIKeyValidator(ISSUER, ENV, AUDIENCE)).status_code == 200
    with override_settings(IAMKIT_VERIFIER=None), pytest.raises(RuntimeError):
        IAMKitMiddleware(lambda r: r)
    with override_settings(IAMKIT_VERIFIER="tests.test_integrations.DOTTED"):
        assert IAMKitMiddleware(lambda r: r)._auth.verifier is DOTTED


DOTTED = object()
urlpatterns: list[Any] = []


def test_httpx_headers_object_is_accepted_by_webhooks() -> None:
    import base64
    import hashlib
    import hmac

    from iamkit import verify_webhook

    key = b"q" * 32
    body = b'{"id":1,"type":"x"}'
    ts = str(int(time.time()))
    sig = base64.b64encode(hmac.new(key, f"m.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    h = httpx.Headers({"Webhook-Id": "m", "Webhook-Timestamp": ts, "Webhook-Signature": f"v1,{sig}"})
    assert verify_webhook("whsec_" + base64.b64encode(key).decode(), h, body).id == 1
