from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from iamkit import (
    AccessClaims,
    ExpectedToken,
    IAMKitError,
    IntrospectionVerifier,
    JwtVerifier,
    KeySet,
    averify_id_token,
    averify_logout_token,
    has_mfa,
    has_permission,
    has_recent_mfa,
    is_fresh,
    is_impersonated,
    require_mfa,
    require_permission,
    verify_id_token,
    verify_logout_token,
)
from iamkit.tokens import BACKCHANNEL_LOGOUT_EVENT

from .conftest import AUDIENCE, ISSUER, Signer, make_claims

JWKS = f"{ISSUER}/.well-known/jwks.json"


def jwks_route(*signers: Signer) -> respx.Route:
    return respx.get(JWKS).respond(200, json={"keys": [s.jwk for s in signers]})


@respx.mock
def test_verify_ok(signer: Signer, expected: ExpectedToken) -> None:
    jwks_route(signer)
    v = JwtVerifier(expected)
    claims = v.verify(signer.sign(make_claims()))
    assert claims.sub == "user-1"
    assert claims.organization_id == "org-1"
    assert claims.has_permission("invoices:read")
    assert claims.has_mfa and not claims.impersonated
    assert claims.aud == (AUDIENCE,)


@respx.mock
def test_verify_rejections(signer: Signer, other_signer: Signer, expected: ExpectedToken) -> None:
    jwks_route(signer)
    v = JwtVerifier(expected)
    now = int(time.time())
    bad: list[str] = [
        signer.sign(make_claims(iss="https://evil.test")),
        signer.sign(make_claims(aud=["https://other.test"])),
        signer.sign(make_claims(exp=now - 100)),
        signer.sign(make_claims(environment_id="env-2")),
        signer.sign(make_claims(application_id="app-2")),
        signer.sign(make_claims(resource_id="res-2")),
        signer.sign(make_claims(purpose="api_key")),
        signer.sign(make_claims(organization_id=None)),  # application token needs organization
        signer.sign(make_claims(sid=None)),
        signer.sign(make_claims(purpose="machine")),  # machine token with org/sid
        signer.sign(make_claims(sub=None)),
        signer.sign(make_claims(), alg="RS512"),  # alg not on the allowlist
        "not-a-jwt",
        "",
    ]
    # a token signed by a key with the same kid but a different private key
    forged = Signer(other_signer.private, signer.kid).sign(make_claims())
    bad.append(forged)
    for token in bad:
        with pytest.raises(IAMKitError) as exc:
            v.verify(token)
        assert exc.value.status == 401, token


@respx.mock
def test_alg_none_and_hs256_refused(signer: Signer, expected: ExpectedToken) -> None:
    import jwt

    jwks_route(signer)
    v = JwtVerifier(expected)
    none_token = jwt.encode(make_claims(), "", algorithm="none", headers={"kid": signer.kid})
    hs = jwt.encode(make_claims(), "x" * 40, algorithm="HS256", headers={"kid": signer.kid})
    for token in (none_token, hs):
        with pytest.raises(IAMKitError) as exc:
            v.verify(token)
        assert exc.value.status == 401


@respx.mock
def test_machine_token(signer: Signer, expected: ExpectedToken) -> None:
    jwks_route(signer)
    claims = JwtVerifier(expected).verify(
        signer.sign(make_claims(purpose="machine", organization_id=None, sid=None, amr=None, auth_time=None))
    )
    assert claims.purpose == "machine" and claims.organization_id is None
    assert not claims.has_mfa


@respx.mock
def test_leeway(signer: Signer, expected: ExpectedToken) -> None:
    jwks_route(signer)
    token = signer.sign(make_claims(exp=int(time.time()) - 5))
    with pytest.raises(IAMKitError):
        JwtVerifier(expected).verify(token)
    assert JwtVerifier(expected, leeway=30).verify(token).sub == "user-1"


@respx.mock
def test_kid_miss_refetch_and_cooldown(signer: Signer, other_signer: Signer, expected: ExpectedToken) -> None:
    route = jwks_route(signer)
    v = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, cooldown=0))
    v.verify(signer.sign(make_claims()))
    assert route.call_count == 1
    v.verify(signer.sign(make_claims()))
    assert route.call_count == 1  # cached
    # rotation: the new key is published, an unknown kid refetches
    route.respond(200, json={"keys": [signer.jwk, other_signer.jwk]})
    assert v.verify(other_signer.sign(make_claims())).sub == "user-1"
    assert route.call_count == 2
    # a kid that stays unknown is 401, one refetch per attempt
    stranger = Signer(other_signer.private, "kid-unknown")
    with pytest.raises(IAMKitError) as exc:
        v.verify(stranger.sign(make_claims()))
    assert exc.value.status == 401
    assert route.call_count == 3


@respx.mock
def test_unknown_kid_refetch_is_rate_limited(signer: Signer, other_signer: Signer, expected: ExpectedToken) -> None:
    route = jwks_route(signer)
    v = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, cooldown=3600))
    v.verify(signer.sign(make_claims()))
    route.respond(200, json={"keys": [signer.jwk, other_signer.jwk]})
    for _ in range(3):  # inside the cooldown the rotated key is not fetched: a flood cannot hammer the JWKS
        with pytest.raises(IAMKitError) as exc:
            v.verify(other_signer.sign(make_claims()))
        assert exc.value.status == 401
    assert route.call_count == 1


@respx.mock
def test_max_age_refetch(signer: Signer, expected: ExpectedToken) -> None:
    route = jwks_route(signer)
    v = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, max_age=0, cooldown=0))
    v.verify(signer.sign(make_claims()))
    v.verify(signer.sign(make_claims()))
    assert route.call_count == 2


@respx.mock
def test_stale_refetch_is_rate_limited(signer: Signer, expected: ExpectedToken) -> None:
    route = jwks_route(signer)
    v = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, max_age=0, cooldown=3600))
    for _ in range(3):  # a stale set is refetched at most once per cooldown
        v.verify(signer.sign(make_claims()))
    assert route.call_count == 1


@respx.mock
def test_jwks_outage_serves_cached_keys_within_grace(signer: Signer, expected: ExpectedToken) -> None:
    route = jwks_route(signer)
    v = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, max_age=0, cooldown=0))
    v.verify(signer.sign(make_claims()))
    route.respond(500)
    for _ in range(2):  # the endpoint fails: the cached key keeps verifying
        v.verify(signer.sign(make_claims()))
    expired = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, max_age=0, cooldown=0, stale_grace=0))
    route.respond(200, json={"keys": [signer.jwk]})
    expired.verify(signer.sign(make_claims()))
    route.respond(500)
    with pytest.raises(IAMKitError) as exc:  # past the grace a failing endpoint is an outage
        expired.verify(signer.sign(make_claims()))
    assert exc.value.status == 503


def test_keyset_requires_https() -> None:
    with pytest.raises(IAMKitError):
        KeySet(issuer="http://iam.example.com")
    with pytest.raises(IAMKitError):
        KeySet(jwks_url="ftp://iam.example.com/jwks.json")
    for ok in (
        "https://iam.example.com",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://iam.localhost",
    ):
        KeySet(issuer=ok)


@respx.mock
def test_jwks_outage_is_503(signer: Signer, expected: ExpectedToken) -> None:
    respx.get(JWKS).respond(500)
    v = JwtVerifier(expected)
    with pytest.raises(IAMKitError) as exc:
        v.verify(signer.sign(make_claims()))
    assert (exc.value.status, exc.value.code) == (503, "JWKS_UNAVAILABLE")
    # cooling down after an outage still reports an outage, not a bad token
    with pytest.raises(IAMKitError) as exc2:
        v.verify(signer.sign(make_claims()))
    assert exc2.value.status == 503


@respx.mock
def test_jwks_network_error_and_garbage(signer: Signer, expected: ExpectedToken) -> None:
    respx.get(JWKS).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(IAMKitError) as exc:
        JwtVerifier(expected).verify(signer.sign(make_claims()))
    assert exc.value.status == 503
    respx.get(JWKS).respond(200, json={"nope": 1})
    with pytest.raises(IAMKitError) as exc2:
        JwtVerifier(expected).verify(signer.sign(make_claims()))
    assert exc2.value.status == 503


@respx.mock
def test_keyset_skips_unusable_keys(signer: Signer) -> None:
    respx.get(JWKS).respond(
        200, json={"keys": [{"kty": "oct", "kid": "x"}, {**signer.jwk, "use": "enc", "kid": "e"}, 5, signer.jwk]}
    )
    keys = KeySet(jwks_url=JWKS)
    assert keys.get_key(signer.sign(make_claims())).key is not None
    with pytest.raises(IAMKitError):
        KeySet()


@respx.mock
async def test_async_verify(signer: Signer, other_signer: Signer, expected: ExpectedToken) -> None:
    route = jwks_route(signer)
    v = JwtVerifier(expected, keys=KeySet(issuer=ISSUER, cooldown=0))
    assert (await v.averify(signer.sign(make_claims()))).sub == "user-1"
    with pytest.raises(IAMKitError):
        await v.averify("")
    route.respond(200, json={"keys": [signer.jwk, other_signer.jwk]})
    assert (await v.averify(other_signer.sign(make_claims()))).sub == "user-1"
    respx.get(JWKS).respond(503)
    broken = JwtVerifier(expected)
    with pytest.raises(IAMKitError) as exc:
        await broken.averify(signer.sign(make_claims()))
    assert exc.value.status == 503
    await v.keys.aclose()


def test_expected_requires_everything() -> None:
    with pytest.raises(IAMKitError):
        ExpectedToken(issuer="", audience="a", environment_id="e", application_id="a", resource_id="r")


def test_claim_helpers(claims_factory: Callable[..., dict[str, Any]]) -> None:
    c = AccessClaims.from_payload(claims_factory(actor_id="op-1"))
    assert is_impersonated(c) and c.impersonated
    via_act = AccessClaims.from_payload(claims_factory(act={"sub": "svc-1"}))
    assert via_act.act_sub == "svc-1" and is_impersonated(via_act)
    legacy = AccessClaims.from_payload(claims_factory(actor_account_id="svc-2"))
    assert legacy.act_sub == "svc-2"
    assert has_permission(c, "invoices:read", "invoices:write")
    assert not has_permission(c, "invoices:read", "x")
    assert not has_permission(c)
    assert not has_permission(c, "")
    require_permission(c, "invoices:read")
    with pytest.raises(IAMKitError) as exc:
        require_permission(c, "x")
    assert exc.value.status == 403
    assert has_mfa(c)
    assert not has_mfa(AccessClaims.from_payload(claims_factory(amr=["pwd"])))
    now = time.time()
    assert is_fresh(c, 60, now=now)
    assert not is_fresh(c, 5, now=now)
    assert not is_fresh(AccessClaims.from_payload(claims_factory(auth_time=None)), 60)
    assert has_recent_mfa(c) and has_recent_mfa(c, 60)
    assert not has_recent_mfa(c, 1)
    require_mfa(c, 60)
    with pytest.raises(IAMKitError) as exc2:
        require_mfa(AccessClaims.from_payload(claims_factory(amr=["pwd"])))
    assert (exc2.value.status, exc2.value.code) == (403, "STEP_UP_REQUIRED")
    assert AccessClaims.from_payload({"aud": "single", "scp": ["a", 1]}).aud == ("single",)
    assert AccessClaims.from_payload({"scp": ["a", 1]}).scp == ("a",)


# -- introspection ------------------------------------------------------------------------------


@respx.mock
def test_introspection_verifier(expected: ExpectedToken) -> None:
    route = respx.post(f"{ISSUER}/identity/v1/introspect").respond(200, json={"active": True, "claims": make_claims()})
    v = IntrospectionVerifier(expected, ISSUER)
    assert v.verify("tok").sub == "user-1"
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer tok"
    assert req.read() == b'{"environment_id":"env-1","audience":"https://api.test"}' or b"environment_id" in req.read()
    v.close()


@respx.mock
def test_introspection_rejections(expected: ExpectedToken) -> None:
    route = respx.post(f"{ISSUER}/identity/v1/introspect")
    v = IntrospectionVerifier(expected, ISSUER)
    cases = [
        {"active": False},
        {"active": True},
        {"active": True, "claims": make_claims(environment_id="other")},
        {"active": True, "claims": make_claims(iss="https://evil.test")},
        {"active": True, "claims": make_claims(aud=["x"])},
        {"active": True, "claims": make_claims(purpose="api_key")},
        {"active": True, "claims": make_claims(sub=None)},
        [],
    ]
    for body in cases:
        route.respond(200, json=body)
        with pytest.raises(IAMKitError) as exc:
            v.verify("tok")
        assert exc.value.status == 401
    with pytest.raises(IAMKitError):
        v.verify("")
    route.respond(401, json={"error": {"code": "UNAUTHORIZED", "message": "no"}})
    with pytest.raises(IAMKitError) as exc:
        v.verify("tok")
    assert exc.value.status == 401


@respx.mock
async def test_introspection_fails_closed_on_outage(expected: ExpectedToken) -> None:
    route = respx.post(f"{ISSUER}/identity/v1/introspect").respond(500)
    v = IntrospectionVerifier(expected, ISSUER)
    with pytest.raises(IAMKitError) as exc:
        v.verify("tok")
    assert exc.value.status == 500
    with pytest.raises(IAMKitError) as exc2:
        await v.averify("tok")
    assert exc2.value.status == 500
    route.respond(200, json={"active": True, "claims": make_claims()})
    assert (await v.averify("tok")).sub == "user-1"
    route.respond(401, json={"error": "x"})
    with pytest.raises(IAMKitError) as exc3:
        await v.averify("tok")
    assert exc3.value.code == "UNAUTHORIZED"
    with pytest.raises(IAMKitError):
        await v.averify("")
    await v.aclose()


# -- ID tokens and logout tokens ----------------------------------------------------------------


def id_claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {"iss": ISSUER, "sub": "u1", "aud": "client-1", "exp": now + 60, "iat": now, "nonce": "n-1"}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


@respx.mock
async def test_id_token(signer: Signer) -> None:
    jwks_route(signer)
    keys = KeySet(issuer=ISSUER)
    tok = signer.sign(id_claims())
    assert verify_id_token(tok, issuer=ISSUER, client_id="client-1", keys=keys, nonce="n-1")["sub"] == "u1"
    assert (await averify_id_token(tok, issuer=ISSUER, client_id="client-1", keys=keys, nonce="n-1"))["sub"] == "u1"
    for token, nonce, client in [
        (tok, "wrong", "client-1"),
        (tok, "n-1", "other-client"),
        (signer.sign(id_claims(nonce=None)), "n-1", "client-1"),
        (signer.sign(id_claims(iss="https://evil.test")), "n-1", "client-1"),
    ]:
        with pytest.raises(IAMKitError):
            verify_id_token(token, issuer=ISSUER, client_id=client, keys=keys, nonce=nonce)
        with pytest.raises(IAMKitError):
            await averify_id_token(token, issuer=ISSUER, client_id=client, keys=keys, nonce=nonce)
    with pytest.raises(IAMKitError):
        verify_id_token(tok, issuer=ISSUER, client_id="client-1", keys=keys, nonce="")
    with pytest.raises(IAMKitError):
        await averify_id_token(tok, issuer=ISSUER, client_id="", keys=keys, nonce="n")


@respx.mock
async def test_logout_token(signer: Signer) -> None:
    jwks_route(signer)
    keys = KeySet(issuer=ISSUER)
    now = int(time.time())

    def lt(**over: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "u1",
            "aud": "client-1",
            "iat": now,
            "exp": now + 60,
            "jti": "j1",
            "sid": "s1",
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        }
        base.update(over)
        return {k: v for k, v in base.items() if v is not None}

    ok = verify_logout_token(signer.sign(lt()), issuer=ISSUER, client_id="client-1", keys=keys)
    assert (ok.sub, ok.sid, ok.jti) == ("u1", "s1", "j1")
    ok2 = await averify_logout_token(signer.sign(lt()), issuer=ISSUER, client_id="client-1", keys=keys)
    assert ok2.sid == "s1"
    cases: list[dict[str, Any]] = [
        {"events": None},
        {"events": {"other": {}}},
        {"nonce": "n"},
        {"sid": None},
        {"aud": "other"},
        {"iss": "https://evil.test"},
    ]
    for over in cases:
        with pytest.raises(IAMKitError) as exc:
            verify_logout_token(signer.sign(lt(**over)), issuer=ISSUER, client_id="client-1", keys=keys)
        assert exc.value.status == 400
        with pytest.raises(IAMKitError):
            await averify_logout_token(signer.sign(lt(**over)), issuer=ISSUER, client_id="client-1", keys=keys)
    with pytest.raises(IAMKitError):
        verify_logout_token("x", issuer="", client_id="c", keys=keys)
    with pytest.raises(IAMKitError):
        await averify_logout_token("x", issuer="", client_id="c", keys=keys)
