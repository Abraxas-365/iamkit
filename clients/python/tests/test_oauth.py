from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from iamkit import (
    ClientAuth,
    GrantTypes,
    IAMKitError,
    KeyBoundary,
    KeyLogin,
    OAuthClient,
    adiscover,
    create_pkce,
    discover,
    random_token,
)

from .conftest import ISSUER

TOKEN = f"{ISSUER}/oauth/token"
TOKENS = {"access_token": "at", "token_type": "Bearer", "expires_in": 300, "refresh_token": "rt", "id_token": "it"}


def form(call: respx.models.Call) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(call.request.read().decode()).items()}


def test_pkce_and_random() -> None:
    p = create_pkce()
    assert len(p.verifier) == 43
    want = base64.urlsafe_b64encode(hashlib.sha256(p.verifier.encode()).digest()).rstrip(b"=").decode()
    assert p.challenge == want
    assert create_pkce().verifier != p.verifier
    assert random_token() != random_token()


def test_authorization_url() -> None:
    c = OAuthClient(ISSUER, "client-1")
    url = c.authorization_url(
        redirect_uri="https://app.test/cb",
        state="state-123",
        nonce="n1",
        code_challenge="chal",
        scopes=["profile", "openid"],
        organization_id="org-1",
        connection_id="conn-1",
        prompt=["login", "consent"],
        max_age=0,
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/oauth/authorize"
    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
    assert q["scope"] == "openid profile"
    assert (q["state"], q["nonce"], q["code_challenge"], q["client_id"]) == ("state-123", "n1", "chal", "client-1")
    assert (q["organization_id"], q["connection_id"], q["prompt"], q["max_age"]) == (
        "org-1",
        "conn-1",
        "login consent",
        "0",
    )
    assert "prompt=none" in c.authorization_url(
        redirect_uri="r", state="state-123", nonce="n", code_challenge="c", prompt="none"
    )


def test_authorization_url_validation() -> None:
    c = OAuthClient(ISSUER, "client-1")
    base = {"redirect_uri": "r", "state": "state-123", "nonce": "n", "code_challenge": "c"}
    for over in ({"state": "short"}, {"nonce": ""}, {"code_challenge": ""}, {"redirect_uri": ""}, {"max_age": -1}):
        with pytest.raises(IAMKitError):
            c.authorization_url(**{**base, **over})  # type: ignore[arg-type]
    with pytest.raises(IAMKitError):
        OAuthClient(ISSUER, "")


def test_end_session_url() -> None:
    url = OAuthClient(ISSUER, "c1").end_session_url(
        id_token_hint="idt", post_logout_redirect_uri="https://app.test/bye", state="s"
    )
    q = parse_qs(urlsplit(url).query)
    assert urlsplit(url).path == "/oauth/end_session"
    assert (q["client_id"], q["id_token_hint"], q["state"]) == (["c1"], ["idt"], ["s"])
    assert "id_token_hint" not in OAuthClient(ISSUER, "c1").end_session_url()


@respx.mock
def test_exchange_code_basic_auth() -> None:
    route = respx.post(TOKEN).respond(200, json=TOKENS)
    c = OAuthClient(ISSUER, "client-1", client_secret="s3cr3t")
    t = c.exchange_code("code-1", "https://app.test/cb", "verifier")
    assert (t.access_token, t.refresh_token, t.id_token, t.expires_in) == ("at", "rt", "it", 300)
    call = route.calls.last
    assert call.request.headers["authorization"] == "Basic " + base64.b64encode(b"client-1:s3cr3t").decode()
    f = form(call)
    assert f["grant_type"] == GrantTypes.AUTHORIZATION_CODE
    assert (f["code"], f["redirect_uri"], f["code_verifier"]) == ("code-1", "https://app.test/cb", "verifier")
    assert call.request.headers["content-type"] == "application/x-www-form-urlencoded"


@respx.mock
def test_public_and_post_clients() -> None:
    route = respx.post(TOKEN).respond(200, json=TOKENS)
    OAuthClient(ISSUER, "pub").refresh("rt-1")
    assert "authorization" not in route.calls.last.request.headers
    assert form(route.calls.last) == {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "pub"}
    OAuthClient(ISSUER, "c", auth=ClientAuth.post("sec")).refresh("rt-1")
    assert form(route.calls.last)["client_secret"] == "sec"
    assert "authorization" not in route.calls.last.request.headers


@respx.mock
def test_client_credentials_and_errors() -> None:
    route = respx.post(TOKEN).respond(200, json=TOKENS)
    c = OAuthClient(ISSUER, "svc", client_secret="s")
    assert c.client_credentials().access_token == "at"
    assert form(route.calls.last)["grant_type"] == "client_credentials"
    route.respond(400, json={"error": "invalid_grant", "error_description": "code expired"})
    with pytest.raises(IAMKitError) as exc:
        c.exchange_code("c", "r", "v")
    assert (exc.value.status, exc.value.code, exc.value.message) == (400, "invalid_grant", "code expired")


@respx.mock
def test_private_key_jwt(rsa_pem: str, ec_pem: str) -> None:
    route = respx.post(TOKEN).respond(200, json=TOKENS)
    for pem, alg in ((rsa_pem, "RS256"), (ec_pem, "ES256")):
        c = OAuthClient(ISSUER, "svc", auth=ClientAuth.private_key_jwt(pem, "key-1"))
        c.client_credentials()
        f = form(route.calls.last)
        assert f["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        header = jwt.get_unverified_header(f["client_assertion"])
        assert (header["kid"], header["alg"]) == ("key-1", alg)
        payload = jwt.decode(
            f["client_assertion"], options={"verify_signature": False}, audience=f"{ISSUER}/oauth/token"
        )
        assert payload["iss"] == payload["sub"] == "svc" and payload["exp"] - payload["iat"] == 60
        assert "authorization" not in route.calls.last.request.headers
    c = OAuthClient(
        ISSUER, "svc", auth=ClientAuth.private_key_jwt(rsa_pem, "k", alg="PS256"), issuer="https://public.test/"
    )
    c.client_credentials()
    a = jwt.decode(
        form(route.calls.last)["client_assertion"],
        options={"verify_signature": False},
        audience="https://public.test/oauth/token",
    )
    assert a["aud"] == "https://public.test/oauth/token"
    assert jwt.get_unverified_header(form(route.calls.last)["client_assertion"])["alg"] == "PS256"


def test_bad_private_keys() -> None:
    for key in ("not a pem", b"junk", object()):
        c = OAuthClient(ISSUER, "svc", auth=ClientAuth.private_key_jwt(key, "k"))
        with pytest.raises(IAMKitError):
            c._assertion()
    with pytest.raises(IAMKitError):
        KeyLogin(ISSUER, "", "k", "pem")


@respx.mock
def test_token_exchange_and_impersonation() -> None:
    route = respx.post(TOKEN).respond(
        200,
        json={
            "access_token": "x",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 60,
        },
    )
    c = OAuthClient(ISSUER, "svc", client_secret="s")
    ex = c.exchange_token("subj", "https://other.test", ["a:b", "c:d"])
    assert (ex.access_token, ex.expires_in) == ("x", 60)
    f = form(route.calls.last)
    assert f["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert (f["subject_token"], f["audience"], f["scope"]) == ("subj", "https://other.test", "a:b c:d")
    assert f["subject_token_type"].endswith("access_token")
    c.impersonate("user-1", "org-1", "support case")
    f2 = form(route.calls.last)
    assert (f2["subject_token"], f2["organization_id"], f2["reason"]) == ("user-1", "org-1", "support case")
    assert f2["subject_token_type"] != f["subject_token_type"]


@respx.mock
def test_revoke_userinfo_introspect() -> None:
    respx.post(f"{ISSUER}/oauth/revoke").respond(200)
    respx.get(f"{ISSUER}/oauth/userinfo").respond(200, json={"sub": "u1", "email": "a@b.c"})
    intro = respx.post(f"{ISSUER}/oauth/introspect").respond(
        200, json={"active": True, "sub": "u1", "scope": "openid", "permissions": ["a"], "exp": 5}
    )
    c = OAuthClient(ISSUER, "c1", client_secret="s")
    c.revoke("tok")
    assert c.user_info("at")["sub"] == "u1"
    i = c.introspect("tok")
    assert i.active and i.sub == "u1" and i.permissions == ["a"]
    assert intro.calls.last.request.headers["authorization"].startswith("Basic ")
    intro.respond(200, json={"active": False})
    assert not c.introspect("tok").active
    with pytest.raises(IAMKitError) as exc:
        OAuthClient(ISSUER, "pub").introspect("tok")
    assert exc.value.code == "invalid_client"


@respx.mock
def test_device_flow() -> None:
    respx.post(f"{ISSUER}/oauth/device_authorization").respond(
        200,
        json={
            "device_code": "dc",
            "user_code": "BCDFGHJK",
            "verification_uri": f"{ISSUER}/hosted/device",
            "expires_in": 600,
            "interval": 5,
        },
    )
    c = OAuthClient(ISSUER, "tv")
    auth = c.authorize_device(["openid"])
    assert (auth.device_code, auth.user_code, auth.interval) == ("dc", "BCDFGHJK", 5)
    route = respx.post(TOKEN)
    route.side_effect = [
        respx.MockResponse(400, json={"error": "authorization_pending"}),
        respx.MockResponse(400, json={"error": "slow_down"}),
        respx.MockResponse(200, json=TOKENS),
    ]
    tokens = c.wait_for_device(auth, step=0.001)
    assert tokens.access_token == "at"
    assert form(route.calls.last)["grant_type"] == GrantTypes.DEVICE_CODE
    assert form(route.calls.last)["device_code"] == "dc"


@respx.mock
def test_device_flow_terminal_errors() -> None:
    c = OAuthClient(ISSUER, "tv")
    from iamkit.oauth import DeviceAuthorization

    auth = DeviceAuthorization("dc", "U", "https://v", interval=1)
    respx.post(TOKEN).respond(400, json={"error": "access_denied"})
    with pytest.raises(IAMKitError) as exc:
        c.wait_for_device(auth, step=0.001)
    assert exc.value.code == "access_denied"
    respx.post(TOKEN).respond(400, json={"error": "authorization_pending"})
    with pytest.raises(IAMKitError) as exc2:
        c.wait_for_device(auth, step=0.001, timeout=0.01)
    assert exc2.value.code == "expired_token"


@respx.mock
async def test_async_paths() -> None:
    route = respx.post(TOKEN).respond(200, json=TOKENS)
    respx.post(f"{ISSUER}/oauth/revoke").respond(200)
    respx.get(f"{ISSUER}/oauth/userinfo").respond(200, json={"sub": "u"})
    respx.post(f"{ISSUER}/oauth/introspect").respond(200, json={"active": True, "sub": "u"})
    respx.post(f"{ISSUER}/oauth/device_authorization").respond(
        200, json={"device_code": "d", "user_code": "u", "verification_uri": "https://v", "interval": 1}
    )
    c = OAuthClient(ISSUER, "c1", client_secret="s")
    assert (await c.aexchange_code("c", "r", "v")).access_token == "at"
    assert (await c.arefresh("r")).access_token == "at"
    assert (await c.aclient_credentials()).access_token == "at"
    assert (await c.aexchange_token("s", "aud")).access_token == "at"
    assert (await c.aimpersonate("u", "o", "why")).access_token == "at"
    await c.arevoke("t")
    assert (await c.auser_info("at"))["sub"] == "u"
    assert (await c.aintrospect("t")).active
    auth = await c.aauthorize_device()
    assert (await c.apoll_device("d")).access_token == "at"
    assert (await c.await_for_device(auth, step=0.001)).access_token == "at"
    assert route.call_count >= 6
    respx.post(TOKEN).respond(400, json={"error": "access_denied"})
    with pytest.raises(IAMKitError):
        await c.await_for_device(auth, step=0.001)
    respx.post(TOKEN).respond(400, json={"error": "authorization_pending"})
    with pytest.raises(IAMKitError) as exc:
        await c.await_for_device(auth, step=0.001, timeout=0.01)
    assert exc.value.code == "expired_token"
    await c.aclose()


@respx.mock
def test_key_login(rsa_pem: str) -> None:
    route = respx.post(TOKEN).respond(200, json={"access_token": "mt", "expires_in": 300})
    kl = KeyLogin(ISSUER, "machine-1", "key-1", rsa_pem)
    t = kl.token(KeyBoundary("org-1", "app-1", "res-1"))
    assert t.access_token == "mt"
    f = form(route.calls.last)
    assert f["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assert (f["organization_id"], f["application_id"], f["resource_id"]) == ("org-1", "app-1", "res-1")
    assert "environment_id" not in f and "client_id" not in f
    claims = jwt.decode(f["assertion"], options={"verify_signature": False}, audience=f"{ISSUER}/oauth/token")
    assert claims["iss"] == claims["sub"] == "machine-1" and claims["jti"]
    assert jwt.get_unverified_header(f["assertion"])["kid"] == "key-1"
    kl.token(KeyBoundary("o", "a", "r", environment_id="env-9"))
    assert form(route.calls.last)["environment_id"] == "env-9"
    assert kl.assertion() != kl.assertion()  # fresh jti every time
    route.respond(400, json={"error": "invalid_grant", "error_description": "no"})
    with pytest.raises(IAMKitError) as exc:
        kl.token(KeyBoundary("o", "a", "r"))
    assert exc.value.code == "invalid_grant"
    kl.close()


@respx.mock
async def test_key_login_async_ec(ec_pem: str) -> None:
    respx.post(TOKEN).respond(200, json={"access_token": "mt"})
    kl = KeyLogin(ISSUER, "m", "k", ec_pem)
    assert (await kl.atoken(KeyBoundary("o", "a", "r"))).access_token == "mt"
    assert jwt.get_unverified_header(kl.assertion())["alg"] == "ES256"
    await kl.aclose()


def test_key_objects_accepted() -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert KeyLogin(ISSUER, "m", "k", rsa_key).assertion()
    ec_key = ec.generate_private_key(ec.SECP384R1())
    assert jwt.get_unverified_header(KeyLogin(ISSUER, "m", "k", ec_key).assertion())["alg"] == "ES384"


@respx.mock
async def test_discovery() -> None:
    doc = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": TOKEN,
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "prompt_values_supported": ["none", "login"],
        "extra_field": 1,
    }
    respx.get(f"{ISSUER}/.well-known/openid-configuration").respond(200, json=doc)
    d = discover(ISSUER)
    assert d.token_endpoint == TOKEN and d.prompt_values_supported == ["none", "login"]
    assert d.raw["extra_field"] == 1
    assert (await adiscover(ISSUER)).issuer == ISSUER
