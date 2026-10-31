"""The resource server: shared canonicalization vectors, metadata, token checks, challenges, introspection,
the ASGI/WSGI/FastAPI integrations and the staleness of the generated async twin."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from iamkit._resource_core import IntrospectionCache
from iamkit.integrations.asgi import ResourceServerMiddleware, claims_of
from iamkit.integrations.wsgi import ResourceServerWSGIMiddleware
from iamkit.integrations.wsgi import claims_of as wsgi_claims_of
from iamkit.resource_server import (
    AsyncResourceServer,
    IntrospectionOptions,
    ResourceClaims,
    ResourceError,
    ResourceServer,
    bearer_token,
    canonical_resource,
    metadata_url,
    permissions_of,
)
from iamkit.tokens import KeySet

from .conftest import ENV, ISSUER, Signer, make_claims

ROOT = Path(__file__).resolve().parents[3]
RESOURCE = "https://mcp.test/mcp"
JWKS = f"{ISSUER}/.well-known/jwks.json"
INTROSPECT = f"{ISSUER}/oauth/introspect"
METADATA = "https://mcp.test/.well-known/oauth-protected-resource/mcp"


def claims(**over: Any) -> dict[str, Any]:
    base = {
        "aud": [RESOURCE],
        "resource": RESOURCE,
        "scp": ["notes:read"],
        "oauth_client_id": "client-1",
        "application_id": "app-1",
        "resource_id": "res-1",
        "permissions": ["from-claim"],
    }
    return make_claims(**{**base, **over})


def server(**over: Any) -> ResourceServer:
    return ResourceServer(ISSUER, RESOURCE, ENV, **over)


@pytest.fixture
def router(signer: Signer) -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(JWKS, name="jwks").respond(200, json={"keys": [signer.jwk]})
        yield mock


@pytest.fixture
def jwks(router: respx.MockRouter) -> respx.Route:
    return router.routes["jwks"]


# -- shared vectors ------------------------------------------------------------------------------------
def _vectors() -> list[dict[str, Any]]:
    path = ROOT / "sdk" / "resourceserver" / "testdata" / "canonical.json"
    cases: list[dict[str, Any]] = json.loads(path.read_text())["cases"]
    return cases


@pytest.mark.parametrize("case", _vectors(), ids=lambda c: c["name"])
def test_canonical_vectors(case: dict[str, Any]) -> None:
    assert canonical_resource(case["input"]) == case["canonical"]


def test_vectors_are_the_35_shared_cases() -> None:
    assert len(_vectors()) == 35


def test_metadata_url() -> None:
    assert metadata_url("https://mcp.example.com") == "https://mcp.example.com/.well-known/oauth-protected-resource"
    assert metadata_url("https://mcp.example.com/a/b") == (
        "https://mcp.example.com/.well-known/oauth-protected-resource/a/b"
    )
    assert metadata_url("http://localhost:3333/mcp") == (
        "http://localhost:3333/.well-known/oauth-protected-resource/mcp"
    )


def test_bearer_token() -> None:
    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("bearer abc") == "abc"
    assert bearer_token("Basic abc") is None
    assert bearer_token("Bearer") is None
    assert bearer_token(None) is None


def test_permissions_of_drops_protocol_scopes() -> None:
    scopes = ["openid", "profile", "email", "phone", "offline_access", "urn:iamkit:org:id:x", "notes:read"]
    assert permissions_of(scopes) == ("notes:read",)


# -- configuration and metadata ------------------------------------------------------------------------
def test_configuration_errors() -> None:
    with pytest.raises(Exception, match="canonical"):
        ResourceServer(ISSUER, "http://mcp.example.com/mcp", ENV)
    with pytest.raises(Exception, match="issuer"):
        ResourceServer("", RESOURCE, ENV)
    with pytest.raises(Exception, match="client_secret"):
        IntrospectionOptions(client_id="c", client_secret="")
    with pytest.raises(Exception, match="negative"):
        IntrospectionOptions(client_id="c", client_secret="s", cache_ttl=-1)


def test_metadata_document() -> None:
    rs = ResourceServer(
        ISSUER,
        "HTTPS://MCP.test:443/mcp/",
        ENV,
        scopes_supported=["notes:read"],
        resource_name="Notes",
        documentation_url="https://docs.test",
    )
    assert rs.resource == RESOURCE
    assert rs.metadata_url == METADATA
    assert rs.metadata_paths == ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource")
    assert rs.metadata() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["notes:read"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Notes",
        "resource_documentation": "https://docs.test",
    }
    assert server().metadata() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    }
    assert ResourceServer(ISSUER, "https://mcp.test", ENV).metadata_paths == ("/.well-known/oauth-protected-resource",)


def test_metadata_reply_methods() -> None:
    rs = server()
    get = rs.metadata_reply("GET")
    assert get.status == 200
    headers = dict(get.headers)
    assert headers["Access-Control-Allow-Origin"] == "*"
    assert headers["Cache-Control"] == "public, max-age=3600"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(get.body) == rs.metadata()
    head = rs.metadata_reply("HEAD")
    assert head.status == 200 and head.body == b""
    options = rs.metadata_reply("OPTIONS")
    assert options.status == 204
    assert dict(options.headers)["Access-Control-Allow-Methods"] == "GET, OPTIONS"
    assert dict(options.headers)["Access-Control-Max-Age"] == "86400"
    post = rs.metadata_reply("POST")
    assert post.status == 405 and dict(post.headers)["Allow"] == "GET, OPTIONS"


# -- verify --------------------------------------------------------------------------------------------
def test_verify_ok(signer: Signer, jwks: respx.Route) -> None:
    got = server().verify(signer.sign(claims(scp=["openid", "notes:read", "urn:iamkit:org:id:org-1"])))
    assert isinstance(got, ResourceClaims)
    assert got.sub == "user-1" and got.organization_id == "org-1" and got.session_id == "sess-1"
    assert got.environment_id == ENV and got.application_id == "app-1" and got.resource_id == "res-1"
    assert got.oauth_client_id == "client-1" and got.resource == RESOURCE
    assert got.scopes == ("openid", "notes:read", "urn:iamkit:org:id:org-1")
    assert got.permissions == ("notes:read",)  # the `permissions` claim is never read
    assert got.amr == ("pwd", "mfa") and got.auth_time is not None


def test_scope_claim_used_without_scp(signer: Signer, jwks: respx.Route) -> None:
    token = signer.sign(claims(scp=None, scope="openid notes:read notes:write"))
    got = server().verify(token)
    assert got.scopes == ("openid", "notes:read", "notes:write")
    assert got.permissions == ("notes:read", "notes:write")


def test_audience_may_be_a_string_and_is_compared_canonically(signer: Signer, jwks: respx.Route) -> None:
    server().verify(signer.sign(claims(aud="https://MCP.test:443/mcp/", resource="https://mcp.test/mcp/")))


@pytest.mark.parametrize(
    "over",
    [
        {"aud": ["https://other.test/mcp"]},
        {"iss": "https://elsewhere.test"},
        {"environment_id": "env-other"},
        {"purpose": "machine"},
        {"sid": None},
        {"organization_id": None},
        {"sub": None},
        {"exp": 1},
        {"resource": None},
        {"resource": "https://other.test/mcp"},
        {"resource": "not a uri"},
    ],
    ids=lambda o: next(iter(o)) + "=" + str(next(iter(o.values()))),
)
def test_verify_rejects(signer: Signer, jwks: respx.Route, over: dict[str, Any]) -> None:
    with pytest.raises(ResourceError) as exc:
        server().verify(signer.sign(claims(**over)))
    assert exc.value.status == 401 and exc.value.code == "invalid_token"
    assert exc.value.www_authenticate is not None
    assert 'error="invalid_token"' in exc.value.www_authenticate


def test_no_token_and_garbage(jwks: respx.Route) -> None:
    with pytest.raises(ResourceError) as exc:
        server().verify("")
    assert (exc.value.status, exc.value.code) == (401, "unauthorized")
    assert exc.value.www_authenticate == f'Bearer resource_metadata="{METADATA}"'
    with pytest.raises(ResourceError) as bad:
        server().verify("not.a.jwt")
    assert bad.value.code == "invalid_token"


def test_other_algorithms_refused(signer: Signer, jwks: respx.Route) -> None:
    import jwt

    none = jwt.encode(claims(), "", algorithm="none", headers={"kid": signer.kid})
    hs = jwt.encode(claims(), "x" * 40, algorithm="HS256", headers={"kid": signer.kid})
    for token in (none, hs):
        with pytest.raises(ResourceError) as exc:
            server().verify(token)
        assert exc.value.status == 401


def test_leeway(signer: Signer, jwks: respx.Route) -> None:
    token = signer.sign(claims(exp=int(time.time()) - 5))
    assert server().verify(token).sub == "user-1"
    with pytest.raises(ResourceError):
        server(leeway=0).verify(token)


def test_allow_tokens_without_resource(signer: Signer, jwks: respx.Route) -> None:
    token = signer.sign(claims(resource=None))
    got = server(allow_tokens_without_resource=True).verify(token)
    assert got.resource is None
    # a marker that is present must still be this resource
    with pytest.raises(ResourceError):
        server(allow_tokens_without_resource=True).verify(signer.sign(claims(resource="https://other.test/mcp")))


def test_organizations(signer: Signer, jwks: respx.Route) -> None:
    token = signer.sign(claims())
    assert server(organizations=["org-1", "org-2"]).verify(token).organization_id == "org-1"
    with pytest.raises(ResourceError) as exc:
        server(organizations=["org-2"]).verify(token)
    assert exc.value.code == "invalid_token"


def test_jwks_outage_is_503_without_challenge(signer: Signer) -> None:
    with respx.mock() as router:
        router.get(JWKS).respond(500)
        with pytest.raises(ResourceError) as exc:
            server().verify(signer.sign(claims()))
    assert (exc.value.status, exc.value.code) == (503, "temporarily_unavailable")
    assert exc.value.www_authenticate is None


def test_shared_key_set(signer: Signer, jwks: respx.Route) -> None:
    keys = KeySet(issuer=ISSUER)
    one, two = server(keys=keys), server(keys=keys)
    one.verify(signer.sign(claims()))
    two.verify(signer.sign(claims()))
    assert jwks.call_count == 1
    one.close()  # the shared key set is not closed by a server that did not make it


# -- require and challenges ----------------------------------------------------------------------------
def test_require_and_challenge(signer: Signer, jwks: respx.Route) -> None:
    rs = server()
    got = rs.verify(signer.sign(claims(scp=["notes:read"])))
    rs.require(got, "notes:read")
    with pytest.raises(ResourceError) as exc:
        rs.require(got, "notes:read", "notes:write")
    err = exc.value
    assert (err.status, err.code) == (403, "insufficient_scope")
    assert err.required == ("notes:read", "notes:write") and err.granted == ("notes:read",)
    assert err.www_authenticate == (
        f'Bearer error="insufficient_scope", resource_metadata="{METADATA}", scope="notes:read notes:write"'
    )
    assert rs.challenge(err) == err.www_authenticate


def test_challenge_variants() -> None:
    rs = server()
    assert rs.challenge(rs.fail("unauthorized")) == f'Bearer resource_metadata="{METADATA}"'
    assert rs.challenge(rs.fail("unauthorized"), ["notes:read"]) == (
        f'Bearer resource_metadata="{METADATA}", scope="notes:read"'
    )
    assert rs.challenge(rs.fail("invalid_token")) == (
        'Bearer error="invalid_token", error_description="The access token is invalid or expired", '
        f'resource_metadata="{METADATA}"'
    )
    assert rs.challenge(rs.fail("temporarily_unavailable")) is None


def test_denial_replies() -> None:
    rs = server()
    d = rs.denial(rs.fail("invalid_token"))
    headers = dict(d.headers)
    assert d.status == 401 and json.loads(d.body) == {"error": "invalid_token"}
    assert headers["Cache-Control"] == "no-store" and headers["Content-Type"] == "application/json"
    assert headers["Access-Control-Expose-Headers"] == "WWW-Authenticate"
    assert "WWW-Authenticate" in headers
    assert json.loads(rs.denial(rs.fail("unauthorized")).body) == {"error": "unauthorized"}
    assert json.loads(rs.denial(rs.fail("insufficient_scope", required=["a"])).body) == {"error": "insufficient_scope"}
    unavailable = rs.denial(rs.fail("temporarily_unavailable"))
    assert unavailable.status == 503 and json.loads(unavailable.body) == {"error": "temporarily_unavailable"}
    assert "WWW-Authenticate" not in dict(unavailable.headers) and dict(unavailable.headers)["Retry-After"] == "5"


# -- introspection -------------------------------------------------------------------------------------
def answer(**over: Any) -> dict[str, Any]:
    base = {"active": True, "sub": "user-1", "sid": "sess-1", "token_use": "access_token", "aud": [RESOURCE]}
    return {**base, **over}


def introspecting(**over: Any) -> ResourceServer:
    return server(introspection=IntrospectionOptions("cid", "csecret", **over))


def test_introspection_every_time_by_default(signer: Signer, router: respx.MockRouter) -> None:
    route = router.post(INTROSPECT).respond(200, json=answer())
    rs = introspecting()
    token = signer.sign(claims())
    rs.verify(token)
    rs.verify(token)
    assert route.call_count == 2
    request = route.calls.last.request
    assert request.headers["authorization"].startswith("Basic ")
    assert b"token=" in request.content


def test_introspection_inactive_is_401_and_not_cached(signer: Signer, router: respx.MockRouter) -> None:
    route = router.post(INTROSPECT).respond(200, json={"active": False})
    rs = introspecting(cache_ttl=60)
    token = signer.sign(claims())
    for _ in range(2):
        with pytest.raises(ResourceError) as exc:
            rs.verify(token)
        assert (exc.value.status, exc.value.code) == (401, "invalid_token")
    assert route.call_count == 2


@pytest.mark.parametrize(
    "reply",
    [
        answer(sub="someone-else"),
        answer(sid="other-session"),
        answer(token_use="refresh_token"),
        answer(aud=["https://other.test/mcp"]),
        answer(aud=None),
    ],
    ids=["sub", "sid", "token_use", "aud", "no-aud"],
)
def test_introspection_must_describe_this_token(
    signer: Signer, router: respx.MockRouter, reply: dict[str, Any]
) -> None:
    router.post(INTROSPECT).respond(200, json=reply)
    with pytest.raises(ResourceError) as exc:
        introspecting().verify(signer.sign(claims()))
    assert exc.value.code == "invalid_token"


def test_introspection_audience_compared_canonically(signer: Signer, router: respx.MockRouter) -> None:
    router.post(INTROSPECT).respond(200, json=answer(aud=["https://MCP.test/mcp/"]))
    introspecting().verify(signer.sign(claims()))


def test_introspection_cache(signer: Signer, router: respx.MockRouter) -> None:
    route = router.post(INTROSPECT).respond(200, json=answer())
    rs = introspecting(cache_ttl=60)
    token = signer.sign(claims())
    rs.verify(token)
    rs.verify(token)
    assert route.call_count == 1
    rs.verify(signer.sign(claims(jti="another")))
    assert route.call_count == 2


def test_cache_entries_end_at_exp_or_ttl() -> None:
    now = [1000.0]
    cache = IntrospectionCache(60, 10, clock=lambda: now[0])
    short, long_, gone = (IntrospectionCache.key(t) for t in ("short", "long", "gone"))
    cache.keep(short, 1010)  # exp before ttl
    cache.keep(long_, 5000)  # ttl before exp
    cache.keep(gone, 999)  # already expired: never kept
    assert cache.fresh(short) and cache.fresh(long_) and not cache.fresh(gone)
    now[0] = 1011
    assert not cache.fresh(short) and cache.fresh(long_)
    now[0] = 1061
    assert not cache.fresh(long_)


def test_cache_without_ttl_keeps_nothing() -> None:
    cache = IntrospectionCache(0, 10)
    key = IntrospectionCache.key("t")
    cache.keep(key, time.time() + 100)
    assert not cache.fresh(key) and len(cache) == 0


def test_cache_eviction_drops_expired_then_oldest() -> None:
    now = [1000.0]
    cache = IntrospectionCache(60, 3, clock=lambda: now[0])
    a, b, c, d, e = (IntrospectionCache.key(t) for t in "abcde")
    cache.keep(a, 1005)
    cache.keep(b, 5000)
    cache.keep(c, 5000)
    now[0] = 1006  # a expired
    cache.keep(d, 5000)
    assert not cache.fresh(a) and cache.fresh(b) and cache.fresh(c) and cache.fresh(d)
    cache.keep(e, 5000)  # full of live entries: the oldest (b) goes
    assert len(cache) == 3 and not cache.fresh(b) and cache.fresh(e)


def test_introspection_cache_is_bounded(signer: Signer, router: respx.MockRouter) -> None:
    router.post(INTROSPECT).respond(200, json=answer())
    rs = introspecting(cache_ttl=60, max_cache_entries=2)
    for i in range(5):
        rs.verify(signer.sign(claims(jti=f"t{i}")))
    assert rs._cache is not None and len(rs._cache) == 2


@pytest.mark.parametrize("failure", ["status", "network", "timeout", "body"])
def test_introspection_fails_closed(signer: Signer, router: respx.MockRouter, failure: str) -> None:
    route = router.post(INTROSPECT)
    if failure == "status":
        route.respond(500)
    elif failure == "network":
        route.mock(side_effect=httpx.ConnectError("down"))
    elif failure == "timeout":
        route.mock(side_effect=httpx.ReadTimeout("slow"))
    else:
        route.respond(200, text="not json")
    with pytest.raises(ResourceError) as exc:
        introspecting().verify(signer.sign(claims()))
    assert (exc.value.status, exc.value.code) == (503, "temporarily_unavailable")
    assert exc.value.www_authenticate is None


def test_introspection_only_after_local_checks(signer: Signer, router: respx.MockRouter) -> None:
    route = router.post(INTROSPECT).respond(200, json=answer())
    with pytest.raises(ResourceError):
        introspecting().verify(signer.sign(claims(aud=["https://other.test/mcp"])))
    assert route.call_count == 0


def test_introspection_uses_base_url(signer: Signer, router: respx.MockRouter) -> None:
    route = router.post("http://iam.internal:8080/oauth/introspect").respond(200, json=answer())
    server(introspection=IntrospectionOptions("cid", "s", base_url="http://iam.internal:8080")).verify(
        signer.sign(claims())
    )
    assert route.call_count == 1


# -- async server --------------------------------------------------------------------------------------
async def test_async_server(signer: Signer, router: respx.MockRouter) -> None:
    ipath = router.post(INTROSPECT).respond(200, json=answer())
    rs = AsyncResourceServer(ISSUER, RESOURCE, ENV, introspection=IntrospectionOptions("cid", "s"))
    got = await rs.verify(signer.sign(claims()))
    assert got.sub == "user-1" and ipath.call_count == 1
    with pytest.raises(ResourceError) as exc:
        await rs.verify("")
    assert exc.value.code == "unauthorized"
    ipath.respond(200, json={"active": False})
    with pytest.raises(ResourceError) as inactive:
        await rs.verify(signer.sign(claims()))
    assert inactive.value.status == 401
    ipath.respond(500)
    with pytest.raises(ResourceError) as down:
        await rs.verify(signer.sign(claims()))
    assert down.value.status == 503
    await rs.aclose()


# -- ASGI ----------------------------------------------------------------------------------------------
async def app_echo(scope: Any, receive: Any, send: Any) -> None:
    claims_ = claims_of(scope)
    seen = {
        "sub": claims_.sub if claims_ else None,
        "authorization": [v.decode() for k, v in scope["headers"] if k == b"authorization"],
        "path": scope["path"],
    }
    body = json.dumps(seen).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


@pytest.fixture
def asgi(jwks: respx.Route) -> Callable[..., httpx.AsyncClient]:
    def make(**over: Any) -> httpx.AsyncClient:
        rs = AsyncResourceServer(ISSUER, RESOURCE, ENV, scopes_supported=["notes:read"], **over.pop("server", {}))
        app = ResourceServerMiddleware(app_echo, rs, **over)
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.test")

    return make


async def test_asgi_serves_metadata(asgi: Callable[..., httpx.AsyncClient]) -> None:
    async with asgi() as http:
        for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"):
            res = await http.get(path)
            assert res.status_code == 200 and res.json()["resource"] == RESOURCE
            assert res.headers["access-control-allow-origin"] == "*"
        assert (await http.options("/.well-known/oauth-protected-resource/mcp")).status_code == 204
        post = await http.post("/.well-known/oauth-protected-resource/mcp")
        assert post.status_code == 405 and post.headers["allow"] == "GET, OPTIONS"
        head = await http.head("/.well-known/oauth-protected-resource/mcp")
        assert head.status_code == 200 and head.content == b""


async def test_asgi_challenges_without_token(asgi: Callable[..., httpx.AsyncClient]) -> None:
    async with asgi() as http:
        res = await http.post("/mcp")
        assert res.status_code == 401 and res.json() == {"error": "unauthorized"}
        assert res.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'
        assert res.headers["cache-control"] == "no-store"
        bad = await http.post("/mcp", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401 and bad.json() == {"error": "invalid_token"}
        assert 'error="invalid_token"' in bad.headers["www-authenticate"]
        basic = await http.post("/mcp", headers={"Authorization": "Basic abc"})
        assert basic.status_code == 401


async def test_asgi_passes_claims_and_strips_authorization(
    asgi: Callable[..., httpx.AsyncClient], signer: Signer
) -> None:
    async with asgi() as http:
        res = await http.post("/mcp", headers={"Authorization": f"bearer {signer.sign(claims())}"})
    assert res.status_code == 200
    assert res.json() == {"sub": "user-1", "authorization": [], "path": "/mcp"}


async def test_asgi_required_scopes_public_paths_and_options(
    asgi: Callable[..., httpx.AsyncClient], signer: Signer
) -> None:
    token = signer.sign(claims())
    async with asgi(required_scopes=["notes:write"], public_paths=["/health"]) as http:
        res = await http.post("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 403 and res.json() == {"error": "insufficient_scope"}
        assert 'scope="notes:read notes:write"' in res.headers["www-authenticate"]
        assert (await http.get("/health")).status_code == 200
        assert (await http.options("/mcp")).status_code == 200  # CORS preflights carry no token


async def test_asgi_503_when_keys_unreachable(signer: Signer) -> None:
    with respx.mock() as router:
        router.get(JWKS).respond(500)
        rs = AsyncResourceServer(ISSUER, RESOURCE, ENV)
        app = ResourceServerMiddleware(app_echo, rs)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.test") as http:
            res = await http.post("/mcp", headers={"Authorization": f"Bearer {signer.sign(claims())}"})
    assert res.status_code == 503 and "www-authenticate" not in res.headers


async def test_asgi_lifespan_and_websocket_pass_or_close() -> None:
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    app = ResourceServerMiddleware(inner, AsyncResourceServer(ISSUER, RESOURCE, ENV))
    await app({"type": "lifespan"}, None, None)  # type: ignore[arg-type]
    sent: list[dict[str, Any]] = []

    async def send(message: Any) -> None:
        sent.append(message)

    await app({"type": "websocket", "path": "/ws", "headers": []}, None, send)  # type: ignore[arg-type]
    assert seen == ["lifespan"] and sent == [{"type": "websocket.close", "code": 1008}]


# -- FastAPI -------------------------------------------------------------------------------------------
async def test_fastapi_require_scopes(signer: Signer, jwks: respx.Route) -> None:
    from fastapi import Depends, FastAPI

    from iamkit.integrations.fastapi import require_scopes

    rs = AsyncResourceServer(ISSUER, RESOURCE, ENV)
    app = FastAPI()

    @app.get("/notes")
    async def notes(c: ResourceClaims = Depends(require_scopes(rs, "notes:read"))) -> dict[str, str]:
        return {"sub": c.sub}

    @app.get("/admin")
    async def admin(c: ResourceClaims = Depends(require_scopes(rs, "notes:write"))) -> dict[str, str]:
        return {"sub": c.sub}

    auth = {"Authorization": f"Bearer {signer.sign(claims())}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.test") as http:
        assert (await http.get("/notes", headers=auth)).json() == {"sub": "user-1"}
        none = await http.get("/notes")
        assert none.status_code == 401 and none.headers["www-authenticate"].startswith("Bearer resource_metadata=")
        forbidden = await http.get("/admin", headers=auth)
        assert forbidden.status_code == 403
        assert 'error="insufficient_scope"' in forbidden.headers["www-authenticate"]
        assert 'scope="notes:read notes:write"' in forbidden.headers["www-authenticate"]


async def test_fastapi_behind_the_middleware_reuses_claims(signer: Signer, jwks: respx.Route) -> None:
    from fastapi import Depends, FastAPI

    from iamkit.integrations.fastapi import require_scopes

    rs = AsyncResourceServer(ISSUER, RESOURCE, ENV)
    app = FastAPI()

    @app.get("/mcp")
    async def mcp(c: ResourceClaims = Depends(require_scopes(rs, "notes:read"))) -> dict[str, str]:
        return {"sub": c.sub}

    wrapped = ResourceServerMiddleware(app, rs)
    auth = {"Authorization": f"Bearer {signer.sign(claims())}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped), base_url="https://mcp.test") as http:
        # the middleware stripped Authorization: only its verified claims can open the route
        assert (await http.get("/mcp", headers=auth)).json() == {"sub": "user-1"}
        assert (await http.get("/mcp")).status_code == 401


# -- WSGI ----------------------------------------------------------------------------------------------
def wsgi_call(app: Any, method: str = "POST", path: str = "/mcp", **environ: Any) -> tuple[str, dict[str, str], bytes]:
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> None:
        captured["status"], captured["headers"] = status, {k.lower(): v for k, v in headers}

    body = b"".join(app({"REQUEST_METHOD": method, "PATH_INFO": path, **environ}, start_response))
    return captured["status"], captured["headers"], body


def test_wsgi_middleware(signer: Signer, jwks: respx.Route) -> None:
    def inner(environ: Any, start_response: Any) -> list[bytes]:
        c = wsgi_claims_of(environ)
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [f"{c.sub if c else None}|{'HTTP_AUTHORIZATION' in environ}".encode()]

    app = ResourceServerWSGIMiddleware(inner, server(), required_scopes=["notes:read"], public_paths=["/health"])
    status, headers, body = wsgi_call(app, "GET", "/.well-known/oauth-protected-resource/mcp")
    assert status == "200 OK" and json.loads(body)["resource"] == RESOURCE
    assert headers["access-control-allow-origin"] == "*"
    assert wsgi_call(app, "OPTIONS", "/.well-known/oauth-protected-resource/mcp")[0] == "204 No Content"
    assert wsgi_call(app, "DELETE", "/.well-known/oauth-protected-resource/mcp")[0] == "405 Method Not Allowed"

    status, headers, body = wsgi_call(app)
    assert status == "401 Unauthorized" and json.loads(body) == {"error": "unauthorized"}
    assert headers["www-authenticate"].startswith("Bearer resource_metadata=")

    token = signer.sign(claims())
    ok = wsgi_call(app, HTTP_AUTHORIZATION=f"Bearer {token}")
    assert ok[0] == "200 OK" and ok[2] == b"user-1|False"
    assert wsgi_call(app, "GET", "/health")[0] == "200 OK"
    assert wsgi_call(app, "OPTIONS", "/mcp")[0] == "200 OK"

    strict = ResourceServerWSGIMiddleware(inner, server(), required_scopes=["notes:write"])
    status, headers, _ = wsgi_call(strict, HTTP_AUTHORIZATION=f"Bearer {token}")
    assert status == "403 Forbidden" and 'error="insufficient_scope"' in headers["www-authenticate"]


def test_wsgi_flask(signer: Signer, jwks: respx.Route) -> None:
    from flask import Flask, jsonify, request

    flask_app = Flask(__name__)

    @flask_app.post("/mcp")
    def mcp() -> Any:
        c = wsgi_claims_of(request.environ)
        return jsonify(sub=c.sub if c else None, authorization=request.headers.get("Authorization"))

    flask_app.wsgi_app = ResourceServerWSGIMiddleware(flask_app.wsgi_app, server())  # type: ignore[method-assign]
    client = flask_app.test_client()
    assert client.post("/mcp").status_code == 401
    res = client.post("/mcp", headers={"Authorization": f"Bearer {signer.sign(claims())}"})
    assert res.status_code == 200 and res.get_json() == {"sub": "user-1", "authorization": None}
    assert client.get("/.well-known/oauth-protected-resource/mcp").get_json()["resource"] == RESOURCE


# -- the generated twin --------------------------------------------------------------------------------
def test_async_twin_is_current() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "unasync.py"
    done = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
