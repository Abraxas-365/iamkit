from __future__ import annotations

import httpx
import pytest
import respx

from iamkit import IAMKitError
from iamkit._http import Transport, clean_params, segment


def test_envelope() -> None:
    e = IAMKitError.from_response(
        422, {"error": {"code": "VALIDATION", "message": "bad", "type": "validation", "details": {"field": "x"}}}
    )
    assert (e.status, e.code, e.message, e.details) == (422, "VALIDATION", "bad", {"field": "x"})
    assert "VALIDATION (422)" in str(e)
    assert "VALIDATION" in repr(e)


def test_oauth_form() -> None:
    e = IAMKitError.from_response(400, {"error": "invalid_grant", "error_description": "expired"})
    assert (e.code, e.message) == ("invalid_grant", "expired")
    assert IAMKitError.from_response(400, {"error": "invalid_grant"}).message == "invalid_grant"


def test_fallbacks() -> None:
    assert IAMKitError.from_response(429, None).code == "TOO_MANY_REQUESTS"
    assert IAMKitError.from_response(500, "x").code == "http_error"
    assert IAMKitError.from_response(400, {"error": {"code": 5}}).code == "ERROR"


def test_segment_and_params() -> None:
    assert segment("a/b c") == "a%2Fb%20c"
    for bad in ("", ".", ".."):
        with pytest.raises(IAMKitError):
            segment(bad)
    assert clean_params({"a": 1, "b": None, "c": "", "d": True, "e": ["x", "y"]}) == {
        "a": "1",
        "d": "true",
        "e": "x,y",
    }


@respx.mock
def test_transport_errors_and_limits() -> None:
    respx.get("https://x.test/ok").respond(200, json={"a": 1})
    respx.get("https://x.test/empty").respond(204)
    respx.get("https://x.test/bad").respond(500, text="<html>")
    respx.get("https://x.test/big").respond(200, content=b"x" * ((1 << 20) + 1))
    t = Transport("https://x.test/")
    assert t.request("GET", "/ok") == {"a": 1}
    assert t.request("GET", "/empty") is None
    with pytest.raises(IAMKitError) as exc:
        t.request("GET", "/bad")
    assert exc.value.status == 500
    with pytest.raises(IAMKitError):
        t.request("GET", "/big")
    t.close()
    with pytest.raises(ValueError):
        Transport("")


@respx.mock
async def test_transport_async_and_stream() -> None:
    respx.get("https://x.test/lines").respond(200, content=b'{"a":1}\n\n{"a":2}\n')
    respx.get("https://x.test/err").respond(403, json={"error": {"code": "FORBIDDEN", "message": "no"}})
    t = Transport("https://x.test")
    assert [line async for line in t.astream_lines("/lines")] == ['{"a":1}', '{"a":2}']
    assert list(t.stream_lines("/lines")) == ['{"a":1}', '{"a":2}']
    with pytest.raises(IAMKitError) as exc:
        [line async for line in t.astream_lines("/err")]
    assert exc.value.code == "FORBIDDEN"
    with pytest.raises(IAMKitError):
        list(t.stream_lines("/err"))
    await t.aclose()
    t.close()


@respx.mock
def test_transport_uses_given_client_and_never_follows_redirects() -> None:
    respx.get("https://x.test/r").respond(302, headers={"location": "https://evil.test/"})
    with httpx.Client() as client:
        t = Transport("https://x.test", client=client)
        with pytest.raises(IAMKitError) as exc:
            t.request("GET", "/r", token="t")
        assert exc.value.status == 302
        t.close()
        assert not client.is_closed  # not ours
