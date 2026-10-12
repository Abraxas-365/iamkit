"""Contract checks against a real IAMKit stack. Skipped unless ``IAMKIT_CONTRACT_URL`` is set.

Environment:

* ``IAMKIT_CONTRACT_URL``            base URL of the deployment (also its issuer)
* ``IAMKIT_CONTRACT_ENVIRONMENT``    environment id
* ``IAMKIT_CONTRACT_MANAGEMENT_KEY`` management key (``ik_mgmt_…``)
* ``IAMKIT_CONTRACT_TOKEN``          a valid access token of the environment (for verify/introspect)
* ``IAMKIT_CONTRACT_APPLICATION`` / ``IAMKIT_CONTRACT_RESOURCE`` / ``IAMKIT_CONTRACT_AUDIENCE``
                                     the token's boundaries
* ``IAMKIT_CONTRACT_API_KEY``        optional ``ik_key_…`` for API key validation

Run: ``IAMKIT_CONTRACT_URL=http://localhost:8080 ... uv run pytest tests/contract -q``.
"""

from __future__ import annotations

import os

import pytest

from iamkit import (
    APIKeyValidator,
    ExpectedToken,
    IAMKit,
    IAMKitError,
    IntrospectionVerifier,
    JwtVerifier,
    discover,
)

URL = os.environ.get("IAMKIT_CONTRACT_URL", "").rstrip("/")

pytestmark = pytest.mark.skipif(not URL, reason="IAMKIT_CONTRACT_URL is not set")


def need(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        pytest.skip(f"{name} is not set")
    return value


def expected() -> ExpectedToken:
    return ExpectedToken(
        issuer=URL,
        audience=need("IAMKIT_CONTRACT_AUDIENCE"),
        environment_id=need("IAMKIT_CONTRACT_ENVIRONMENT"),
        application_id=need("IAMKIT_CONTRACT_APPLICATION"),
        resource_id=need("IAMKIT_CONTRACT_RESOURCE"),
    )


def test_discovery_and_jwks() -> None:
    doc = discover(URL)
    assert doc.issuer.rstrip("/") == URL
    assert doc.jwks_uri


def test_verify_token_offline_and_online() -> None:
    token = need("IAMKIT_CONTRACT_TOKEN")
    claims = JwtVerifier(expected()).verify(token)
    assert claims.sub and claims.environment_id == need("IAMKIT_CONTRACT_ENVIRONMENT")
    online = IntrospectionVerifier(expected(), URL).verify(token)
    assert online.sub == claims.sub
    with pytest.raises(IAMKitError) as exc:
        JwtVerifier(expected()).verify(token[:-4] + "AAAA")
    assert exc.value.status == 401


def test_management_list_users() -> None:
    with IAMKit(URL, need("IAMKIT_CONTRACT_MANAGEMENT_KEY"), environment_id=need("IAMKIT_CONTRACT_ENVIRONMENT")) as iam:
        page = iam.users.list(limit=5)
        assert isinstance(page["items"], list)
        assert "total" in page["page"]
        assert len(list(iam.users.iterate(page_size=2))) >= len(page["items"])
        with pytest.raises(IAMKitError) as exc:
            iam.users.get("00000000-0000-0000-0000-000000000000")
        assert exc.value.status == 404


def test_introspection_of_garbage_is_inactive_or_401() -> None:
    verifier = IntrospectionVerifier(expected(), URL)
    with pytest.raises(IAMKitError) as exc:
        verifier.verify("not-a-token")
    assert exc.value.status == 401


def test_api_key_validation() -> None:
    key = need("IAMKIT_CONTRACT_API_KEY")
    validator = APIKeyValidator(URL, need("IAMKIT_CONTRACT_ENVIRONMENT"), need("IAMKIT_CONTRACT_AUDIENCE"))
    assert validator.validate(key).permissions
