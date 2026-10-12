"""Shared fixtures. Every key is generated at runtime: nothing secret-looking is committed."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import RSAAlgorithm

from iamkit import ExpectedToken

ISSUER = "https://iam.test"
AUDIENCE = "https://api.test"
ENV = "env-1"
APP = "app-1"
RES = "res-1"
KID = "kid-1"


@dataclass
class Signer:
    private: rsa.RSAPrivateKey
    kid: str

    @property
    def jwk(self) -> dict[str, Any]:
        public = RSAAlgorithm.to_jwk(self.private.public_key(), as_dict=True)
        return {**public, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def sign(self, claims: dict[str, Any], *, alg: str = "RS256", headers: dict[str, Any] | None = None) -> str:
        return jwt.encode(claims, self.private, algorithm=alg, headers={"kid": self.kid, **(headers or {})})


@pytest.fixture(scope="session")
def signer() -> Signer:
    return Signer(rsa.generate_private_key(public_exponent=65537, key_size=2048), KID)


@pytest.fixture(scope="session")
def other_signer() -> Signer:
    return Signer(rsa.generate_private_key(public_exponent=65537, key_size=2048), "kid-2")


@pytest.fixture(scope="session")
def rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


@pytest.fixture(scope="session")
def ec_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


@pytest.fixture
def expected() -> ExpectedToken:
    return ExpectedToken(issuer=ISSUER, audience=AUDIENCE, environment_id=ENV, application_id=APP, resource_id=RES)


def make_claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "user-1",
        "aud": [AUDIENCE],
        "exp": now + 300,
        "iat": now,
        "jti": "jti-1",
        "environment_id": ENV,
        "organization_id": "org-1",
        "application_id": APP,
        "resource_id": RES,
        "permissions": ["invoices:read", "invoices:write"],
        "purpose": "application",
        "sid": "sess-1",
        "amr": ["pwd", "mfa"],
        "auth_time": now - 10,
    }
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


@pytest.fixture
def claims_factory() -> Callable[..., dict[str, Any]]:
    return make_claims
