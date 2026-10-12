"""Private key loading and assertion signing shared by OAuthClient and KeyLogin."""

from __future__ import annotations

import secrets
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .errors import invalid_argument

ASSERTION_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")

_CURVE_ALG = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}


class SigningKey:
    """A private key (RSA or EC P-256/384/521) with the algorithm it signs with."""

    def __init__(self, key: Any, alg: str) -> None:
        self.key = key
        self.alg = alg

    @classmethod
    def load(cls, private_key: str | bytes | Any, alg: str | None = None) -> SigningKey:
        key: Any = private_key
        if isinstance(private_key, (str, bytes)):
            data = private_key.encode() if isinstance(private_key, str) else private_key
            try:
                key = load_pem_private_key(data, password=None)
            except (ValueError, TypeError) as exc:
                raise invalid_argument("not a PEM RSA or EC private key") from exc
        if isinstance(key, rsa.RSAPrivateKey):
            default: str | None = "RS256"
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            default = _CURVE_ALG.get(key.curve.name)
        else:
            raise invalid_argument("key must be an RSA or EC (P-256, P-384, P-521) private key")
        chosen = alg or default
        if chosen is None or chosen not in ASSERTION_ALGORITHMS:
            raise invalid_argument("key must be an RSA or EC (P-256, P-384, P-521) private key")
        return cls(key, chosen)

    def assertion(self, kid: str, subject: str, audience: str) -> str:
        """A fresh one-minute JWT (RFC 7523 §3) with iss = sub = ``subject``."""
        now = int(time.time())
        claims = {
            "iss": subject,
            "sub": subject,
            "aud": audience,
            "jti": secrets.token_urlsafe(16),
            "iat": now,
            "exp": now + 60,
        }
        return jwt.encode(claims, self.key, algorithm=self.alg, headers={"kid": kid, "typ": "JWT"})
