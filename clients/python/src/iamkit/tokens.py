"""Access token verification: JWKS (offline) or introspection (online), claims and helpers."""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from jwt import PyJWK

from ._http import Transport
from .errors import IAMKitError, invalid_argument, unauthorized

#: The algorithm IAMKit signs tokens with (``signing.Algorithm``).
ALGORITHMS = ("RS256",)

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


@dataclass(frozen=True)
class AccessClaims:
    """The claims of an IAMKit access token (a JWT or the ``claims`` of introspection)."""

    sub: str
    iss: str
    aud: tuple[str, ...]
    exp: int
    iat: int
    jti: str
    environment_id: str
    application_id: str
    resource_id: str
    #: Exact permission strings on the resource.
    permissions: tuple[str, ...]
    #: ``application`` (a user) or ``machine`` (a service account).
    purpose: str
    nbf: int | None = None
    #: The tenant; empty for machine tokens.
    organization_id: str | None = None
    #: Session id; absent on machine tokens.
    sid: str | None = None
    #: Operator impersonating the user.
    actor_id: str | None = None
    #: RFC 8693 actor: the service account impersonating the user.
    act_sub: str | None = None
    oauth_client_id: str | None = None
    #: How the session signed in: pwd, email, fed, hwk, swk, plus otp/mfa.
    amr: tuple[str, ...] | None = None
    #: When the user signed in (unix seconds, kept across refreshes).
    auth_time: int | None = None
    #: OAuth scopes granted to an OAuth access token.
    scp: tuple[str, ...] | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> AccessClaims:
        def text(key: str) -> str | None:
            value = payload.get(key)
            return value if isinstance(value, str) and value != "" else None

        def items(key: str) -> tuple[str, ...] | None:
            value = payload.get(key)
            if isinstance(value, list):
                return tuple(v for v in value if isinstance(v, str))
            return None

        def number(key: str) -> int | None:
            value = payload.get(key)
            return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None

        act = payload.get("act")
        act_sub = (
            act.get("sub") if isinstance(act, dict) and isinstance(act.get("sub"), str) else text("actor_account_id")
        )
        auth_time = number("auth_time")
        return cls(
            sub=text("sub") or "",
            iss=text("iss") or "",
            aud=_audience(payload.get("aud")),
            exp=number("exp") or 0,
            iat=number("iat") or 0,
            nbf=number("nbf"),
            jti=text("jti") or "",
            environment_id=text("environment_id") or "",
            organization_id=text("organization_id"),
            application_id=text("application_id") or "",
            resource_id=text("resource_id") or "",
            permissions=items("permissions") or (),
            purpose=text("purpose") or "",
            sid=text("sid"),
            actor_id=text("actor_id"),
            act_sub=act_sub,
            oauth_client_id=text("oauth_client_id"),
            amr=items("amr"),
            auth_time=auth_time if auth_time and auth_time > 0 else None,
            scp=items("scp"),
            raw=dict(payload),
        )

    def has_permission(self, *permissions: str) -> bool:
        """Whether the token carries every one of ``permissions`` (exact strings)."""
        return has_permission(self, *permissions)

    @property
    def has_mfa(self) -> bool:
        return has_mfa(self)

    @property
    def impersonated(self) -> bool:
        return is_impersonated(self)


def _audience(aud: Any) -> tuple[str, ...]:
    if isinstance(aud, str):
        return (aud,)
    if isinstance(aud, list):
        return tuple(v for v in aud if isinstance(v, str))
    return ()


def has_permission(claims: AccessClaims, *permissions: str) -> bool:
    """Whether ``claims`` carry every one of ``permissions`` (exact strings, at least one required)."""
    return len(permissions) > 0 and all(p != "" and p in claims.permissions for p in permissions)


def require_permission(claims: AccessClaims, *permissions: str) -> None:
    """Raises a 403 ``FORBIDDEN`` :class:`IAMKitError` unless :func:`has_permission`."""
    if not has_permission(claims, *permissions):
        raise IAMKitError(403, "FORBIDDEN", "missing permission")


def has_mfa(claims: AccessClaims) -> bool:
    """Whether the session passed a second factor (amr ``mfa``): require it for step-up."""
    return "mfa" in (claims.amr or ())


def is_fresh(claims: AccessClaims, max_age_seconds: float, *, now: float | None = None) -> bool:
    """Whether the user signed in at most ``max_age_seconds`` ago (``auth_time``)."""
    if claims.auth_time is None:
        return False
    return (time.time() if now is None else now) - claims.auth_time <= max_age_seconds


def has_recent_mfa(claims: AccessClaims, max_age_seconds: float | None = None, *, now: float | None = None) -> bool:
    """A second factor, optionally passed within ``max_age_seconds``."""
    if not has_mfa(claims):
        return False
    return max_age_seconds is None or is_fresh(claims, max_age_seconds, now=now)


def require_mfa(claims: AccessClaims, max_age_seconds: float | None = None) -> None:
    """Raises 403 ``STEP_UP_REQUIRED`` unless :func:`has_recent_mfa`."""
    if not has_recent_mfa(claims, max_age_seconds):
        raise IAMKitError(403, "STEP_UP_REQUIRED", "a recent second factor is required")


def is_impersonated(claims: AccessClaims) -> bool:
    """Whether an operator (``actor_id``) or a service account (``act``) acts as the user."""
    return bool(claims.actor_id) or claims.act_sub is not None


@dataclass(frozen=True)
class ExpectedToken:
    """The boundaries every accepted token must match. Take them from trusted configuration."""

    #: The deployment's issuer (``JWT_ISSUER``), e.g. ``https://iam.example.com``.
    issuer: str
    #: The resource's audience.
    audience: str
    environment_id: str
    application_id: str
    resource_id: str

    def __post_init__(self) -> None:
        if not (self.issuer and self.audience and self.environment_id and self.application_id and self.resource_id):
            raise invalid_argument("issuer, audience, environment_id, application_id and resource_id are required")


class KeySet:
    """IAMKit's published signing keys, cached by ``kid``.

    Environments rotate keys by publishing the next one before it signs, so a
    set refreshed on an unknown ``kid`` holds it. Keys are refetched after
    ``max_age`` seconds and at most once per ``cooldown`` seconds (an unknown
    kid or a failing endpoint never makes every request fetch). While the
    endpoint fails, cached keys keep verifying for ``stale_grace`` seconds past
    ``max_age``. Share one key set per process. A fetch failure with no usable
    cached key raises 503 ``JWKS_UNAVAILABLE`` (an outage, not a bad token).
    The URL must be https (http only for loopback hosts).
    """

    def __init__(
        self,
        *,
        jwks_url: str | None = None,
        issuer: str | None = None,
        client: httpx.Client | None = None,
        async_client: httpx.AsyncClient | None = None,
        max_age: float = 600.0,
        cooldown: float = 30.0,
        stale_grace: float = 3600.0,
        timeout: float = 10.0,
    ) -> None:
        url = jwks_url or (f"{issuer.rstrip('/')}/.well-known/jwks.json" if issuer else None)
        if not url:
            raise invalid_argument("jwks_url or issuer is required")
        parts = urlsplit(url)
        if not (parts.scheme == "https" or (parts.scheme == "http" and _loopback(parts.hostname))):
            raise invalid_argument("the JWKS URL must be https (http only for localhost)")
        self.url = url
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._path = parts.path + (f"?{parts.query}" if parts.query else "")
        self._http = Transport(self._origin, client=client, async_client=async_client, timeout=timeout)
        self._max_age = max_age
        self._cooldown = cooldown
        self._stale_grace = stale_grace
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at = 0.0
        self._attempted_at: float | None = None
        self._lock = threading.Lock()

    def _plan(self, kid: str | None) -> tuple[PyJWK | None, bool]:
        """The cached key for ``kid`` and whether the set must be refetched first."""
        now = time.monotonic()
        with self._lock:
            key = self._pick(kid)
            stale = not self._keys or now - self._fetched_at >= self._max_age
            if key is not None and not stale:
                return key, False
            cooled = self._attempted_at is None or now - self._attempted_at >= self._cooldown
            return self._usable(key, now), cooled

    def _usable(self, key: PyJWK | None, now: float) -> PyJWK | None:
        """A cached key still within max_age + stale_grace (caller holds the lock)."""
        if key is None or now - self._fetched_at >= self._max_age + self._stale_grace:
            return None
        return key

    def _pick(self, kid: str | None) -> PyJWK | None:
        if kid is None:
            return next(iter(self._keys.values())) if len(self._keys) == 1 else None
        return self._keys.get(kid)

    def _begin(self) -> None:
        with self._lock:
            self._attempted_at = time.monotonic()

    def _store(self, document: Any) -> None:
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise _unavailable()
        keys: dict[str, PyJWK] = {}
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("use", "sig") != "sig":
                continue
            try:
                keys[str(entry.get("kid", ""))] = PyJWK.from_dict(entry)
            except Exception:  # an unusable key (unknown kty, malformed members) must not drop the others
                continue
        with self._lock:
            self._keys = keys
            self._fetched_at = time.monotonic()

    def refresh(self) -> None:
        """Fetches the key set now."""
        self._begin()
        try:
            document = self._http.request("GET", self._path)
        except Exception as exc:  # HTTP errors, network failures, bad JSON: an outage either way
            raise _unavailable() from exc
        self._store(document)

    async def arefresh(self) -> None:
        self._begin()
        try:
            document = await self._http.arequest("GET", self._path)
        except Exception as exc:
            raise _unavailable() from exc
        self._store(document)

    def get_key(self, token: str) -> PyJWK:
        """The key that signed ``token`` (its ``kid`` header): 401 for an unknown kid, 503 on an outage."""
        kid = _kid(token)
        key, refetch = self._plan(kid)
        if refetch:
            try:
                self.refresh()
            except IAMKitError:
                if key is None:
                    raise
                return key
            key = self._fresh(kid)
        return self._found(key)

    async def aget_key(self, token: str) -> PyJWK:
        kid = _kid(token)
        key, refetch = self._plan(kid)
        if refetch:
            try:
                await self.arefresh()
            except IAMKitError:
                if key is None:
                    raise
                return key
            key = self._fresh(kid)
        return self._found(key)

    def _fresh(self, kid: str | None) -> PyJWK | None:
        """The key for ``kid`` in the set just fetched."""
        with self._lock:
            return self._pick(kid)

    def _found(self, key: PyJWK | None) -> PyJWK:
        if key is not None:
            return key
        if not self._keys:  # nothing was ever fetched (cooling down after an outage)
            raise _unavailable()
        raise unauthorized("invalid or expired token")

    def close(self) -> None:
        self._http.close()

    async def aclose(self) -> None:
        await self._http.aclose()


def _unavailable() -> IAMKitError:
    return IAMKitError(503, "JWKS_UNAVAILABLE", "signing keys could not be fetched")


def _loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _kid(token: str) -> str | None:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid or expired token") from exc
    kid = header.get("kid")
    return kid if isinstance(kid, str) else None


class TokenVerifier:
    """Resolves a bearer token to trusted :class:`AccessClaims` or raises :class:`IAMKitError` (401/503)."""

    def verify(self, token: str) -> AccessClaims:  # pragma: no cover - interface
        raise NotImplementedError

    async def averify(self, token: str) -> AccessClaims:  # pragma: no cover - interface
        raise NotImplementedError


def _check_boundary(claims: AccessClaims, expected: ExpectedToken) -> None:
    if (
        claims.environment_id != expected.environment_id
        or claims.application_id != expected.application_id
        or claims.resource_id != expected.resource_id
    ):
        raise unauthorized("token boundary mismatch")
    if claims.purpose == "application":
        if not claims.organization_id or not claims.sid:
            raise unauthorized("missing user session context")
    elif claims.purpose == "machine":
        if claims.organization_id or claims.sid:
            raise unauthorized("invalid machine context")
    else:
        raise unauthorized("unsupported token purpose")


class JwtVerifier(TokenVerifier):
    """Verifies access tokens offline: RS256 signature from the issuer's JWKS, issuer, audience, expiry,
    environment, application, resource and purpose (``application`` tokens need an organization and session,
    ``machine`` tokens have neither).

    Offline verification cannot observe revocation before expiry; use
    :class:`IntrospectionVerifier` where logout, suspension or a permission removal must take effect
    immediately. API keys (``ik_key_``) are not JWTs: introspect them (:mod:`iamkit.apikeys`).

    You still must compare ``organization_id`` with the tenant a request touches.
    """

    def __init__(
        self,
        expected: ExpectedToken,
        *,
        keys: KeySet | None = None,
        leeway: float = 0,
        algorithms: Iterable[str] = ALGORITHMS,
    ) -> None:
        self.expected = expected
        self.keys = keys or KeySet(issuer=expected.issuer)
        self._leeway = leeway
        self._algorithms = list(algorithms)

    def verify(self, token: str) -> AccessClaims:
        if not token:
            raise unauthorized("missing token")
        return self._claims(token, self.keys.get_key(token))

    async def averify(self, token: str) -> AccessClaims:
        if not token:
            raise unauthorized("missing token")
        return self._claims(token, await self.keys.aget_key(token))

    def _claims(self, token: str, key: PyJWK) -> AccessClaims:
        try:
            payload = jwt.decode(
                token,
                key.key,
                algorithms=self._algorithms,
                issuer=self.expected.issuer,
                audience=self.expected.audience,
                leeway=self._leeway,
                options={"require": ["exp", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise unauthorized("invalid or expired token") from exc
        claims = AccessClaims.from_payload(payload)
        _check_boundary(claims, self.expected)
        return claims


class IntrospectionVerifier(TokenVerifier):
    """Verifies access tokens online with ``POST /identity/v1/introspect``: the session, account and grants
    are checked now, so revocation takes effect at once. If IAMKit is unreachable the call raises —
    fail closed, never falls back to decoding the token."""

    def __init__(
        self,
        expected: ExpectedToken,
        base_url: str,
        *,
        transport: Transport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.expected = expected
        self._http = transport or Transport(base_url, timeout=timeout)

    def _body(self) -> dict[str, str]:
        return {"environment_id": self.expected.environment_id, "audience": self.expected.audience}

    def verify(self, token: str) -> AccessClaims:
        if not token:
            raise unauthorized("missing token")
        try:
            answer = self._http.request("POST", "/identity/v1/introspect", json=self._body(), token=token)
        except IAMKitError as exc:
            raise _inactive(exc, "inactive token") from exc
        return self._claims(answer)

    async def averify(self, token: str) -> AccessClaims:
        if not token:
            raise unauthorized("missing token")
        try:
            answer = await self._http.arequest("POST", "/identity/v1/introspect", json=self._body(), token=token)
        except IAMKitError as exc:
            raise _inactive(exc, "inactive token") from exc
        return self._claims(answer)

    def _claims(self, answer: Any) -> AccessClaims:
        raw = answer.get("claims") if isinstance(answer, dict) else None
        if not isinstance(answer, dict) or not answer.get("active") or not isinstance(raw, dict):
            raise unauthorized("inactive token or boundary mismatch")
        claims = AccessClaims.from_payload(raw)
        e = self.expected
        if (
            claims.iss != e.issuer
            or e.audience not in claims.aud
            or claims.environment_id != e.environment_id
            or claims.application_id != e.application_id
            or claims.resource_id != e.resource_id
            or not claims.sub
        ):
            raise unauthorized("inactive token or boundary mismatch")
        if claims.purpose not in ("application", "machine"):
            raise unauthorized("invalid token purpose")
        return claims

    def close(self) -> None:
        self._http.close()

    async def aclose(self) -> None:
        await self._http.aclose()


def _inactive(exc: IAMKitError, message: str) -> IAMKitError:
    return unauthorized(message) if exc.status == 401 else exc


# -- ID tokens and logout tokens --------------------------------------------------------------


def verify_id_token(
    token: str,
    *,
    issuer: str,
    client_id: str,
    keys: KeySet,
    nonce: str,
    leeway: float = 0,
) -> dict[str, Any]:
    """Verifies an ID token from the authorization code flow: RS256 signature, issuer, audience = client,
    expiry and the request's ``nonce``. ID tokens identify the user to the client; never accept one as an
    API access token."""
    if not (issuer and client_id and nonce):
        raise invalid_argument("issuer, client_id and nonce are required")
    return _check_id_token(token, keys.get_key(token), issuer, client_id, nonce, leeway)


async def averify_id_token(
    token: str,
    *,
    issuer: str,
    client_id: str,
    keys: KeySet,
    nonce: str,
    leeway: float = 0,
) -> dict[str, Any]:
    if not (issuer and client_id and nonce):
        raise invalid_argument("issuer, client_id and nonce are required")
    return _check_id_token(token, await keys.aget_key(token), issuer, client_id, nonce, leeway)


def _check_id_token(token: str, key: PyJWK, issuer: str, client_id: str, nonce: str, leeway: float) -> dict[str, Any]:
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            key.key,
            algorithms=list(ALGORITHMS),
            issuer=issuer,
            audience=client_id,
            leeway=leeway,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid ID token") from exc
    if payload.get("nonce") != nonce:
        raise unauthorized("ID token nonce mismatch")
    return payload


@dataclass(frozen=True)
class LogoutToken:
    """A verified OpenID Connect Back-Channel Logout token."""

    sub: str
    #: The ended session: end your application's session for it.
    sid: str
    jti: str
    iss: str
    aud: tuple[str, ...]
    iat: int
    exp: int
    environment_id: str | None = None


def verify_logout_token(token: str, *, issuer: str, client_id: str, keys: KeySet) -> LogoutToken:
    """Verifies the ``logout_token`` form field IAMKit POSTs to a client's ``backchannel_logout_uri``.

    Checks RS256 signature, issuer, audience = client, expiry, the back-channel logout event, a ``sid`` and
    no ``nonce``. Answer 200 when it verifies, 400 otherwise. Replay protection (remembering ``jti`` until
    ``exp``) is up to the caller."""
    if not (issuer and client_id):
        raise invalid_argument("issuer and client_id are required")
    return _check_logout_token(token, keys.get_key(token), issuer, client_id)


async def averify_logout_token(token: str, *, issuer: str, client_id: str, keys: KeySet) -> LogoutToken:
    if not (issuer and client_id):
        raise invalid_argument("issuer and client_id are required")
    return _check_logout_token(token, await keys.aget_key(token), issuer, client_id)


def _check_logout_token(token: str, key: PyJWK, issuer: str, client_id: str) -> LogoutToken:
    invalid = IAMKitError(400, "UNAUTHORIZED", "invalid logout token")
    try:
        payload = jwt.decode(
            token,
            key.key,
            algorithms=list(ALGORITHMS),
            issuer=issuer,
            audience=client_id,
            options={"require": ["exp", "iat", "sub", "sid", "jti"]},
        )
        typ = jwt.get_unverified_header(token).get("typ")
    except jwt.PyJWTError as exc:
        raise invalid from exc
    events = payload.get("events")
    event = events.get(BACKCHANNEL_LOGOUT_EVENT) if isinstance(events, dict) else None
    if not isinstance(event, dict) or "nonce" in payload or (typ and typ not in ("logout+jwt", "JWT")):
        raise invalid
    environment = payload.get("environment_id")
    return LogoutToken(
        sub=str(payload["sub"]),
        sid=str(payload["sid"]),
        jti=str(payload["jti"]),
        iss=str(payload["iss"]),
        aud=_audience(payload.get("aud")),
        iat=int(payload["iat"]),
        exp=int(payload["exp"]),
        environment_id=environment if isinstance(environment, str) else None,
    )
