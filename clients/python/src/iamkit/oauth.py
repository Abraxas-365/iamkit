"""OAuth 2.0 / OIDC client flows for server-side code, and machine-user key login."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass, field, fields
from typing import Any, Literal, TypeVar
from urllib.parse import quote_plus, urlencode

import httpx

from ._http import Transport
from ._jwk import SigningKey
from .errors import IAMKitError, invalid_argument

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class GrantTypes:
    """Grant types IAMKit's ``/oauth/token`` understands."""

    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class TokenTypes:
    #: Subject type of :meth:`OAuthClient.exchange_token` and type of every issued token.
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    #: Subject type of :meth:`OAuthClient.impersonate`.
    USER_ID = "urn:iamkit:params:oauth:token-type:user_id"


Prompt = Literal["none", "login", "consent", "select_account"]

_T = TypeVar("_T")


def _build(cls: type[_T], data: Any) -> _T:
    """Builds a dataclass from an answer, ignoring members it does not declare."""
    if not isinstance(data, dict):
        raise IAMKitError(502, "http_error", "unexpected response")
    names = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    values = {k: v for k, v in data.items() if k in names}
    try:
        return cls(**values)
    except TypeError as exc:
        raise IAMKitError(502, "http_error", "unexpected response") from exc


@dataclass(frozen=True)
class OAuthTokens:
    """A token endpoint answer."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


@dataclass(frozen=True)
class ExchangedToken:
    """A token exchange answer: an access token only."""

    access_token: str
    issued_token_type: str = ""
    token_type: str = "Bearer"
    expires_in: int = 0


@dataclass(frozen=True)
class DeviceAuthorization:
    """RFC 8628 device authorization: show ``user_code`` and ``verification_uri``, then wait."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str = ""
    expires_in: int = 0
    interval: int = 5


@dataclass(frozen=True)
class Introspection:
    """RFC 7662 answer; inactive tokens only set ``active``."""

    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None
    token_type: str | None = None
    token_use: str | None = None
    aud: list[str] | None = None
    iss: str | None = None
    exp: int | None = None
    iat: int | None = None
    environment_id: str | None = None
    organization_id: str | None = None
    application_id: str | None = None
    resource_id: str | None = None
    permissions: list[str] | None = None
    sid: str | None = None
    amr: list[str] | None = None
    auth_time: int | None = None


@dataclass(frozen=True)
class PKCE:
    """A PKCE pair (RFC 7636, S256). Keep the verifier server-side until the callback."""

    verifier: str
    challenge: str


def create_pkce() -> PKCE:
    """A PKCE verifier (43 characters) and its S256 challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    return PKCE(verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode())


def random_token(nbytes: int = 24) -> str:
    """A random URL-safe value for ``state`` or ``nonce``."""
    return secrets.token_urlsafe(nbytes)


@dataclass(frozen=True)
class ClientAuth:
    """Client authentication at the token endpoint.

    Use the constructors: :meth:`none` (public client with PKCE), :meth:`basic`,
    :meth:`post` and :meth:`private_key_jwt`.
    """

    method: Literal["none", "client_secret_basic", "client_secret_post", "private_key_jwt"] = "none"
    secret: str | None = field(default=None, repr=False)
    key: Any = field(default=None, repr=False)
    kid: str | None = None
    alg: str | None = None

    @classmethod
    def none(cls) -> ClientAuth:
        return cls("none")

    @classmethod
    def basic(cls, secret: str) -> ClientAuth:
        return cls("client_secret_basic", secret=secret)

    @classmethod
    def post(cls, secret: str) -> ClientAuth:
        return cls("client_secret_post", secret=secret)

    @classmethod
    def private_key_jwt(cls, key: str | bytes | Any, kid: str, alg: str | None = None) -> ClientAuth:
        """``key``: PEM (PKCS #8, PKCS #1 or SEC 1) or a ``cryptography`` private key object;
        ``kid``: the key's id in the client's registered key set; ``alg``: the registered signing
        algorithm (default RS256, or the curve's ES algorithm)."""
        if not kid:
            raise invalid_argument("kid is required")
        return cls("private_key_jwt", key=key, kid=kid, alg=alg)


def _basic(client_id: str, secret: str) -> str:
    # RFC 6749 §2.3.1: form-encode both parts before base64.
    raw = f"{quote_plus(client_id)}:{quote_plus(secret)}".encode()
    return "Basic " + base64.b64encode(raw).decode()


class OAuthClient:
    """The OAuth 2.0 / OIDC endpoints for a server-side client: authorization code + PKCE, refresh,
    revocation, UserInfo, introspection, client_credentials, device authorization, token exchange and
    impersonation. Failures raise :class:`IAMKitError` with the OAuth ``error`` as code.

    Every network method has an ``a``-prefixed coroutine twin (``aexchange_code`` …).
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        *,
        client_secret: str | None = None,
        auth: ClientAuth | None = None,
        issuer: str | None = None,
        client: httpx.Client | None = None,
        async_client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        """``client_secret`` is shorthand for ``ClientAuth.basic``; ``auth`` overrides it (default
        ``none``: a public client with PKCE). ``issuer`` is the address assertions are made to
        (default ``base_url``): set it when the SDK reaches IAMKit at another origin than the public one."""
        if not client_id:
            raise invalid_argument("client_id is required")
        self._http = Transport(base_url, client=client, async_client=async_client, timeout=timeout)
        self.client_id = client_id
        self._auth = auth or (ClientAuth.basic(client_secret) if client_secret else ClientAuth.none())
        self._token_audience = f"{(issuer or base_url).rstrip('/')}/oauth/token"
        self._signer: SigningKey | None = None

    @property
    def base_url(self) -> str:
        return self._http.base_url

    def close(self) -> None:
        self._http.close()

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- authorization URL -------------------------------------------------------------------
    def authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        scopes: Sequence[str] = (),
        organization_id: str | None = None,
        connection_id: str | None = None,
        prompt: Prompt | Sequence[Prompt] | None = None,
        max_age: int | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        """The ``/oauth/authorize`` URL to redirect the browser to (code flow + PKCE S256).

        ``state`` (at least 8 characters) must be compared on the callback; ``scopes`` always
        include ``openid``. ``organization_id`` brands the hosted pages and limits the sign-in to it;
        ``connection_id`` starts that federation connection. ``prompt=\"none\"`` makes IAMKit answer at
        once with ``error=login_required`` (it keeps no session between authorize requests);
        ``max_age=0`` is ``prompt=login``.
        """
        if not state or len(state) < 8:
            raise invalid_argument("state must have at least 8 characters")
        if not (nonce and code_challenge and redirect_uri):
            raise invalid_argument("redirect_uri, nonce and code_challenge are required")
        scope = list(dict.fromkeys(["openid", *scopes]))
        query: dict[str, str] = {
            **(extra or {}),
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": " ".join(scope),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if organization_id:
            query["organization_id"] = organization_id
        if connection_id:
            query["connection_id"] = connection_id
        if prompt is not None:
            query["prompt"] = prompt if isinstance(prompt, str) else " ".join(prompt)
        if max_age is not None:
            if isinstance(max_age, bool) or max_age < 0:
                raise invalid_argument("max_age must be a non-negative integer number of seconds")
            query["max_age"] = str(max_age)
        return f"{self.base_url}/oauth/authorize?{urlencode(query)}"

    def end_session_url(
        self,
        *,
        id_token_hint: str | None = None,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str:
        """The RP-initiated logout URL; ``post_logout_redirect_uri`` must be registered on the client."""
        query = {"client_id": self.client_id}
        if id_token_hint:
            query["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            query["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            query["state"] = state
        return f"{self.base_url}/oauth/end_session?{urlencode(query)}"

    # -- request plumbing --------------------------------------------------------------------
    def _assertion(self) -> str:
        auth = self._auth
        if self._signer is None:
            self._signer = SigningKey.load(auth.key, auth.alg)
        return self._signer.assertion(auth.kid or "", self.client_id, self._token_audience)

    def _prepare(self, fields_: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
        form = {**fields_, "client_id": self.client_id}
        headers: dict[str, str] = {}
        auth = self._auth
        if auth.method == "client_secret_basic":
            headers["Authorization"] = _basic(self.client_id, auth.secret or "")
        elif auth.method == "client_secret_post":
            form["client_secret"] = auth.secret or ""
        elif auth.method == "private_key_jwt":
            form["client_assertion_type"] = CLIENT_ASSERTION_TYPE
            form["client_assertion"] = self._assertion()
        return form, headers

    def _post(self, path: str, fields_: dict[str, str]) -> Any:
        form, headers = self._prepare(fields_)
        return self._http.request("POST", path, form=form, headers=headers)

    async def _apost(self, path: str, fields_: dict[str, str]) -> Any:
        form, headers = self._prepare(fields_)
        return await self._http.arequest("POST", path, form=form, headers=headers)

    # -- grants ------------------------------------------------------------------------------
    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str) -> OAuthTokens:
        """Trades the callback's code for tokens."""
        return _build(OAuthTokens, self._post("/oauth/token", _code_form(code, redirect_uri, code_verifier)))

    async def aexchange_code(self, code: str, redirect_uri: str, code_verifier: str) -> OAuthTokens:
        return _build(OAuthTokens, await self._apost("/oauth/token", _code_form(code, redirect_uri, code_verifier)))

    def refresh(self, refresh_token: str) -> OAuthTokens:
        """Exchanges a refresh token (rotated: store the new one)."""
        return _build(OAuthTokens, self._post("/oauth/token", _refresh_form(refresh_token)))

    async def arefresh(self, refresh_token: str) -> OAuthTokens:
        return _build(OAuthTokens, await self._apost("/oauth/token", _refresh_form(refresh_token)))

    def client_credentials(self) -> OAuthTokens:
        """A service account's access token (``client_id`` = account ID; secret ``ik_svc_…`` or private_key_jwt)."""
        return _build(OAuthTokens, self._post("/oauth/token", {"grant_type": GrantTypes.CLIENT_CREDENTIALS}))

    async def aclient_credentials(self) -> OAuthTokens:
        return _build(OAuthTokens, await self._apost("/oauth/token", {"grant_type": GrantTypes.CLIENT_CREDENTIALS}))

    def exchange_token(self, subject_token: str, audience: str, permissions: Sequence[str] = ()) -> ExchangedToken:
        """RFC 8693: turns a user's access token into one for another resource (audience) of the same
        application. The client must be confidential with the token exchange grant; ``permissions`` narrow it."""
        return _build(ExchangedToken, self._post("/oauth/token", _exchange_form(subject_token, audience, permissions)))

    async def aexchange_token(
        self, subject_token: str, audience: str, permissions: Sequence[str] = ()
    ) -> ExchangedToken:
        return _build(
            ExchangedToken, await self._apost("/oauth/token", _exchange_form(subject_token, audience, permissions))
        )

    def impersonate(self, user: str, organization: str, reason: str) -> ExchangedToken:
        """A service account allowed to impersonate gets a token acting as ``user`` in ``organization``;
        its ``act`` claim names the account. The reason is audited."""
        return _build(ExchangedToken, self._post("/oauth/token", _impersonate_form(user, organization, reason)))

    async def aimpersonate(self, user: str, organization: str, reason: str) -> ExchangedToken:
        return _build(ExchangedToken, await self._apost("/oauth/token", _impersonate_form(user, organization, reason)))

    # -- revoke, userinfo, introspect --------------------------------------------------------
    def revoke(self, token: str) -> None:
        """Revokes an access or refresh token."""
        self._post("/oauth/revoke", {"token": token})

    async def arevoke(self, token: str) -> None:
        await self._apost("/oauth/revoke", {"token": token})

    def user_info(self, access_token: str) -> dict[str, Any]:
        """The signed-in user's claims with an OAuth access token (``openid`` scope)."""
        result: dict[str, Any] = self._http.request("GET", "/oauth/userinfo", token=access_token)
        return result

    async def auser_info(self, access_token: str) -> dict[str, Any]:
        result: dict[str, Any] = await self._http.arequest("GET", "/oauth/userinfo", token=access_token)
        return result

    def _introspection(self, token: str) -> tuple[dict[str, str], dict[str, str]]:
        auth = self._auth
        if auth.method not in ("client_secret_basic", "client_secret_post"):
            raise IAMKitError(401, "invalid_client", "introspection needs a confidential client with a secret")
        return {"token": token}, {"Authorization": _basic(self.client_id, auth.secret or "")}

    def introspect(self, token: str) -> Introspection:
        """RFC 7662 introspection of an access or refresh token of this client's environment (also opaque
        ``ory_at_`` tokens). Needs a confidential client with a secret (HTTP Basic)."""
        form, headers = self._introspection(token)
        return _build(Introspection, self._http.request("POST", "/oauth/introspect", form=form, headers=headers))

    async def aintrospect(self, token: str) -> Introspection:
        form, headers = self._introspection(token)
        answer = await self._http.arequest("POST", "/oauth/introspect", form=form, headers=headers)
        return _build(Introspection, answer)

    # -- device flow -------------------------------------------------------------------------
    def authorize_device(self, scopes: Sequence[str] = ()) -> DeviceAuthorization:
        """Starts a device authorization (the client's grant types must include the device code grant)."""
        fields_ = {"scope": " ".join(scopes)} if scopes else {}
        return _build(DeviceAuthorization, self._post("/oauth/device_authorization", fields_))

    async def aauthorize_device(self, scopes: Sequence[str] = ()) -> DeviceAuthorization:
        fields_ = {"scope": " ".join(scopes)} if scopes else {}
        return _build(DeviceAuthorization, await self._apost("/oauth/device_authorization", fields_))

    def poll_device(self, device_code: str) -> OAuthTokens:
        """Polls once; until the user decides it raises ``authorization_pending`` or ``slow_down``."""
        return _build(OAuthTokens, self._post("/oauth/token", _device_form(device_code)))

    async def apoll_device(self, device_code: str) -> OAuthTokens:
        return _build(OAuthTokens, await self._apost("/oauth/token", _device_form(device_code)))

    def wait_for_device(
        self,
        authorization: DeviceAuthorization,
        *,
        step: float = 1.0,
        timeout: float | None = None,
    ) -> OAuthTokens:
        """Polls at the authorization's interval (five more after each ``slow_down``) until the user approves,
        denies (``access_denied``), the code expires (``expired_token``) or ``timeout`` seconds pass
        (``expired_token``). ``step`` scales the interval's unit (tests use a small one)."""
        interval = (authorization.interval if authorization.interval > 0 else 5) * step
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            time.sleep(interval)
            try:
                return self.poll_device(authorization.device_code)
            except IAMKitError as exc:
                interval = _next_interval(exc, interval, step)
            if deadline is not None and time.monotonic() >= deadline:
                raise IAMKitError(400, "expired_token", "device authorization timed out")

    async def await_for_device(
        self,
        authorization: DeviceAuthorization,
        *,
        step: float = 1.0,
        timeout: float | None = None,
    ) -> OAuthTokens:
        import asyncio

        interval = (authorization.interval if authorization.interval > 0 else 5) * step
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            await asyncio.sleep(interval)
            try:
                return await self.apoll_device(authorization.device_code)
            except IAMKitError as exc:
                interval = _next_interval(exc, interval, step)
            if deadline is not None and time.monotonic() >= deadline:
                raise IAMKitError(400, "expired_token", "device authorization timed out")


def _next_interval(error: IAMKitError, interval: float, step: float) -> float:
    if error.code == "slow_down":
        return interval + 5 * step
    if error.code != "authorization_pending":
        raise error
    return interval


def _code_form(code: str, redirect_uri: str, code_verifier: str) -> dict[str, str]:
    return {
        "grant_type": GrantTypes.AUTHORIZATION_CODE,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }


def _refresh_form(refresh_token: str) -> dict[str, str]:
    return {"grant_type": GrantTypes.REFRESH_TOKEN, "refresh_token": refresh_token}


def _device_form(device_code: str) -> dict[str, str]:
    return {"grant_type": GrantTypes.DEVICE_CODE, "device_code": device_code}


def _exchange_form(subject_token: str, audience: str, permissions: Sequence[str]) -> dict[str, str]:
    form = {
        "grant_type": GrantTypes.TOKEN_EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": TokenTypes.ACCESS_TOKEN,
        "audience": audience,
    }
    if permissions:
        form["scope"] = " ".join(permissions)
    return form


def _impersonate_form(user: str, organization: str, reason: str) -> dict[str, str]:
    return {
        "grant_type": GrantTypes.TOKEN_EXCHANGE,
        "subject_token": user,
        "subject_token_type": TokenTypes.USER_ID,
        "organization_id": organization,
        "reason": reason,
    }


@dataclass(frozen=True)
class KeyBoundary:
    """Where a key login's session opens; ``environment_id`` defaults to the key's."""

    organization_id: str
    application_id: str
    resource_id: str
    environment_id: str | None = None


class KeyLogin:
    """Signs a machine user in with one of its keys (RFC 7523 JWT-bearer grant, no OAuth client): each call
    signs a fresh one-minute assertion. There is no refresh token; sign in again when the access token expires.

    ``user_id`` is the machine user, ``kid`` the key's id (from ``POST …/users/:id/keys``) and
    ``private_key`` its private half: the PEM IAMKit returned when it generated the pair, or your own.
    """

    def __init__(
        self,
        base_url: str,
        user_id: str,
        kid: str,
        private_key: str | bytes | Any,
        *,
        issuer: str | None = None,
        client: httpx.Client | None = None,
        async_client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not (user_id and kid and private_key):
            raise invalid_argument("user_id, kid and private_key are required")
        self._http = Transport(base_url, client=client, async_client=async_client, timeout=timeout)
        self.user_id = user_id
        self.kid = kid
        self._key = SigningKey.load(private_key)
        self._audience = f"{(issuer or base_url).rstrip('/')}/oauth/token"

    def assertion(self) -> str:
        """A fresh signed assertion."""
        return self._key.assertion(self.kid, self.user_id, self._audience)

    def _form(self, boundary: KeyBoundary) -> dict[str, str]:
        form = {
            "grant_type": GrantTypes.JWT_BEARER,
            "assertion": self.assertion(),
            "organization_id": boundary.organization_id,
            "application_id": boundary.application_id,
            "resource_id": boundary.resource_id,
        }
        if boundary.environment_id:
            form["environment_id"] = boundary.environment_id
        return form

    def token(self, boundary: KeyBoundary) -> OAuthTokens:
        """Trades a fresh assertion for an application access token in ``boundary``."""
        return _build(OAuthTokens, self._http.request("POST", "/oauth/token", form=self._form(boundary)))

    async def atoken(self, boundary: KeyBoundary) -> OAuthTokens:
        return _build(OAuthTokens, await self._http.arequest("POST", "/oauth/token", form=self._form(boundary)))

    def close(self) -> None:
        self._http.close()

    async def aclose(self) -> None:
        await self._http.aclose()


@dataclass(frozen=True)
class Discovery:
    """The OpenID Provider metadata (``/.well-known/openid-configuration``)."""

    issuer: str
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    introspection_endpoint: str = ""
    revocation_endpoint: str = ""
    end_session_endpoint: str = ""
    device_authorization_endpoint: str = ""
    scopes_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    prompt_values_supported: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


def _discovery(document: Any) -> Discovery:
    found = _build(Discovery, document)
    return Discovery(**{**found.__dict__, "raw": dict(document)})


def discover(base_url: str, *, client: httpx.Client | None = None, timeout: float = 10.0) -> Discovery:
    """Fetches the OpenID Provider metadata of the deployment at ``base_url``."""
    http = Transport(base_url, client=client, timeout=timeout)
    try:
        return _discovery(http.request("GET", "/.well-known/openid-configuration"))
    finally:
        http.close()


async def adiscover(
    base_url: str, *, async_client: httpx.AsyncClient | None = None, timeout: float = 10.0
) -> Discovery:
    http = Transport(base_url, async_client=async_client, timeout=timeout)
    try:
        return _discovery(await http.arequest("GET", "/.well-known/openid-configuration"))
    finally:
        await http.aclose()
