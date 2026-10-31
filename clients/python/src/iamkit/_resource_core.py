"""What the synchronous and asynchronous resource servers share: canonical resource URIs, claims, errors,
challenges, the RFC 9728 document, the token checks that need no I/O and the introspection cache.

``_resource_server.py`` adds the key lookup and the introspection call; ``_aresource_server.py`` is generated
from it by ``scripts/unasync.py``."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, NamedTuple

import httpx
import jwt
from jwt import PyJWK

from .errors import IAMKitError, invalid_argument
from .oauth import Introspection, OAuthClient
from .tokens import ALGORITHMS, KeySet

#: The RFC 9728 well-known path of protected resource metadata.
METADATA_PATH = "/.well-known/oauth-protected-resource"

#: Granted scopes that are not permissions of the resource.
PROTOCOL_SCOPES = ("openid", "profile", "email", "phone", "offline_access")

_MAX_RESOURCE_URI = 2048
_HEX = frozenset("0123456789abcdefABCDEF")
_PCHAR = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@")
_HOST = re.compile(r"[a-z0-9.-]+")
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]")


# -- canonical resource ------------------------------------------------------------------------------
def canonical_resource(raw: str) -> str | None:
    """The canonical form of an RFC 8707 resource indicator, or ``None`` when it has none.

    Absolute https (http only on ``localhost``, ``127.0.0.1`` and ``[::1]``), lowercase scheme and host, no
    default port, userinfo, query, fragment, dot or empty segments, no trailing slash; the path's case and
    percent-encoding are kept. The same rule, and the same shared vectors
    (``sdk/resourceserver/testdata/canonical.json``), as IAMKit, the Go SDK and ``@iamkit/node/resource-server``.
    """
    if not raw or len(raw) > _MAX_RESOURCE_URI:
        return None
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in raw):
        return None
    sep = raw.find("://")
    if sep < 0:
        return None
    scheme = raw[:sep].lower()
    rest = raw[sep + 3 :]
    if scheme not in ("https", "http") or "?" in rest or "#" in rest:
        return None
    slash = rest.find("/")
    authority = rest[:slash] if slash >= 0 else rest
    raw_path = rest[slash:] if slash >= 0 else ""
    split = _split_authority(authority)
    if split is None:
        return None
    host, port = split
    if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
        port = ""
    if scheme == "http" and host not in _LOOPBACK_HOSTS:
        return None
    path = _canonical_path(raw_path)
    if path is None:
        return None
    return f"{scheme}://{host}{':' + port if port else ''}{path}"


def _valid_port(port: str) -> str | None:
    if not port or port[0] == "0" or not port.isascii() or not port.isdigit():
        return None
    return port if 1 <= int(port) <= 65535 else None


def _split_authority(authority: str) -> tuple[str, str] | None:
    if not authority or "@" in authority:
        return None
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host = authority[: end + 1].lower()
        rest = authority[end + 1 :]
        inner = host[1:-1]
        if not inner or any(c not in _HEX and c not in ":." for c in inner):
            return None
        if not rest:
            return host, ""
        if not rest.startswith(":"):
            return None
        port = _valid_port(rest[1:])
        return None if port is None else (host, port)
    colon = authority.find(":")
    host = (authority[:colon] if colon >= 0 else authority).lower()
    if not host or host.startswith(".") or host.endswith(".") or ".." in host or not _HOST.fullmatch(host):
        return None
    if colon < 0:
        return host, ""
    port = _valid_port(authority[colon + 1 :])
    return None if port is None else (host, port)


def _canonical_path(path: str) -> str | None:
    if path in ("", "/"):
        return ""
    if path.endswith("/"):
        path = path[:-1]
    for segment in path[1:].split("/"):
        if not segment:
            return None
        i = 0
        while i < len(segment):
            c = segment[i]
            if c == "%":
                if i + 2 >= len(segment) or segment[i + 1] not in _HEX or segment[i + 2] not in _HEX:
                    return None
                i += 2
            elif c not in _PCHAR:
                return None
            i += 1
        if segment.lower().replace("%2e", ".") in (".", ".."):
            return None
    return path


def metadata_url(resource: str) -> str:
    """The RFC 9728 §3.1 metadata URL of a canonical resource: the well-known path between host and path."""
    sep = resource.find("://")
    rest = resource[sep + 3 :]
    slash = rest.find("/")
    host = rest[:slash] if slash >= 0 else rest
    path = rest[slash:] if slash >= 0 else ""
    return f"{resource[:sep]}://{host}{METADATA_PATH}{path}"


def bearer_token(header: str | None) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` header value, or ``None``."""
    scheme, _, token = (header or "").strip().partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


def permissions_of(scopes: Iterable[str]) -> tuple[str, ...]:
    """The granted scopes that are permissions: neither OpenID Connect scopes nor IAMKit organization hints."""
    return tuple(s for s in scopes if s not in PROTOCOL_SCOPES and not s.startswith("urn:iamkit:"))


# -- claims, errors and replies ------------------------------------------------------------------------
@dataclass(frozen=True)
class ResourceClaims:
    """The claims of a verified access token for the resource."""

    sub: str
    environment_id: str
    organization_id: str
    application_id: str
    resource_id: str
    session_id: str
    #: Granted scopes (OpenID Connect scopes included).
    scopes: tuple[str, ...]
    #: The granted scopes that are permissions; the token's ``permissions`` claim is never read.
    permissions: tuple[str, ...]
    exp: int
    #: The ``client_id`` the OAuth client uses (RFC 9068): its Client ID Metadata Document URL or ``dcr_`` id for
    #: external clients, else the registered client's id.
    client_id: str | None = None
    #: IAMKit's id of the client row (equal to ``client_id`` for registered clients).
    oauth_client_id: str | None = None
    #: The protected resource the authorization named (the ``resource`` claim); ``None`` only with
    #: ``allow_tokens_without_resource``.
    resource: str | None = None
    amr: tuple[str, ...] = ()
    auth_time: int | None = None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


_STATUS = {"unauthorized": 401, "invalid_token": 401, "insufficient_scope": 403, "temporarily_unavailable": 503}


class ResourceError(Exception):
    """Why a request is refused.

    ``code`` is ``unauthorized`` (no token), ``invalid_token``, ``insufficient_scope`` or
    ``temporarily_unavailable``; ``status`` is 401, 401, 403 or 503. ``www_authenticate`` is the challenge to
    send (``None`` for 503: the token was not judged, so the client keeps it). For ``insufficient_scope``,
    ``required`` are the scopes the route needs and ``granted`` the token's.
    """

    def __init__(
        self,
        status: int,
        code: str,
        www_authenticate: str | None = None,
        *,
        required: Sequence[str] = (),
        granted: Sequence[str] = (),
    ) -> None:
        super().__init__(f"{code}: {' '.join(required)}" if required else code)
        self.status = status
        self.code = code
        self.www_authenticate = www_authenticate
        self.required = tuple(required)
        self.granted = tuple(granted)


class HttpReply(NamedTuple):
    """A complete answer for an HTTP adapter: status, headers (name, value) and body."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes

    @property
    def status_line(self) -> str:
        """``"401 Unauthorized"``, as WSGI wants it."""
        return f"{self.status} {HTTPStatus(self.status).phrase}"


# -- introspection -------------------------------------------------------------------------------------
@dataclass(frozen=True)
class IntrospectionOptions:
    """Ask IAMKit (RFC 7662) whether each token is still live, after the local checks pass.

    A revoked consent, a disconnected application, a blocked client or an ended session then stops a token at
    once instead of when it expires. Fails closed: when IAMKit cannot answer (network, timeout, non-2xx, refused
    credentials) the request gets 503 without a challenge and the token is never admitted unchecked.
    """

    #: A confidential OAuth client of the resource's environment (public and external clients cannot introspect).
    client_id: str
    client_secret: str = field(repr=False)
    #: Keep an *active* answer for at most this many seconds (never past the token's ``exp``). 0, the default,
    #: asks on every request; a cached answer admits a revoked token for up to ``cache_ttl`` seconds.
    cache_ttl: float = 0.0
    #: Bound of the cache.
    max_cache_entries: int = 10_000
    #: IAMKit's origin when it differs from the issuer (default the issuer).
    base_url: str | None = None
    #: Seconds to wait for IAMKit before failing closed.
    timeout: float = 5.0
    #: Your own httpx clients (proxies, mTLS, tests).
    client: httpx.Client | None = field(default=None, repr=False)
    async_client: httpx.AsyncClient | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret:
            raise invalid_argument("introspection needs client_id and client_secret")
        if not self.cache_ttl >= 0:
            raise invalid_argument("introspection cache_ttl cannot be negative")
        if self.max_cache_entries < 1:
            raise invalid_argument("introspection max_cache_entries must be positive")


class IntrospectionCache:
    """Active answers by the token's SHA-256 (the cache never holds tokens), each kept until
    ``min(now + ttl, exp)``. Inactive answers are never cached. Bounded: expired entries go first, then the
    oldest; it is an optimization, never a list of what is allowed."""

    def __init__(self, ttl: float, limit: int, clock: Callable[[], float] = time.time) -> None:
        self._ttl = ttl
        self._limit = limit
        self._clock = clock
        self._entries: dict[bytes, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(token: str) -> bytes:
        return hashlib.sha256(token.encode()).digest()

    def fresh(self, key: bytes) -> bool:
        if self._ttl <= 0:
            return False
        with self._lock:
            until = self._entries.get(key)
            if until is None:
                return False
            if self._clock() < until:
                return True
            del self._entries[key]
            return False

    def keep(self, key: bytes, exp: float) -> None:
        if self._ttl <= 0:
            return
        now = self._clock()
        until = min(now + self._ttl, exp)
        if until <= now:
            return
        with self._lock:
            if key not in self._entries and len(self._entries) >= self._limit:
                for expired in [k for k, v in self._entries.items() if v <= now]:
                    del self._entries[expired]
                while self._entries and len(self._entries) >= self._limit:
                    del self._entries[next(iter(self._entries))]  # dicts iterate in insertion order
            self._entries[key] = until

    def __len__(self) -> int:
        return len(self._entries)


def _unique(*lists: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(item for items in lists for item in items))


# -- the server ----------------------------------------------------------------------------------------
class ResourceServerBase:
    """What :class:`ResourceServer` and :class:`AsyncResourceServer` share: configuration, the RFC 9728
    document, the token checks, scope requirements and challenges."""

    def __init__(
        self,
        issuer: str,
        resource: str,
        environment_id: str,
        organizations: Iterable[str] | None = None,
        scopes_supported: Iterable[str] = (),
        resource_name: str | None = None,
        documentation_url: str | None = None,
        keys: KeySet | None = None,
        jwks_url: str | None = None,
        leeway: float = 30.0,
        allow_tokens_without_resource: bool = False,
        introspection: IntrospectionOptions | None = None,
    ) -> None:
        """``issuer`` is IAMKit's issuer URL (the ``iss`` of its tokens), ``resource`` the server's URL as
        registered in IAMKit (canonicalized: the tokens' ``aud``) and ``environment_id`` the IAMKit environment.

        ``organizations`` admits only tokens of those organizations. ``scopes_supported`` are advertised in the
        metadata (the protected resource's ``default_scopes``). Signatures are verified with ``keys`` (share one
        :class:`KeySet` per process), else with a key set for ``jwks_url`` (default
        ``<issuer>/.well-known/jwks.json``). ``leeway`` tolerates clock skew, in seconds.

        ``allow_tokens_without_resource`` also admits tokens issued without the RFC 8707 ``resource`` parameter
        (no ``resource`` claim), such as plain OpenID Connect tokens of a client whose resource is this server.
        Off by default: such tokens were never consented for this server.

        ``introspection`` also asks IAMKit whether each token is still live (off by default: a valid signature
        is trusted until the token expires, at most the protected resource's ``access_token_ttl_seconds``).
        """
        if not issuer or not environment_id:
            raise invalid_argument("issuer and environment_id are required")
        canonical = canonical_resource(resource)
        if canonical is None:
            raise invalid_argument(f"resource {resource!r} has no canonical form")
        self.issuer = issuer
        self.resource = canonical
        self.environment_id = environment_id
        self.metadata_url = metadata_url(canonical)
        rest = canonical[canonical.index("://") + 3 :]
        slash = rest.find("/")
        #: Paths the metadata is served at: the RFC 9728 one for the resource's path, then the root one.
        self.metadata_paths: tuple[str, ...] = (
            (METADATA_PATH + rest[slash:], METADATA_PATH) if slash >= 0 else (METADATA_PATH,)
        )
        self._organizations = frozenset(organizations or ())
        self._scopes_supported = tuple(scopes_supported)
        self._resource_name = resource_name
        self._documentation_url = documentation_url
        self._leeway = leeway
        self._allow_unmarked = allow_tokens_without_resource
        self._own_keys = keys is None
        self._keys = keys or KeySet(jwks_url=jwks_url, issuer=issuer)
        self._oauth: OAuthClient | None = None
        self._cache: IntrospectionCache | None = None
        if introspection is not None:
            self._oauth = OAuthClient(
                introspection.base_url or issuer,
                introspection.client_id,
                client_secret=introspection.client_secret,
                issuer=issuer,
                client=introspection.client,
                async_client=introspection.async_client,
                timeout=introspection.timeout,
            )
            self._cache = IntrospectionCache(introspection.cache_ttl, introspection.max_cache_entries)

    # -- the document ----------------------------------------------------------------------------------
    def metadata(self) -> dict[str, Any]:
        """The RFC 9728 protected resource metadata document."""
        document: dict[str, Any] = {"resource": self.resource, "authorization_servers": [self.issuer]}
        if self._scopes_supported:
            document["scopes_supported"] = list(self._scopes_supported)
        document["bearer_methods_supported"] = ["header"]
        if self._resource_name:
            document["resource_name"] = self._resource_name
        if self._documentation_url:
            document["resource_documentation"] = self._documentation_url
        return document

    def metadata_reply(self, method: str) -> HttpReply:
        """The answer to a request at a metadata path: ``GET``/``HEAD`` the document, ``OPTIONS`` the CORS
        preflight (``Access-Control-Allow-Origin: *``, since browser-based MCP clients read it), else 405."""
        cors = [("Access-Control-Allow-Origin", "*")]
        method = method.upper()
        if method == "OPTIONS":
            headers = [
                *cors,
                ("Access-Control-Allow-Methods", "GET, OPTIONS"),
                ("Access-Control-Allow-Headers", "*"),
                ("Access-Control-Max-Age", "86400"),
                ("Content-Length", "0"),
            ]
            return HttpReply(204, headers, b"")
        if method in ("GET", "HEAD"):
            body = json.dumps(self.metadata()).encode()
            headers = [
                *cors,
                ("Content-Type", "application/json"),
                ("Cache-Control", "public, max-age=3600"),
                ("Content-Length", str(len(body))),
            ]
            return HttpReply(200, headers, body if method == "GET" else b"")
        return HttpReply(405, [*cors, ("Allow", "GET, OPTIONS"), ("Content-Length", "0")], b"")

    # -- scopes and challenges -----------------------------------------------------------------------
    def challenge(self, error: ResourceError, required_scopes: Iterable[str] = ()) -> str | None:
        """The ``WWW-Authenticate`` value for ``error``, always carrying ``resource_metadata``; ``None`` for 503
        (no challenge, so the client keeps its token). ``required_scopes`` are the scopes the request needs,
        advertised as ``scope``; for ``insufficient_scope`` the challenge asks for ``granted + required``, so a
        client stepping up keeps what it had."""
        if error.code == "temporarily_unavailable":
            return None
        params = [f'resource_metadata="{self.metadata_url}"']
        scopes = list(required_scopes)
        if error.code == "insufficient_scope":
            params.insert(0, 'error="insufficient_scope"')
            scopes = _unique(error.granted, error.required, scopes)
        elif error.code == "invalid_token":
            params[0:0] = ['error="invalid_token"', 'error_description="The access token is invalid or expired"']
        if scopes:
            params.append(f'scope="{" ".join(scopes)}"')
        return "Bearer " + ", ".join(params)

    def fail(self, code: str, *, required: Sequence[str] = (), granted: Sequence[str] = ()) -> ResourceError:
        """A :class:`ResourceError` for ``code`` with its status and challenge."""
        error = ResourceError(_STATUS[code], code, required=required, granted=granted)
        error.www_authenticate = self.challenge(error)
        return error

    def require(self, claims: ResourceClaims, *scopes: str) -> None:
        """Raises ``ResourceError`` (403 ``insufficient_scope``) unless the token was granted every scope."""
        if not all(claims.has_scope(s) for s in scopes):
            raise self.fail("insufficient_scope", required=scopes, granted=claims.scopes)

    def denial(self, error: ResourceError, required_scopes: Iterable[str] = ()) -> HttpReply:
        """The 401/403/503 answer for ``error``: a JSON body ``{"error": code}``, never cached; 401 and 403 carry
        the challenge, 503 ``Retry-After``."""
        header = self.challenge(error, required_scopes)
        body = json.dumps({"error": error.code}).encode()
        headers = [
            ("Cache-Control", "no-store"),
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ]
        if header is None:
            headers.append(("Retry-After", "5"))
        else:
            headers += [("WWW-Authenticate", header), ("Access-Control-Expose-Headers", "WWW-Authenticate")]
        return HttpReply(error.status, headers, body)

    # -- token checks ----------------------------------------------------------------------------------
    def _key_failure(self, exc: IAMKitError) -> ResourceError:
        """A failed key lookup: an outage (503) is not the token's fault, anything else is an invalid token."""
        return self.fail("temporarily_unavailable" if exc.status == 503 else "invalid_token")

    def _is_resource(self, audience: str) -> bool:
        return canonical_resource(audience) == self.resource

    def _claims(self, token: str, key: PyJWK) -> ResourceClaims:
        """The checks that need no further I/O: RS256 signature, ``iss``, ``exp``/``nbf`` with leeway, the
        resource in ``aud``, environment, user session, organizations and the ``resource`` marker."""
        try:
            payload = jwt.decode(
                token,
                key.key,
                algorithms=list(ALGORITHMS),
                issuer=self.issuer,
                leeway=self._leeway,
                options={"require": ["exp", "sub"], "verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            raise self.fail("invalid_token") from exc
        if not isinstance(payload, dict):
            raise self.fail("invalid_token")

        def text(name: str) -> str:
            value = payload.get(name)
            return value if isinstance(value, str) else ""

        def items(name: str) -> tuple[str, ...]:
            value = payload.get(name)
            return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()

        aud = payload.get("aud")
        audiences = (aud,) if isinstance(aud, str) else items("aud")
        if not any(self._is_resource(a) for a in audiences):
            raise self.fail("invalid_token")
        if (
            not text("sub")
            or text("environment_id") != self.environment_id
            or text("purpose") != "application"
            or not text("sid")
            or not text("organization_id")
        ):
            raise self.fail("invalid_token")
        if self._organizations and text("organization_id") not in self._organizations:
            raise self.fail("invalid_token")
        # Only tokens of an authorization that named this resource (RFC 8707) open it: a plain OpenID Connect
        # token of the same client was never consented for it. A marker that is present must be this resource.
        marker = text("resource")
        if marker:
            if canonical_resource(marker) != self.resource:
                raise self.fail("invalid_token")
        elif not self._allow_unmarked:
            raise self.fail("invalid_token")
        scopes = items("scp") or tuple(text("scope").split())
        auth_time = payload.get("auth_time")
        return ResourceClaims(
            sub=text("sub"),
            environment_id=text("environment_id"),
            organization_id=text("organization_id"),
            application_id=text("application_id"),
            resource_id=text("resource_id"),
            session_id=text("sid"),
            client_id=text("client_id") or None,
            oauth_client_id=text("oauth_client_id") or None,
            resource=marker or None,
            scopes=scopes,
            permissions=permissions_of(scopes),
            amr=items("amr"),
            auth_time=int(auth_time)
            if isinstance(auth_time, (int, float)) and not isinstance(auth_time, bool)
            else None,
            exp=int(payload["exp"]),
        )

    def _describes(self, answer: Introspection, claims: ResourceClaims) -> bool:
        """Whether IAMKit's answer is an active access token that is this token: the same subject, session and
        client, the same granted scopes (as a set), and the resource in its audience. Anything else describes
        another token, or a grant that changed."""
        return (
            answer.active
            and answer.token_use == "access_token"
            and answer.sub == claims.sub
            and answer.sid == claims.session_id
            and bool(claims.client_id)
            and answer.client_id == claims.client_id
            and set((answer.scope or "").split()) == set(claims.scopes)
            and any(self._is_resource(a) for a in answer.aud or [])
        )
