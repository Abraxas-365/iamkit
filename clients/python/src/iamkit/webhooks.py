"""Standard Webhooks verification for event webhooks and action calls.

IAMKit signs event webhooks and action calls per Standard Webhooks
(https://www.standardwebhooks.com): headers ``webhook-id``, ``webhook-timestamp`` and
``webhook-signature`` (``v1,<base64 HMAC-SHA256>`` of ``id.timestamp.body``, several
space-separated while a secret rotation overlaps). Verify against the raw body bytes, before
any JSON parsing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import WebhookError

#: How far ``webhook-timestamp`` may be from now (5 minutes).
TOLERANCE_SECONDS = 5 * 60

#: Bodies larger than this are refused (1 MiB).
MAX_BODY = 1 << 20

_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class Conditions:
    """Action conditions."""

    PRE_SIGN_IN = "function:pre_sign_in"
    PRE_REGISTRATION = "function:pre_registration"
    POST_FEDERATION = "function:post_federation"
    PRE_ACCESS_TOKEN = "function:pre_access_token"
    PRE_ID_TOKEN = "function:pre_id_token"
    PRE_USERINFO = "function:pre_userinfo"
    USER_CREATE = "request:user.create"
    USER_UPDATE = "request:user.update"
    MEMBERSHIP_CREATE = "request:membership.create"


def _header(headers: Mapping[str, Any], name: str) -> str:
    """Case-insensitive header lookup over any mapping (dict, ``httpx.Headers``, Django/Flask headers)."""
    value = headers.get(name)
    if value is None:
        for key in headers:
            if isinstance(key, str) and key.lower() == name:
                value = headers[key]
                break
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return "" if value is None else str(value)


def verify_signature(
    secret: str,
    headers: Mapping[str, Any],
    body: bytes | str,
    *,
    now: float | None = None,
    tolerance: float = TOLERANCE_SECONDS,
) -> None:
    """Checks the signature headers of ``body`` (the raw bytes) with ``secret`` (``whsec_…``).

    Raises :class:`~iamkit.errors.WebhookError` (``SIGNATURE``, ``TIMESTAMP``, ``SECRET`` or ``BODY``)
    when it does not verify. During a secret rotation either secret's signature is accepted because
    IAMKit sends one ``v1,`` signature per live secret.
    """
    raw = secret.removeprefix("whsec_")
    if not raw or not _B64.match(raw):
        raise WebhookError("SECRET", "malformed webhook secret")
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WebhookError("SECRET", "malformed webhook secret") from exc
    if not key:
        raise WebhookError("SECRET", "malformed webhook secret")
    data = body.encode() if isinstance(body, str) else bytes(body)
    if len(data) > MAX_BODY:
        raise WebhookError("BODY", "webhook body too large")
    message_id = _header(headers, "webhook-id")
    timestamp = _header(headers, "webhook-timestamp")
    current = time.time() if now is None else now
    if not timestamp.isascii() or not timestamp.isdigit() or abs(current - int(timestamp)) > tolerance:
        raise WebhookError("TIMESTAMP", "webhook timestamp outside tolerance")
    mac = hmac.new(key, f"{message_id}.{timestamp}.".encode(), hashlib.sha256)
    mac.update(data)
    want = mac.digest()
    for signature in _header(headers, "webhook-signature").split():
        version, _, value = signature.partition(",")
        if version != "v1" or not value:
            continue
        try:
            got = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            continue
        if hmac.compare_digest(got, want):
            return
    raise WebhookError("SIGNATURE", "webhook signature mismatch")


def _decode(body: bytes | str) -> dict[str, Any]:
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise WebhookError("BODY", "webhook body is not JSON") from exc
    if not isinstance(decoded, dict):
        raise WebhookError("BODY", "webhook body is not a JSON object")
    return decoded


@dataclass(frozen=True)
class WebhookEvent:
    """An event delivered to a webhook subscription (an entry of the event log)."""

    id: int
    environment_id: str
    #: ``<subject>.<verb>``, e.g. ``user.created``; test deliveries are ``webhook.test``.
    type: str
    actor: dict[str, Any]
    subject: dict[str, Any]
    occurred_at: str
    organization_id: str | None = None
    #: ``{"truncated": true}`` past 64 KiB: read the event log for it.
    data: Any = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> WebhookEvent:
        return cls(
            id=int(raw.get("id", 0)),
            environment_id=str(raw.get("environment_id", "")),
            type=str(raw.get("type", "")),
            actor=dict(raw.get("actor") or {}),
            subject=dict(raw.get("subject") or {}),
            occurred_at=str(raw.get("occurred_at", "")),
            organization_id=raw.get("organization_id") or None,
            data=raw.get("data"),
        )


def verify_webhook(
    secret: str,
    headers: Mapping[str, Any],
    body: bytes | str,
    *,
    now: float | None = None,
    tolerance: float = TOLERANCE_SECONDS,
) -> WebhookEvent:
    """Verifies an event webhook and decodes the event.

    Deliveries are at least once: dedupe on the ``webhook-id`` header or ``event.id``. Answer 2xx quickly.
    """
    verify_signature(secret, headers, body, now=now, tolerance=tolerance)
    return WebhookEvent.from_dict(_decode(body))


@dataclass(frozen=True)
class ActionInput:
    """What an action target receives; fields a condition does not have are ``None``."""

    condition: str
    environment_id: str
    organization_id: str | None = None
    application_id: str | None = None
    client_id: str | None = None
    #: The user the flow is about; ``id`` is absent before registration.
    user: dict[str, Any] | None = None
    #: How the user signed in.
    amr: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    #: The external identity of post_federation and federated pre_registration.
    identity: dict[str, Any] | None = None
    #: The request body of a ``request:*`` condition (passwords left out).
    request: Any = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ActionInput:
        return cls(
            condition=str(raw.get("condition", "")),
            environment_id=str(raw.get("environment_id", "")),
            organization_id=raw.get("organization_id") or None,
            application_id=raw.get("application_id") or None,
            client_id=raw.get("client_id") or None,
            user=raw.get("user"),
            amr=list(raw.get("amr") or []),
            scopes=list(raw.get("scopes") or []),
            identity=raw.get("identity"),
            request=raw.get("request"),
        )


@dataclass(frozen=True)
class ActionResponse:
    """A call target's answer: answer 204 (or an empty :class:`ActionResponse`) to allow unchanged.

    ``claims`` are added to tokens/UserInfo (reserved claims refused, 4 KiB at most); ``patch``
    replaces fields the condition lets targets change; ``deny`` refuses the flow where the condition
    allows it, with ``message`` (≤ 200 characters) shown to the user.
    """

    deny: bool = False
    message: str = ""
    claims: dict[str, Any] | None = None
    patch: dict[str, Any] | None = None

    @classmethod
    def denied(cls, message: str) -> ActionResponse:
        """A response refusing the flow with ``message``."""
        return cls(deny=True, message=message)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.deny:
            out["deny"] = True
        if self.message:
            out["message"] = self.message
        if self.claims:
            out["claims"] = self.claims
        if self.patch:
            out["patch"] = self.patch
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))


def deny(message: str) -> ActionResponse:
    """A response refusing the flow with ``message``."""
    return ActionResponse.denied(message)


def verify_action(
    secret: str,
    headers: Mapping[str, Any],
    body: bytes | str,
    *,
    now: float | None = None,
    tolerance: float = TOLERANCE_SECONDS,
) -> ActionInput:
    """Verifies an action call (either secret verifies during a rotation) and decodes its input."""
    verify_signature(secret, headers, body, now=now, tolerance=tolerance)
    return ActionInput.from_dict(_decode(body))
