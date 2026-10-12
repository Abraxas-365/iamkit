"""Errors: every failed IAMKit call or refused credential is an :class:`IAMKitError`."""

from __future__ import annotations

from typing import Any


class IAMKitError(Exception):
    """A failed IAMKit call or a refused credential.

    ``code`` is IAMKit's error code (``UNAUTHORIZED``, ``VALIDATION``,
    ``ACTION_DENIED``, ...) or, on ``/oauth/*`` endpoints, the OAuth error
    (``invalid_grant``, ``authorization_pending``, ...). ``status`` is the HTTP
    status (401 for tokens this SDK refuses locally). Network failures raise the
    ``httpx`` error instead.
    """

    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details

    def __repr__(self) -> str:
        return f"IAMKitError(status={self.status!r}, code={self.code!r}, message={self.message!r})"

    def __str__(self) -> str:
        return f"{self.code} ({self.status}): {self.message}"

    @classmethod
    def from_response(cls, status: int, body: Any) -> IAMKitError:
        """Builds an error from a failed response body (any shape).

        Understands IAMKit's envelope ``{"error": {"code", "message", "details"}}``
        and the OAuth form ``{"error": "invalid_grant", "error_description": ...}``.
        """
        if isinstance(body, dict) and "error" in body:
            err = body["error"]
            if isinstance(err, dict):
                code = err.get("code")
                message = err.get("message")
                details = err.get("details")
                return cls(
                    status,
                    code if isinstance(code, str) else "ERROR",
                    message if isinstance(message, str) else "request failed",
                    details if isinstance(details, dict) else None,
                )
            if isinstance(err, str):
                description = body.get("error_description")
                return cls(status, err, description if isinstance(description, str) and description else err)
        if status == 429:
            return cls(status, "TOO_MANY_REQUESTS", "too many requests")
        return cls(status, "http_error", "request failed")


class WebhookError(IAMKitError):
    """A webhook or action call that does not verify (``SIGNATURE``, ``TIMESTAMP``, ``SECRET``, ``BODY``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(400 if code == "BODY" else 401, code, message)


class ErrorCodes:
    """Well-known error codes."""

    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    VALIDATION = "VALIDATION"
    JWKS_UNAVAILABLE = "JWKS_UNAVAILABLE"
    ACTION_DENIED = "ACTION_DENIED"
    ACTION_FAILED = "ACTION_FAILED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED"
    PASSWORD_POLICY = "PASSWORD_POLICY"
    CAPTCHA_REQUIRED = "CAPTCHA_REQUIRED"
    SIGN_IN_BLOCKED = "SIGN_IN_BLOCKED"
    RISK_CHALLENGE = "RISK_CHALLENGE"
    CHALLENGE_UNAVAILABLE = "CHALLENGE_UNAVAILABLE"
    IDEMPOTENCY_KEY_REUSED = "IDEMPOTENCY_KEY_REUSED"
    # OAuth
    INVALID_GRANT = "invalid_grant"
    INVALID_CLIENT = "invalid_client"
    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"
    ACCESS_DENIED = "access_denied"


def unauthorized(message: str) -> IAMKitError:
    return IAMKitError(401, ErrorCodes.UNAUTHORIZED, message)


def invalid_argument(message: str) -> IAMKitError:
    return IAMKitError(400, ErrorCodes.VALIDATION, message)
