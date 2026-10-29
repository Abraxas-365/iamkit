"""Management resources (synchronous). THE SOURCE OF ``_aresources.py`` — edit this file, then run
``uv run python scripts/unasync.py`` (a test fails when the generated file is stale).

Rules that keep the transformation mechanical: every method does its I/O through ``self._c.request(...)``
(``return self._c.request(...)`` / ``x = self._c.request(...)``) or iterates ``self._c.stream(...)`` in a
``for`` statement; generators loop over plain lists only.

Answers are decoded JSON documents (fields as in ``api/openapi.json``); failures raise
:class:`~iamkit.errors.IAMKitError`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from ._common import MAX_PAGE_SIZE, compact, seg
from ._core import JSON, Core


class _Resource:
    def __init__(self, core: Core) -> None:
        self._c = core

    def _offset_pages(self, path: str, params: Mapping[str, Any], page_size: int) -> Iterator[JSON]:
        """Items of an entity-list endpoint (``{"items", "page"}``), page after page."""
        offset = 0
        while True:
            page = self._c.request("GET", path, params={**params, "limit": page_size, "offset": offset})
            items = (page or {}).get("items") or []
            for item in items:
                yield item
            total = ((page or {}).get("page") or {}).get("total", 0)
            offset += len(items)
            if not items or offset >= total:
                return

    def _cursor_pages(self, path: str, params: Mapping[str, Any], page_size: int, after: int | None) -> Iterator[JSON]:
        """Items of a cursor log (``{"items", "next"}``): newest first (``before``), or oldest first from ``after``."""
        cursor = after
        while True:
            query = {**params, "limit": page_size}
            if after is not None:
                query["after"] = cursor
            elif cursor is not None:
                query["before"] = cursor
            page = self._c.request("GET", path, params=query)
            items = (page or {}).get("items") or []
            for item in items:
                yield item
            nxt = (page or {}).get("next")
            if not items or nxt in (None, 0) or nxt == cursor:
                return
            cursor = nxt


class Users(_Resource):
    """End users (``/users``). Machine users are ``kind="machine"``."""

    def list(
        self,
        *,
        search: str | None = None,
        state: str | None = None,
        kind: str | None = None,
        external_id: str | None = None,
        home_organization_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        """One page: ``{"items": [...], "page": {"total", "limit", "offset"}}``."""
        params = compact(
            {
                "search": search,
                "state": state,
                "kind": kind,
                "external_id": external_id,
                "home_organization_id": home_organization_id,
                "limit": limit,
                "offset": offset,
            }
        )
        return self._c.request("GET", f"{self._c.env()}/users", params=params)  # type: ignore[no-any-return]

    def iterate(self, *, page_size: int = MAX_PAGE_SIZE, **filters: Any) -> Iterator[JSON]:
        """Every user matching the filters (``search``, ``state``, ``kind``, ``external_id``, …), page after page."""
        return self._offset_pages(f"{self._c.env()}/users", filters, page_size)

    def get(self, user_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/users/{seg(user_id)}")  # type: ignore[no-any-return]

    def create(
        self,
        *,
        email: str | None = None,
        name: str | None = None,
        password: str | None = None,
        password_hash: str | None = None,
        email_verified: bool | None = None,
        username: str | None = None,
        external_id: str | None = None,
        home_organization_id: str | None = None,
        kind: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        avatar_url: str | None = None,
        otp_enabled: bool | None = None,
    ) -> JSON:
        """Creates a user; answers ``{"id": ...}``. ``password`` and ``password_hash`` are exclusive."""
        body = compact(
            {
                "email": email,
                "name": name,
                "password": password,
                "password_hash": password_hash,
                "email_verified": email_verified,
                "username": username,
                "external_id": external_id,
                "home_organization_id": home_organization_id,
                "kind": kind,
                "metadata": metadata,
                "avatar_url": avatar_url,
                "otp_enabled": otp_enabled,
            }
        )
        return self._c.request("POST", f"{self._c.env()}/users", json=body)  # type: ignore[no-any-return]

    def import_(self, users: Sequence[Mapping[str, Any]]) -> JSON:
        """Imports up to 1000 users (each as its own create: quota, hook, transaction).

        Answers ``{"results": [{"index", "id" | "error"}], "created", "failed"}``; a failed row does not stop the rest.
        """
        return self._c.request("POST", f"{self._c.env()}/users/import", json={"users": list(users)})  # type: ignore[no-any-return]

    def update(self, user_id: str, **fields: Any) -> None:
        """Patches a user (``name``, ``username``, ``external_id``, ``phone``, ``metadata``, ``active`` …).

        Pass ``None`` to clear a nullable field; omit a field to keep it.
        """
        self._c.request("PATCH", f"{self._c.env()}/users/{seg(user_id)}", json=fields)

    def deactivate(self, user_id: str) -> None:
        self._c.request("POST", f"{self._c.env()}/users/{seg(user_id)}/deactivate")

    def reactivate(self, user_id: str) -> None:
        self._c.request("POST", f"{self._c.env()}/users/{seg(user_id)}/reactivate")

    def suspend(self, user_id: str) -> None:
        """``DELETE /users/:id`` — the reversible removal."""
        self._c.request("DELETE", f"{self._c.env()}/users/{seg(user_id)}")

    def delete(self, user_id: str) -> None:
        """Permanently deletes a user (``DELETE /users/:id/permanent``)."""
        self._c.request("DELETE", f"{self._c.env()}/users/{seg(user_id)}/permanent")

    def revoke_sessions(self, user_id: str) -> JSON | None:
        """Ends every live session of the user (audited ``user.sessions_revoked``)."""
        return self._c.request("POST", f"{self._c.env()}/users/{seg(user_id)}/revoke-sessions")  # type: ignore[no-any-return]

    def require_password_change(self, user_id: str) -> None:
        self._c.request("POST", f"{self._c.env()}/users/{seg(user_id)}/require-password-change")

    def unlock(self, user_id: str) -> None:
        self._c.request("POST", f"{self._c.env()}/users/{seg(user_id)}/unlock")

    def history(self, user_id: str, *, limit: int | None = None, before: int | None = None) -> JSON:
        params = compact({"limit": limit, "before": before})
        return self._c.request("GET", f"{self._c.env()}/users/{seg(user_id)}/history", params=params)  # type: ignore[no-any-return]


class Organizations(_Resource):
    """Organizations, their members and invitations."""

    def list(
        self,
        *,
        search: str | None = None,
        user_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        params = compact({"search": search, "user_id": user_id, "limit": limit, "offset": offset})
        return self._c.request("GET", f"{self._c.env()}/organizations", params=params)  # type: ignore[no-any-return]

    def iterate(self, *, page_size: int = MAX_PAGE_SIZE, **filters: Any) -> Iterator[JSON]:
        return self._offset_pages(f"{self._c.env()}/organizations", filters, page_size)

    def get(self, organization_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/organizations/{seg(organization_id)}")  # type: ignore[no-any-return]

    def create(self, name: str) -> JSON:
        """Creates an organization; answers ``{"id": ...}``."""
        return self._c.request("POST", f"{self._c.env()}/organizations", json={"name": name})  # type: ignore[no-any-return]

    def update(self, organization_id: str, **fields: Any) -> None:
        """Patches an organization (``name``, ``active``, ``mfa_required``, ``allow_*``, ``domain_join`` …)."""
        self._c.request("PATCH", f"{self._c.env()}/organizations/{seg(organization_id)}", json=fields)

    def members(
        self,
        organization_id: str,
        *,
        search: str | None = None,
        active: bool | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        params = compact({"search": search, "active": active, "limit": limit, "offset": offset})
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/members"
        return self._c.request("GET", path, params=params)  # type: ignore[no-any-return]

    def iterate_members(
        self, organization_id: str, *, page_size: int = MAX_PAGE_SIZE, **filters: Any
    ) -> Iterator[JSON]:
        return self._offset_pages(f"{self._c.env()}/organizations/{seg(organization_id)}/members", filters, page_size)

    def add_member(self, organization_id: str, user_id: str) -> None:
        """Makes the user a member (``POST /memberships``)."""
        body = {"organization_id": organization_id, "user_id": user_id}
        self._c.request("POST", f"{self._c.env()}/memberships", json=body)

    def remove_member(self, organization_id: str, user_id: str) -> None:
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/members/{seg(user_id)}"
        self._c.request("DELETE", path)

    def invitations(
        self,
        organization_id: str,
        *,
        status: str | None = None,
        search: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        params = compact({"status": status, "search": search, "limit": limit, "offset": offset})
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/invitations"
        return self._c.request("GET", path, params=params)  # type: ignore[no-any-return]

    def invite(
        self,
        organization_id: str,
        email: str,
        *,
        role_ids: Sequence[str] | None = None,
        group_ids: Sequence[str] | None = None,
    ) -> JSON:
        """Issues an invitation (emailed by the deployment); answers the invitation with its one-time token."""
        body = compact({"email": email, "role_ids": role_ids, "group_ids": group_ids})
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/invitations"
        return self._c.request("POST", path, json=body)  # type: ignore[no-any-return]

    def get_invitation(self, organization_id: str, invitation_id: str) -> JSON:
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/invitations/{seg(invitation_id)}"
        return self._c.request("GET", path)  # type: ignore[no-any-return]

    def revoke_invitation(self, organization_id: str, invitation_id: str) -> None:
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/invitations/{seg(invitation_id)}"
        self._c.request("DELETE", path)

    def resend_invitation(self, organization_id: str, invitation_id: str) -> JSON | None:
        path = f"{self._c.env()}/organizations/{seg(organization_id)}/invitations/{seg(invitation_id)}/resend"
        return self._c.request("POST", path)  # type: ignore[no-any-return]


class Roles(_Resource):
    """Roles, role assignments and direct grants."""

    def list(self, *, search: str | None = None, limit: int | None = None, offset: int | None = None) -> JSON:
        params = compact({"search": search, "limit": limit, "offset": offset})
        return self._c.request("GET", f"{self._c.env()}/roles", params=params)  # type: ignore[no-any-return]

    def get(self, role_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/roles/{seg(role_id)}")  # type: ignore[no-any-return]

    def create(self, name: str, resource_id: str, permissions: Sequence[str]) -> JSON | None:
        body = {"name": name, "resource_id": resource_id, "permissions": list(permissions)}
        return self._c.request("POST", f"{self._c.env()}/roles", json=body)  # type: ignore[no-any-return]

    def update(self, role_id: str, name: str, resource_id: str, permissions: Sequence[str]) -> JSON | None:
        body = {"name": name, "resource_id": resource_id, "permissions": list(permissions)}
        return self._c.request("PUT", f"{self._c.env()}/roles/{seg(role_id)}", json=body)  # type: ignore[no-any-return]

    def delete(self, role_id: str) -> None:
        self._c.request("DELETE", f"{self._c.env()}/roles/{seg(role_id)}")

    def assignments(
        self,
        *,
        user_id: str | None = None,
        organization_id: str | None = None,
        role_id: str | None = None,
        resource_id: str | None = None,
        search: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        params = compact(
            {
                "user_id": user_id,
                "organization_id": organization_id,
                "role_id": role_id,
                "resource_id": resource_id,
                "search": search,
                "limit": limit,
                "offset": offset,
            }
        )
        return self._c.request("GET", f"{self._c.env()}/role-assignments", params=params)  # type: ignore[no-any-return]

    def assign(self, role_id: str, organization_id: str, user_id: str) -> None:
        body = {"role_id": role_id, "organization_id": organization_id, "user_id": user_id}
        self._c.request("POST", f"{self._c.env()}/role-assignments", json=body)

    def unassign(self, role_id: str, organization_id: str, user_id: str) -> None:
        path = f"{self._c.env()}/role-assignments/{seg(role_id)}/{seg(organization_id)}/{seg(user_id)}"
        self._c.request("DELETE", path)

    def grants(self, *, limit: int | None = None, offset: int | None = None, **filters: Any) -> JSON:
        params = compact({**filters, "limit": limit, "offset": offset})
        return self._c.request("GET", f"{self._c.env()}/grants", params=params)  # type: ignore[no-any-return]

    def put_grant(self, user_id: str, organization_id: str, resource_id: str, permissions: Sequence[str]) -> JSON:
        """Sets the user's direct permissions on a resource in an organization; answers ``{"id": ...}``."""
        body = {
            "user_id": user_id,
            "organization_id": organization_id,
            "resource_id": resource_id,
            "permissions": list(permissions),
        }
        return self._c.request("PUT", f"{self._c.env()}/grants", json=body)  # type: ignore[no-any-return]

    def delete_grant(self, grant_id: str) -> None:
        self._c.request("DELETE", f"{self._c.env()}/grants/{seg(grant_id)}")


class APIKeys(_Resource):
    """API keys (``ik_key_``): organization keys, and the keys of users and machine users."""

    def list(
        self,
        *,
        organization_id: str | None = None,
        user_id: str | None = None,
        owner_type: str | None = None,
        resource_id: str | None = None,
        state: str | None = None,
        search: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        params = compact(
            {
                "organization_id": organization_id,
                "user_id": user_id,
                "owner_type": owner_type,
                "resource_id": resource_id,
                "state": state,
                "search": search,
                "limit": limit,
                "offset": offset,
            }
        )
        return self._c.request("GET", f"{self._c.env()}/api-keys", params=params)  # type: ignore[no-any-return]

    def get(self, key_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/api-keys/{seg(key_id)}")  # type: ignore[no-any-return]

    def create_organization_key(
        self,
        organization_id: str,
        resource_id: str,
        name: str,
        *,
        application_id: str | None = None,
        permissions: Sequence[str] | None = None,
        expires_in: int | None = None,
    ) -> JSON:
        """Creates an organization key; the answer carries the secret ``key`` once."""
        body = compact(
            {
                "organization_id": organization_id,
                "resource_id": resource_id,
                "name": name,
                "application_id": application_id,
                "permissions": permissions,
                "expires_in": expires_in,
            }
        )
        return self._c.request("POST", f"{self._c.env()}/api-keys", json=body)  # type: ignore[no-any-return]

    def revoke(self, key_id: str) -> None:
        self._c.request("DELETE", f"{self._c.env()}/api-keys/{seg(key_id)}")

    def user_keys(self, user_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/users/{seg(user_id)}/api-keys")  # type: ignore[no-any-return]

    def create_machine_key(
        self,
        user_id: str,
        resource_id: str,
        name: str,
        application_id: str,
        *,
        organization_id: str | None = None,
        permissions: Sequence[str] | None = None,
        expires_in: int | None = None,
    ) -> JSON:
        """Creates a key for a machine user; the answer carries the secret ``key`` once."""
        body = compact(
            {
                "application_id": application_id,
                "resource_id": resource_id,
                "name": name,
                "organization_id": organization_id,
                "permissions": permissions,
                "expires_in": expires_in,
            }
        )
        return self._c.request("POST", f"{self._c.env()}/users/{seg(user_id)}/api-keys", json=body)  # type: ignore[no-any-return]

    def revoke_user_key(self, user_id: str, key_id: str) -> None:
        self._c.request("DELETE", f"{self._c.env()}/users/{seg(user_id)}/api-keys/{seg(key_id)}")

    def policy(self) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/api-key-policy")  # type: ignore[no-any-return]

    def save_policy(self, policy: Mapping[str, Any]) -> JSON | None:
        return self._c.request("PUT", f"{self._c.env()}/api-key-policy", json=dict(policy))  # type: ignore[no-any-return]


class Events(_Resource):
    """The event log (``/events``): newest first from ``before``, or a feed oldest first from ``after``."""

    def list(
        self,
        *,
        type: str | None = None,
        subject: str | None = None,
        organization_id: str | None = None,
        after: int | None = None,
        before: int | None = None,
        limit: int | None = None,
    ) -> JSON:
        """One page ``{"items", "next"}``: with ``after`` pass ``next`` as the next ``after``, else as ``before``."""
        params = compact(
            {
                "type": type,
                "subject": subject,
                "organization_id": organization_id,
                "after": after,
                "before": before,
                "limit": limit,
            }
        )
        return self._c.request("GET", f"{self._c.env()}/events", params=params)  # type: ignore[no-any-return]

    def iterate(self, *, after: int | None = None, page_size: int = MAX_PAGE_SIZE, **filters: Any) -> Iterator[JSON]:
        """Walks the log: newest first, or oldest first from the cursor ``after`` until it has nothing newer."""
        return self._cursor_pages(f"{self._c.env()}/events", filters, page_size, after)

    def export(self, *, type: str | None = None, subject: str | None = None, **filters: Any) -> Iterator[JSON]:
        """Streams matching events oldest first (NDJSON), one decoded event at a time."""
        params = compact({**filters, "type": type, "subject": subject})
        for line in self._c.stream(f"{self._c.env()}/events/export", params):
            yield json.loads(line)


class Webhooks(_Resource):
    """Event webhook subscriptions (receivers verify with :func:`iamkit.verify_webhook`)."""

    def list(self) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/webhooks")  # type: ignore[no-any-return]

    def get(self, subscription_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/webhooks/{seg(subscription_id)}")  # type: ignore[no-any-return]

    def create(self, url: str, *, name: str | None = None, types: Sequence[str] | None = None) -> JSON:
        """Creates a subscription; answers ``{"id", "secret"}`` — the ``whsec_`` secret is shown once.

        ``types`` are exact (``user.created``) or ``family.*``; empty = all.
        """
        body = compact({"url": url, "name": name, "types": types})
        return self._c.request("POST", f"{self._c.env()}/webhooks", json=body)  # type: ignore[no-any-return]

    def update(self, subscription_id: str, **fields: Any) -> JSON:
        """Patches ``url``, ``name``, ``types`` or ``active``."""
        path = f"{self._c.env()}/webhooks/{seg(subscription_id)}"
        return self._c.request("PATCH", path, json=fields)  # type: ignore[no-any-return]

    def delete(self, subscription_id: str) -> None:
        self._c.request("DELETE", f"{self._c.env()}/webhooks/{seg(subscription_id)}")

    def rotate_secret(self, subscription_id: str) -> JSON:
        """New secret; the previous one keeps signing for an overlap window."""
        path = f"{self._c.env()}/webhooks/{seg(subscription_id)}/rotate-secret"
        return self._c.request("POST", path)  # type: ignore[no-any-return]

    def test(self, subscription_id: str) -> JSON | None:
        return self._c.request("POST", f"{self._c.env()}/webhooks/{seg(subscription_id)}/test")  # type: ignore[no-any-return]

    def deliveries(
        self,
        subscription_id: str,
        *,
        status: str | None = None,
        search: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        params = compact({"status": status, "search": search, "limit": limit, "offset": offset})
        path = f"{self._c.env()}/webhooks/{seg(subscription_id)}/deliveries"
        return self._c.request("GET", path, params=params)  # type: ignore[no-any-return]

    def retry_delivery(self, subscription_id: str, delivery_id: str) -> JSON | None:
        path = f"{self._c.env()}/webhooks/{seg(subscription_id)}/deliveries/{seg(delivery_id)}/retry"
        return self._c.request("POST", path)  # type: ignore[no-any-return]

    def replay(self, subscription_id: str, from_event: int) -> JSON | None:
        """Re-queues events from event id ``from_event`` on."""
        path = f"{self._c.env()}/webhooks/{seg(subscription_id)}/replay"
        return self._c.request("POST", path, json={"from": from_event})  # type: ignore[no-any-return]


class AuditLogs(_Resource):
    """The app audit log: events your application emits about its users, per organization."""

    def emit(
        self,
        organization_id: str,
        action: str,
        occurred_at: str,
        actor: Mapping[str, Any],
        targets: Sequence[Mapping[str, Any]],
        *,
        version: int | None = None,
        context: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> JSON:
        """Emits one event (``action`` registered, ``occurred_at`` RFC 3339).

        With ``idempotency_key`` (≤ 255 characters) a retry answers the first receipt; the same key with
        another event is 409 ``IDEMPOTENCY_KEY_REUSED``.
        """
        body = compact(
            {
                "organization_id": organization_id,
                "action": action,
                "occurred_at": occurred_at,
                "actor": dict(actor),
                "targets": [dict(t) for t in targets],
                "version": version,
                "context": context,
                "metadata": metadata,
            }
        )
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._c.request("POST", f"{self._c.env()}/audit-logs/events", json=body, headers=headers)  # type: ignore[no-any-return]

    def list(
        self,
        *,
        organization_id: str | None = None,
        action: Sequence[str] | None = None,
        actor_id: str | None = None,
        actor_type: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        occurred_after: str | None = None,
        occurred_before: str | None = None,
        after: int | None = None,
        before: int | None = None,
        limit: int | None = None,
    ) -> JSON:
        """One page ``{"items", "next"}``: with ``after`` pass ``next`` as the next ``after``, else as ``before``."""
        params = compact(
            {
                "organization_id": organization_id,
                "action": ",".join(action) if action else None,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "target_id": target_id,
                "target_type": target_type,
                "occurred_after": occurred_after,
                "occurred_before": occurred_before,
                "after": after,
                "before": before,
                "limit": limit,
            }
        )
        return self._c.request("GET", f"{self._c.env()}/audit-logs/events", params=params)  # type: ignore[no-any-return]

    def iterate(self, *, after: int | None = None, page_size: int = MAX_PAGE_SIZE, **filters: Any) -> Iterator[JSON]:
        return self._cursor_pages(f"{self._c.env()}/audit-logs/events", filters, page_size, after)

    def get(self, event_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/audit-logs/events/{seg(event_id)}")  # type: ignore[no-any-return]

    def export(self, *, format: str = "ndjson", **filters: Any) -> Iterator[Any]:
        """Streams matching events oldest first: decoded dicts for ``ndjson`` (default), raw lines for ``csv``."""
        params = compact({**filters, "format": format})
        for line in self._c.stream(f"{self._c.env()}/audit-logs/events/export", params):
            yield json.loads(line) if format == "ndjson" else line

    def actions(self) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/audit-logs/actions")  # type: ignore[no-any-return]

    def create_action(
        self,
        name: str,
        *,
        description: str | None = None,
        target_types: Sequence[str] | None = None,
        schema: Mapping[str, Any] | None = None,
    ) -> JSON:
        body = compact({"name": name, "description": description, "target_types": target_types, "schema": schema})
        return self._c.request("POST", f"{self._c.env()}/audit-logs/actions", json=body)  # type: ignore[no-any-return]


class Risk(_Resource):
    """Bot protection (CAPTCHA) and risk signals."""

    def policy(self) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/risk-policy")  # type: ignore[no-any-return]

    def save_policy(self, policy: Mapping[str, Any]) -> JSON | None:
        return self._c.request("PUT", f"{self._c.env()}/risk-policy", json=dict(policy))  # type: ignore[no-any-return]

    def reset_policy(self) -> None:
        self._c.request("DELETE", f"{self._c.env()}/risk-policy")

    def status(self) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/risk/status")  # type: ignore[no-any-return]

    def restrictions(self, *, kind: str | None = None, action: str | None = None) -> JSON:
        params = compact({"kind": kind, "action": action})
        return self._c.request("GET", f"{self._c.env()}/risk-restrictions", params=params)  # type: ignore[no-any-return]

    def add_restriction(self, kind: str, action: str, value: str, *, note: str | None = None) -> JSON:
        """``kind``: ``ip``, ``country`` or ``email_domain``; ``action``: ``allow`` or ``deny``."""
        body = compact({"kind": kind, "action": action, "value": value, "note": note})
        return self._c.request("POST", f"{self._c.env()}/risk-restrictions", json=body)  # type: ignore[no-any-return]

    def delete_restriction(self, restriction_id: str) -> None:
        self._c.request("DELETE", f"{self._c.env()}/risk-restrictions/{seg(restriction_id)}")

    def sign_in_attempts(self, *, limit: int | None = None, **filters: Any) -> JSON:
        params = compact({**filters, "limit": limit})
        return self._c.request("GET", f"{self._c.env()}/sign-in-attempts", params=params)  # type: ignore[no-any-return]

    def captcha(self) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/captcha")  # type: ignore[no-any-return]

    def save_captcha(self, config: Mapping[str, Any]) -> JSON | None:
        """Saves the CAPTCHA configuration (``provider``, ``site_key``, ``secret``, ``hostnames``, ``enabled`` …)."""
        return self._c.request("PUT", f"{self._c.env()}/captcha", json=dict(config))  # type: ignore[no-any-return]

    def delete_captcha(self) -> None:
        self._c.request("DELETE", f"{self._c.env()}/captcha")

    def test_captcha(self) -> None:
        """Asks the provider to check the stored secret; 422 ``CAPTCHA_SECRET_INVALID`` when it rejects it."""
        self._c.request("POST", f"{self._c.env()}/captcha/test")


class Waitlist(_Resource):
    """The sign-up waitlist (``/waitlist``, on with the sign-in policy's ``waitlist``).

    Statuses: ``pending``, ``approved``, ``rejected``, ``completed``. Deciding an entry that is not pending
    answers 409 ``WAITLIST_ENTRY_NOT_PENDING``.
    """

    def list(
        self,
        *,
        status: str | None = None,
        email: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        """One page, newest first: ``{"items": [...], "page": {"total", "limit", "offset"}}``; ``email`` is a prefix."""
        params = compact({"status": status, "email": email, "limit": limit, "offset": offset})
        return self._c.request("GET", f"{self._c.env()}/waitlist", params=params)  # type: ignore[no-any-return]

    def iterate(self, *, page_size: int = MAX_PAGE_SIZE, **filters: Any) -> Iterator[JSON]:
        return self._offset_pages(f"{self._c.env()}/waitlist", filters, page_size)

    def get(self, entry_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/waitlist/{seg(entry_id)}")  # type: ignore[no-any-return]

    def approve(self, entry_id: str) -> JSON:
        """Approves a pending entry (or sends an approved one a new link) and emails the person the sign-up link."""
        return self._c.request("POST", f"{self._c.env()}/waitlist/{seg(entry_id)}/approve")  # type: ignore[no-any-return]

    def approve_many(self, ids: Sequence[str] | None = None, *, all_pending: bool = False) -> JSON:
        """Approves ``ids`` or every pending entry; at most 500 per call: ``{"approved", "skipped", "more"}``."""
        body = compact({"ids": list(ids) if ids is not None else None, "all_pending": all_pending or None})
        return self._c.request("POST", f"{self._c.env()}/waitlist/approve", json=body)  # type: ignore[no-any-return]

    def reject(self, entry_id: str, *, notify: bool = False) -> JSON:
        """Rejects an entry; the person is emailed only with ``notify``."""
        path = f"{self._c.env()}/waitlist/{seg(entry_id)}/reject"
        return self._c.request("POST", path, json={"notify": notify})  # type: ignore[no-any-return]

    def delete(self, entry_id: str) -> None:
        """Deletes an entry, so its email can join again."""
        self._c.request("DELETE", f"{self._c.env()}/waitlist/{seg(entry_id)}")

    def approve_all_pending(self) -> JSON:
        """Approves every pending entry, repeating while IAMKit reports ``more``: ``{"approved", "skipped"}`` totals."""
        approved = 0
        skipped = 0
        while True:
            out = self._c.request("POST", f"{self._c.env()}/waitlist/approve", json={"all_pending": True})
            done = int((out or {}).get("approved", 0))
            approved += done
            skipped += int((out or {}).get("skipped", 0))
            # Stop when nothing moved, so a stuck batch cannot loop forever.
            if not (out or {}).get("more") or not done:
                result: JSON = {"approved": approved, "skipped": skipped}
                return result


class ProtectedResources(_Resource):
    """RFC 8707 protected resources (MCP servers): clients ask for one with ``resource=<uri>`` and get tokens
    with ``aud`` = uri and the resource's permissions as scopes.
    """

    def list(self, *, limit: int | None = None, offset: int | None = None) -> JSON:
        """One page: ``{"items": [...], "page": {"total", "limit", "offset"}}``."""
        params = compact({"limit": limit, "offset": offset})
        return self._c.request("GET", f"{self._c.env()}/protected-resources", params=params)  # type: ignore[no-any-return]

    def iterate(self, *, page_size: int = MAX_PAGE_SIZE) -> Iterator[JSON]:
        return self._offset_pages(f"{self._c.env()}/protected-resources", {}, page_size)

    def get(self, protected_id: str) -> JSON:
        return self._c.request("GET", f"{self._c.env()}/protected-resources/{seg(protected_id)}")  # type: ignore[no-any-return]

    def create(
        self,
        application_id: str,
        resource_id: str,
        name: str,
        *,
        default_scopes: Sequence[str] | None = None,
        idle_ttl_seconds: int | None = None,
        max_ttl_seconds: int | None = None,
    ) -> JSON:
        """Registers a resource linked to the application; its audience must be its canonical URL.

        TTLs left out take the defaults (7 days idle, 30 days in all).
        """
        body = compact(
            {
                "application_id": application_id,
                "resource_id": resource_id,
                "name": name,
                "default_scopes": list(default_scopes) if default_scopes is not None else None,
                "idle_ttl_seconds": idle_ttl_seconds,
                "max_ttl_seconds": max_ttl_seconds,
            }
        )
        return self._c.request("POST", f"{self._c.env()}/protected-resources", json=body)  # type: ignore[no-any-return]

    def update(self, protected_id: str, **fields: Any) -> JSON:
        """Patches ``name``, ``default_scopes``, ``idle_ttl_seconds``, ``max_ttl_seconds``, ``active``
        (``active=False`` ends every authorization), ``allow_client_metadata``,
        ``allow_dynamic_registration`` (clients registered at ``/oauth/register``, while the environment's
        ``dynamic_client_registration`` feature is on) or ``client_admission`` (``"allowlist"`` or
        ``"open"``: open admits any such client without review)."""
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}"
        return self._c.request("PATCH", path, json=fields)  # type: ignore[no-any-return]

    def delete(self, protected_id: str) -> None:
        """Removes the registration and ends its authorizations; the resource stays."""
        self._c.request("DELETE", f"{self._c.env()}/protected-resources/{seg(protected_id)}")

    def impact(self, protected_id: str) -> JSON:
        """What deactivating or deleting the server would end: ``{"active_sessions", "external_clients"}``."""
        return self._c.request("GET", f"{self._c.env()}/protected-resources/{seg(protected_id)}/impact")  # type: ignore[no-any-return]

    def clients(
        self,
        protected_id: str,
        *,
        admission: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JSON:
        """One page of the clients named by Client ID Metadata Documents (``admission``: pending, approved, blocked)."""
        params = compact({"admission": admission, "limit": limit, "offset": offset})
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients"
        return self._c.request("GET", path, params=params)  # type: ignore[no-any-return]

    def iterate_clients(
        self, protected_id: str, *, admission: str | None = None, page_size: int = MAX_PAGE_SIZE
    ) -> Iterator[JSON]:
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients"
        return self._offset_pages(path, compact({"admission": admission}), page_size)

    def client(self, protected_id: str, client_id: str) -> JSON:
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}"
        return self._c.request("GET", path)  # type: ignore[no-any-return]

    def client_impact(self, protected_id: str, client_id: str) -> JSON:
        """Counts what blocking or forgetting a client would end: ``active_sessions`` and ``users``."""
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}/impact"
        return self._c.request("GET", path)  # type: ignore[no-any-return]

    def client_requests(
        self, protected_id: str, client_id: str, *, limit: int | None = None, offset: int | None = None
    ) -> JSON:
        """Who asked for a client, newest first."""
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}/requests"
        return self._c.request("GET", path, params=compact({"limit": limit, "offset": offset}))  # type: ignore[no-any-return]

    def approve_client(
        self, protected_id: str, client_id: str, *, metadata_hash: str, expires_at: str | None = None
    ) -> JSON:
        """Approves a pending, blocked or expired client, optionally until ``expires_at`` (RFC 3339).

        ``metadata_hash`` is the one of the client you reviewed (its ``metadata_hash`` field); if the
        document changed since, the call fails with 409 ``CLIENT_METADATA_CHANGED`` and approves nothing.
        """
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}/approve"
        body = compact({"metadata_hash": metadata_hash, "expires_at": expires_at})
        return self._c.request("POST", path, json=body)  # type: ignore[no-any-return]

    def block_client(self, protected_id: str, client_id: str) -> JSON:
        """Blocks a client and ends its sessions and grants."""
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}/block"
        return self._c.request("POST", path, json={})  # type: ignore[no-any-return]

    def unblock_client(self, protected_id: str, client_id: str) -> JSON:
        """Returns a blocked client to pending."""
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}/unblock"
        return self._c.request("POST", path, json={})  # type: ignore[no-any-return]

    def forget_client(self, protected_id: str, client_id: str) -> None:
        """Deletes a client and its grants; it is discovered again, as pending, the next time it is used."""
        self._c.request("DELETE", f"{self._c.env()}/protected-resources/{seg(protected_id)}/clients/{seg(client_id)}")

    def create_client_from_template(self, protected_id: str, preset: str) -> JSON:
        """Creates (or returns) the fixed client of a template preset (``cursor``, ``antigravity``, ``gemini_cli``)."""
        path = f"{self._c.env()}/protected-resources/{seg(protected_id)}/client-templates"
        return self._c.request("POST", path, json={"preset": preset})  # type: ignore[no-any-return]

    def allowlist(
        self, *, protected_resource_id: str | None = None, limit: int | None = None, offset: int | None = None
    ) -> JSON:
        """One page of the allowlist of metadata documents admitted without review."""
        params = compact({"protected_resource_id": protected_resource_id, "limit": limit, "offset": offset})
        return self._c.request("GET", f"{self._c.env()}/oauth-client-allowlist", params=params)  # type: ignore[no-any-return]

    def create_allowlist_entry(
        self,
        *,
        origin: str | None = None,
        path_prefix: str | None = None,
        preset: str | None = None,
        protected_resource_id: str | None = None,
    ) -> JSON:
        """Admits documents under ``origin`` (``https://host``) and ``path_prefix``, or a ``preset``'s document."""
        body = compact(
            {
                "origin": origin,
                "path_prefix": path_prefix,
                "preset": preset,
                "protected_resource_id": protected_resource_id,
            }
        )
        return self._c.request("POST", f"{self._c.env()}/oauth-client-allowlist", json=body)  # type: ignore[no-any-return]

    def delete_allowlist_entry(self, entry_id: str) -> None:
        """Removes an entry; clients it approved stay approved."""
        self._c.request("DELETE", f"{self._c.env()}/oauth-client-allowlist/{seg(entry_id)}")

    def presets(self) -> JSON:
        """The catalog of known MCP clients: ``{"items": [{key, name, mechanism, network, warnings, ...}]}``."""
        return self._c.request("GET", f"{self._c.env()}/oauth-client-presets")  # type: ignore[no-any-return]

    def apply_preset(self, preset: str, *, protected_resource_id: str | None = None) -> JSON:
        """Enables a preset: an allowlist entry (metadata document) or a client (template; needs the server)."""
        body = compact({"preset": preset, "protected_resource_id": protected_resource_id})
        return self._c.request("POST", f"{self._c.env()}/oauth-client-presets", json=body)  # type: ignore[no-any-return]

    def policy(self) -> JSON:
        """The environment's ceilings: ``{"max_idle_ttl_seconds", "max_lifetime_ttl_seconds"}``."""
        return self._c.request("GET", f"{self._c.env()}/protected-resource-policy")  # type: ignore[no-any-return]

    def set_policy(self, *, max_idle_ttl_seconds: int, max_lifetime_ttl_seconds: int) -> JSON:
        """Replaces the ceilings; resources above a lowered ceiling are trimmed to it."""
        body = {"max_idle_ttl_seconds": max_idle_ttl_seconds, "max_lifetime_ttl_seconds": max_lifetime_ttl_seconds}
        return self._c.request("PUT", f"{self._c.env()}/protected-resource-policy", json=body)  # type: ignore[no-any-return]
