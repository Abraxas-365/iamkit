"""Helpers shared by the sync and async management clients."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._http import segment as _segment

MANAGEMENT_KEY_PREFIX = "ik_mgmt_"

#: Page size the management API clamps to (default 50, maximum 200).
MAX_PAGE_SIZE = 200


def seg(value: str, what: str = "id") -> str:
    return _segment(value, what)


def compact(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Drops ``None`` members (absent), keeps everything else."""
    return {k: v for k, v in fields.items() if v is not None}
