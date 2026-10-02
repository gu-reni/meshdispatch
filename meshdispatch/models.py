"""Unified task model: enum domains, task ids, and timestamp normalization.

This module is the single source of truth for the value domain of the
database.  Everything persisted to SQLite flows through the helpers here so
that timestamps are always normalized UTC ISO 8601 (``Z`` suffix) and enum
fields are always one of the allowed literals.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, TypeVar

# ---------------------------------------------------------------------------
# Enum domains (the contract)
# ---------------------------------------------------------------------------


class Origin(StrEnum):
    """Where a task came from."""

    CRON = "cron"
    A2A = "a2a"
    SUBAGENT = "subagent"
    MANUAL = "manual"


class Coordination(StrEnum):
    """How many agents coordinate on a task."""

    SINGLE = "single"
    MULTI = "multi"


class Status(StrEnum):
    """Lifecycle status of a task or run."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class AuthorKind(StrEnum):
    """Who authored a message."""

    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def now_utc() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def normalize_ts(value: str | datetime | None) -> str | None:
    """Normalize ``value`` to an ISO 8601 UTC string with a ``Z`` suffix.

    Accepts aware or naive datetimes and ISO 8601 strings.  Naive values are
    assumed to be UTC.  Empty/whitespace strings collapse to ``None`` so a
    column never carries an empty-string timestamp (see the "one empty
    representation" rule).
    """
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
    else:
        dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    timespec = "microseconds" if dt.microsecond else "seconds"
    return dt.isoformat(timespec=timespec).replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Task numbering
# ---------------------------------------------------------------------------


def generate_task_id(now: datetime | None = None) -> str:
    """Build a task id of the form ``md-<YYYYMMDD>-<6hex>``.

    The six-character suffix is 3 bytes of ``secrets`` entropy rendered as
    lowercase hex.  Callers are responsible for retrying on the (astronomically
    unlikely) collision with an existing row.
    """
    day = (now or now_utc()).strftime("%Y%m%d")
    suffix = secrets.token_hex(3)  # 6 lowercase hex chars
    return f"md-{day}-{suffix}"


# ---------------------------------------------------------------------------
# Enum validation
# ---------------------------------------------------------------------------

_T = TypeVar("_T", bound=StrEnum)


def coerce_enum(value: Any, enum_cls: type[_T], field: str) -> str | None:
    """Return the canonical string value of ``value`` for ``enum_cls``.

    ``None`` passes through (the caller decides whether the field is
    optional).  Anything that is not a valid member value raises
    :class:`ValueError` naming the allowed literals.
    """
    if value is None:
        return None
    if isinstance(value, enum_cls):
        return value.value
    try:
        return enum_cls(value).value
    except ValueError:
        allowed = ", ".join(repr(v.value) for v in enum_cls)
        raise ValueError(f"{field} must be one of {allowed}; got {value!r}") from None


__all__ = [
    "AuthorKind",
    "Coordination",
    "Origin",
    "Status",
    "coerce_enum",
    "generate_task_id",
    "normalize_ts",
    "now_utc",
]
