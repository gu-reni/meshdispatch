"""Adapter contract and shared helpers.

Real adapters translate an external source (cron jobs, subagent traces, A2A
conversations) into registry/store calls.  Every adapter is read-only with
respect to its source and idempotent with respect to the database: re-running
:meth:`OriginAdapter.sync` must not duplicate tasks, runs, messages or events.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from meshdispatch import models


# ---------------------------------------------------------------------------
# Sync statistics
# ---------------------------------------------------------------------------


@dataclass
class SyncStats:
    """Counters for a single ``sync`` invocation.

    ``*_new`` count records actually inserted; ``*_skipped`` count records
    that were already present (idempotent re-sync) or unrepresentable.
    ``skipped`` is the total across all entity kinds.
    """

    tasks_new: int = 0
    tasks_updated: int = 0
    tasks_skipped: int = 0
    runs_new: int = 0
    runs_skipped: int = 0
    messages_new: int = 0
    messages_skipped: int = 0
    events_new: int = 0
    events_skipped: int = 0

    @property
    def skipped(self) -> int:
        return (
            self.tasks_skipped
            + self.runs_skipped
            + self.messages_skipped
            + self.events_skipped
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "tasks_new": self.tasks_new,
            "tasks_updated": self.tasks_updated,
            "tasks_skipped": self.tasks_skipped,
            "runs_new": self.runs_new,
            "runs_skipped": self.runs_skipped,
            "messages_new": self.messages_new,
            "messages_skipped": self.messages_skipped,
            "events_new": self.events_new,
            "events_skipped": self.events_skipped,
            "skipped": self.skipped,
        }

    def __add__(self, other: "SyncStats") -> "SyncStats":
        return SyncStats(
            tasks_new=self.tasks_new + other.tasks_new,
            tasks_updated=self.tasks_updated + other.tasks_updated,
            tasks_skipped=self.tasks_skipped + other.tasks_skipped,
            runs_new=self.runs_new + other.runs_new,
            runs_skipped=self.runs_skipped + other.runs_skipped,
            messages_new=self.messages_new + other.messages_new,
            messages_skipped=self.messages_skipped + other.messages_skipped,
            events_new=self.events_new + other.events_new,
            events_skipped=self.events_skipped + other.events_skipped,
        )


# ---------------------------------------------------------------------------
# Adapter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class OriginAdapter(Protocol):
    """A read-only source of tasks that can be pulled into the registry."""

    name: str  # 'cron' | 'a2a' | 'subagent'

    def sync(self, registry: object, *, since: str | None = None) -> SyncStats: ...


# ---------------------------------------------------------------------------
# Path / identity helpers
# ---------------------------------------------------------------------------


def hermes_home() -> Path:
    """Resolve the Hermes data root.

    Defaults to ``~/.hermes`` but is overridable with ``MESHDISPATCH_HERMES_HOME``
    so that non-Hermes users can point the adapters at their own layout.
    """
    default = str(Path.home() / ".hermes")
    return Path(os.environ.get("MESHDISPATCH_HERMES_HOME", default)).expanduser()


def local_hostname() -> str:
    """The local machine's name, used as the default assignee / participant."""
    return os.environ.get("MESHDISPATCH_HOST") or socket.gethostname()


def parse_since(since: str | None) -> datetime | None:
    """Normalize a ``--since`` value into an aware UTC datetime, or ``None``."""
    if not since:
        return None
    normalized = models.normalize_ts(since)
    if normalized is None:
        return None
    return datetime.fromisoformat(normalized)


def _to_dt(value: str | None) -> datetime | None:
    """Best-effort parse of an arbitrary timestamp string into aware UTC."""
    if not value:
        return None
    try:
        normalized = models.normalize_ts(value)
        return datetime.fromisoformat(normalized) if normalized else None
    except ValueError:
        return None


def _to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return models.normalize_ts(dt)


__all__ = [
    "OriginAdapter",
    "SyncStats",
    "hermes_home",
    "local_hostname",
    "parse_since",
]
