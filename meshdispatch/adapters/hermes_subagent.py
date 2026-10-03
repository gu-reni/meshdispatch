"""Hermes subagent adapter (origin = ``subagent``).

Reads one directory per delegated subagent under
``~/.hermes/cache/delegation/live/``.  Each directory holds a ``manifest.json``
with the delegation metadata and a human-readable ``task-0.log`` trace.

Mapping:

* ``origin_ref`` — the directory name (e.g. ``deleg_3dde286e``).
* ``title``      — the task goal, from the manifest first, then the trace
  header; when neither is reliably present the delegation id is used (never a
  fabricated goal).
* ``coordination`` — ``single``.

The trace's dialogue lines become ``messages`` (``assistant``/``final`` →
agent, ``user`` kickoff → system); tool calls and their results become
``events``.  Every body/payload is passed through :func:`redact` and tool
output content is never persisted (only structured status/duration fields).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

from meshdispatch import models
from meshdispatch.redact import redact
from meshdispatch.registry import Registry
from meshdispatch.store import Store

from .base import (
    SyncStats,
    hermes_home,
    local_hostname,
    parse_since,
    _to_dt,
    _to_iso,
)

# One delegation directory holds a manifest and N task logs.
_TASK_LOG_RE = re.compile(r"^task-(\d+)\.log$")

# Header lines look like ``goal: <text>`` and ``started: YYYY-MM-DD HH:MM:SS``.
_HEADER_GOAL_RE = re.compile(r"^goal:\s*(.*)$")
_HEADER_STARTED_RE = re.compile(r"^started:\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")

# Trace content lines look like ``HH:MM:SS role  | content``.  The space
# between the role and ``|`` is not always present (``assistant|`` appears
# unpadded), so whitespace around the pipe is optional.
_TRACE_LINE_RE = re.compile(r"^(\d{2}:\d{2}:\d{2})\s+([A-Za-z0-9_-]+)\s*\|\s?(.*)$")

# Roles that become agent messages, system messages, or events.
_AGENT_ROLES = {"assistant", "final"}
_SYSTEM_ROLES = {"user"}

_SUBAGENT_STATUS_MAP: dict[str, str] = {
    "completed": models.Status.DONE.value,
    "running": models.Status.RUNNING.value,
    "failed": models.Status.FAILED.value,
    "cancelled": models.Status.CANCELLED.value,
}

_MAX_PAYLOAD_CHARS = 200


class SubagentAdapter:
    """Pull delegation manifests + traces into the store."""

    name = "subagent"

    def __init__(
        self,
        *,
        delegation_dir: str | Path | None = None,
        assignee: str | None = None,
    ) -> None:
        home = hermes_home()
        self.delegation_dir = Path(
            delegation_dir
            or os.environ.get("MESHDISPATCH_SUBAGENT_DIR")
            or home / "cache" / "delegation"
        )
        self.assignee = assignee or local_hostname()

    # -- parsing (pure helpers, unit-tested) -------------------------------

    @staticmethod
    def parse_manifest(text: str) -> dict:
        """Parse ``manifest.json`` text into a small dict (never raises)."""
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return data

    @staticmethod
    def parse_trace(text: str) -> dict:
        """Parse a ``task-0.log`` into ``{goal, started, entries}``.

        ``entries`` is a list of ``(time_str, role, content)`` tuples in file
        order.  Unparseable lines are skipped.
        """
        goal: str | None = None
        started: str | None = None
        entries: list[tuple[str, str, str]] = []
        for line in text.splitlines():
            gm = _HEADER_GOAL_RE.match(line.strip())
            if gm and goal is None:
                goal = gm.group(1).strip()
                continue
            sm = _HEADER_STARTED_RE.match(line.strip())
            if sm and started is None:
                started = sm.group(1).strip()
                continue
            m = _TRACE_LINE_RE.match(line)
            if m:
                entries.append((m.group(1), m.group(2), m.group(3)))
        return {"goal": goal, "started": started, "entries": entries}

    @staticmethod
    def combine_timestamp(started: str | None, time_str: str) -> str | None:
        """Combine a header ``started`` date with a trace ``HH:MM:SS``."""
        if not started:
            return None
        try:
            base = datetime.fromisoformat(started)
        except ValueError:
            return None
        try:
            h, m, s = (int(part) for part in time_str.split(":"))
        except (ValueError, AttributeError):
            return None
        combined = base.replace(hour=h, minute=m, second=s)
        return models.normalize_ts(combined)

    @staticmethod
    def split_result(content: str) -> tuple[str | None, str | None, str | None]:
        """Split a ``result`` line into ``(tool, status, duration)``.

        Result lines look like ``terminal ERROR 0.1s: {...}`` or
        ``read_file ok 0.0s: {...}``.  The payload is discarded entirely.
        """
        m = re.match(r"^(\S+)\s+(ok|ERROR|error|warn)\s+(\S+)", content)
        if not m:
            return None, None, None
        return m.group(1), m.group(2), m.group(3)

    @staticmethod
    def split_tool(content: str) -> tuple[str | None, str | None]:
        """Split a ``tool`` line into ``(tool_name, args)``.

        Tool lines look like ``-> terminal(python3 --version + 4 commands)``.
        """
        content = content.strip()
        if content.startswith("->"):
            content = content[2:].strip()
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\((.*)\))?$", content)
        if not m:
            return None, None
        return m.group(1), m.group(2)

    # -- source discovery --------------------------------------------------

    def _iter_delegations(self) -> list[tuple[str, Path]]:
        """Return ``(delegation_id, live_dir)`` sorted by id."""
        live_dir = self.delegation_dir / "live"
        if not live_dir.is_dir():
            return []
        dirs = sorted(
            (p for p in live_dir.iterdir() if p.is_dir()),
            key=lambda p: p.name,
        )
        return [(p.name, p) for p in dirs]

    # -- sync --------------------------------------------------------------

    def sync(self, registry: Registry, *, since: str | None = None) -> SyncStats:
        store: Store = registry.store
        stats = SyncStats()
        since_dt = parse_since(since)

        for deleg_id, live_dir in self._iter_delegations():
            manifest_path = live_dir / "manifest.json"
            manifest_text = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else "{}"
            manifest = self.parse_manifest(manifest_text)

            task_meta = (manifest.get("tasks") or [{}])
            first_task = task_meta[0] if task_meta else {}
            manifest_goal = str(first_task.get("goal") or "").strip()
            manifest_started = str(manifest.get("started") or "").strip()
            manifest_status = str(first_task.get("status") or "").strip()
            manifest_completed = str(manifest.get("completed") or "").strip()

            # Trace (task-0.log) provides goal fallback + the timestamp base.
            log_path = live_dir / "task-0.log"
            trace_text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
            trace = self.parse_trace(trace_text)
            goal = manifest_goal or (trace.get("goal") or "")
            started = manifest_started or (trace.get("started") or "")

            # Honour --since on the delegation's start time.
            if since_dt is not None and started:
                started_dt = _to_dt(started)
                if started_dt is not None and started_dt < since_dt:
                    continue

            # Task: use the goal; fall back to the delegation id, never a lie.
            title = goal if goal else deleg_id

            task, created = registry.register(
                title=title,
                origin=models.Origin.SUBAGENT,
                origin_ref=deleg_id,
                assignee=self.assignee,
                coordination=models.Coordination.SINGLE,
            )
            if created:
                stats.tasks_new += 1
            elif task.get("title") != title or task.get("assignee") != self.assignee:
                store.update_task(task["id"], title=title, assignee=self.assignee)
                stats.tasks_updated += 1
            else:
                stats.tasks_skipped += 1

            # One run per delegation.
            run_status = _SUBAGENT_STATUS_MAP.get(
                manifest_status, models.Status.PENDING.value
            )
            duration = _duration(started, manifest_completed)
            summary = f"duration={duration:.3f}s" if duration is not None else None
            _, run_inserted = store.insert_run(
                task["id"],
                agent=self.assignee,
                status=run_status,
                started_at=_to_iso(_to_dt(started)) if started else None,
                ended_at=_to_iso(_to_dt(manifest_completed)) if manifest_completed else None,
                summary=summary,
                source_key=f"deleg:{deleg_id}:run",
            )
            if run_inserted:
                stats.runs_new += 1
            else:
                stats.runs_skipped += 1

            # Trace entries -> messages / events.
            for index, (time_str, role, content) in enumerate(trace["entries"], start=1):
                source_key = f"deleg:{deleg_id}:line:{index}"
                created_at = self.combine_timestamp(started, time_str)

                if role in _AGENT_ROLES:
                    _, inserted = store.insert_message(
                        task["id"],
                        author=deleg_id,
                        author_kind=models.AuthorKind.AGENT,
                        body=redact(content) or "(empty)",
                        created_at=created_at,
                        source_key=source_key,
                    )
                    if inserted:
                        stats.messages_new += 1
                    else:
                        stats.messages_skipped += 1
                elif role in _SYSTEM_ROLES:
                    _, inserted = store.insert_message(
                        task["id"],
                        author=self.assignee,
                        author_kind=models.AuthorKind.SYSTEM,
                        body=redact(content) or "(empty)",
                        created_at=created_at,
                        source_key=source_key,
                    )
                    if inserted:
                        stats.messages_new += 1
                    else:
                        stats.messages_skipped += 1
                elif role == "tool":
                    tool_name, args = self.split_tool(content)
                    payload: dict = {
                        "tool": tool_name or "",
                        "args": redact(_clip(args or "")) or "",
                    }
                    _, inserted = store.insert_event(
                        task["id"],
                        kind="tool_call",
                        payload=payload,
                        created_at=created_at,
                        source_key=source_key,
                    )
                    if inserted:
                        stats.events_new += 1
                    else:
                        stats.events_skipped += 1
                elif role == "result":
                    tool_name, status, duration = self.split_result(content)
                    payload = {
                        "tool": tool_name or "",
                        "status": status or "",
                        "duration": duration or "",
                    }
                    _, inserted = store.insert_event(
                        task["id"],
                        kind="tool_result",
                        payload=payload,
                        created_at=created_at,
                        source_key=source_key,
                    )
                    if inserted:
                        stats.events_new += 1
                    else:
                        stats.events_skipped += 1
                elif role == "start":
                    _, inserted = store.insert_event(
                        task["id"],
                        kind="start",
                        payload={"goal": redact(_clip(content))},
                        created_at=created_at,
                        source_key=source_key,
                    )
                    if inserted:
                        stats.events_new += 1
                    else:
                        stats.events_skipped += 1
                # 'think' (internal reasoning) is intentionally dropped.

        return stats


def _clip(text: str, limit: int = _MAX_PAYLOAD_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _duration(started: str | None, completed: str | None) -> float | None:
    start = _to_dt(started)
    end = _to_dt(completed)
    if start is None or end is None or end < start:
        return None
    return (end - start).total_seconds()


__all__ = ["SubagentAdapter"]
