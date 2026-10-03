"""Hermes cron adapter (origin = ``cron``).

Reads Hermes' cron job definitions and execution history and turns them into
tasks and runs.  The adapter is strictly read-only with respect to both
sources and never persists prompt text, command bodies, or raw error strings —
only structured fields (times, status, a categorical failure type).

Data sources (each overridable via env / constructor arg, defaulting under
``~/.hermes``):

* ``cron/jobs.json``   — job definitions; ``id`` is the stable ``origin_ref``.
* ``cron/executions.db`` — one ``executions`` row per execution (one run each),
  plus ``cron_incidents`` for the categorical ``failure_type``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from meshdispatch import models
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

_EXEC_STATUS_MAP: dict[str, str] = {
    "completed": models.Status.DONE.value,
    "failed": models.Status.FAILED.value,
    "running": models.Status.RUNNING.value,
}


def _duration_seconds(started_at: str | None, finished_at: str | None) -> float | None:
    start = _to_dt(started_at)
    end = _to_dt(finished_at)
    if start is None or end is None or end < start:
        return None
    return (end - start).total_seconds()


class CronAdapter:
    """Pull cron jobs and their executions into the store."""

    name = "cron"

    def __init__(
        self,
        *,
        jobs_path: str | Path | None = None,
        executions_path: str | Path | None = None,
        assignee: str | None = None,
    ) -> None:
        home = hermes_home()
        self.jobs_path = Path(
            jobs_path
            or _env_or("MESHDISPATCH_CRON_JOBS", home / "cron" / "jobs.json")
        )
        self.executions_path = Path(
            executions_path
            or _env_or("MESHDISPATCH_CRON_EXECUTIONS", home / "cron" / "executions.db")
        )
        self.assignee = assignee or local_hostname()

    # -- source readers (kept separate for testability) --------------------

    def _read_jobs(self) -> dict[str, str]:
        """Return ``{job_id: name}`` in definition order."""
        if not self.jobs_path.exists():
            return {}
        data = json.loads(self.jobs_path.read_text(encoding="utf-8"))
        jobs = data.get("jobs", []) if isinstance(data, dict) else []
        result: dict[str, str] = {}
        for job in jobs:
            if not isinstance(job, dict):
                continue
            job_id = str(job.get("id") or "").strip()
            name = str(job.get("name") or "").strip()
            if job_id and name:
                result[job_id] = name
        return result

    def _read_failure_types(self) -> dict[str, str]:
        """Map ``job_id`` -> the most recent ``cron_incidents.failure_type``."""
        if not self.executions_path.exists():
            return {}
        try:
            conn = sqlite3.connect(self.executions_path)
        except sqlite3.Error:
            return {}
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT job_id, failure_type, first_seen_at FROM cron_incidents "
                "ORDER BY job_id, first_seen_at ASC"
            ).fetchall()
        except sqlite3.Error:
            return {}
        finally:
            conn.close()
        result: dict[str, str] = {}
        for row in rows:
            result[str(row["job_id"])] = str(row["failure_type"] or "unknown")
        return result

    def _iter_executions(self) -> list[sqlite3.Row]:
        """Return every execution row (job_id may be orphaned)."""
        if not self.executions_path.exists():
            return []
        try:
            conn = sqlite3.connect(self.executions_path)
        except sqlite3.Error:
            return []
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, job_id, status, claimed_at, started_at, finished_at, "
                "delivery_outcome FROM executions ORDER BY claimed_at ASC"
            ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()
        return rows

    # -- sync --------------------------------------------------------------

    def sync(self, registry: Registry, *, since: str | None = None) -> SyncStats:
        store: Store = registry.store
        stats = SyncStats()
        since_dt = parse_since(since)

        failure_types = self._read_failure_types()

        # Register one task per job (idempotent on origin + origin_ref).
        task_ids: dict[str, str] = {}
        for job_id, name in self._read_jobs().items():
            task, created = registry.register(
                title=name,
                origin=models.Origin.CRON,
                origin_ref=job_id,
                assignee=self.assignee,
                coordination=models.Coordination.SINGLE,
            )
            task_ids[job_id] = task["id"]
            if created:
                stats.tasks_new += 1
            elif task.get("title") != name or task.get("assignee") != self.assignee:
                store.update_task(task["id"], title=name, assignee=self.assignee)
                stats.tasks_updated += 1
            else:
                stats.tasks_skipped += 1

        # One run per execution.  Orphaned executions (job removed from the
        # definitions) cannot map to a task and are skipped.
        for ex in self._iter_executions():
            status = _EXEC_STATUS_MAP.get(str(ex["status"]))
            if status is None:
                # claimed / unknown executions never actually ran.
                stats.runs_skipped += 1
                continue
            if ex["started_at"] is None:
                stats.runs_skipped += 1
                continue
            task_id = task_ids.get(str(ex["job_id"]))
            if task_id is None:
                stats.runs_skipped += 1
                continue

            started = _to_iso(_to_dt(ex["started_at"]))
            ended = _to_iso(_to_dt(ex["finished_at"]))
            duration = _duration_seconds(ex["started_at"], ex["finished_at"])
            summary = f"duration={duration:.3f}s" if duration is not None else None
            error_type = failure_types.get(str(ex["job_id"]))

            _, inserted = store.insert_run(
                task_id,
                agent=self.assignee,
                status=status,
                started_at=started,
                ended_at=ended,
                outcome=ex["delivery_outcome"],
                summary=summary,
                error_type=error_type,
                source_key=f"exec:{ex['id']}",
            )
            if inserted:
                stats.runs_new += 1
            else:
                stats.runs_skipped += 1

        return stats


def _env_or(name: str, default: Path) -> Path:
    return Path(os.environ.get(name) or default)


__all__ = ["CronAdapter"]
