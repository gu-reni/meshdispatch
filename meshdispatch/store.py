"""SQLite storage layer for meshdispatch.

The database file defaults to ``./meshdispatch.db`` and can be overridden
with the ``MESHDISPATCH_DB`` environment variable.  Every connection runs in
WAL mode with foreign-key enforcement on; the schema and indexes are created
idempotently on open.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from . import models

DEFAULT_DB_PATH = "meshdispatch.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id            TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    body          TEXT,
    origin        TEXT NOT NULL,
    origin_ref    TEXT,
    assignee      TEXT,
    coordination  TEXT NOT NULL,
    participants  TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_run_at   TEXT,
    result        TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    agent       TEXT,
    status      TEXT NOT NULL,
    started_at  TEXT,
    ended_at    TEXT,
    outcome     TEXT,
    summary     TEXT,
    error_type  TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    run_id      INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    author      TEXT NOT NULL,
    author_kind TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    run_id      INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_runs_task_id ON runs(task_id);
CREATE INDEX IF NOT EXISTS idx_messages_task_id ON messages(task_id);
CREATE INDEX IF NOT EXISTS idx_events_task_id ON events(task_id);
"""


def get_db_path() -> Path:
    """Resolve the database path from the environment or the default."""
    return Path(os.environ.get("MESHDISPATCH_DB", DEFAULT_DB_PATH))


# ---------------------------------------------------------------------------
# Row helpers
# ---------------------------------------------------------------------------


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _task_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = _row_to_dict(row)
    try:
        data["participants"] = json.loads(data.get("participants") or "[]")
    except (TypeError, ValueError):
        data["participants"] = []
    return data


def _event_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = _row_to_dict(row)
    try:
        data["payload"] = json.loads(data.get("payload") or "{}")
    except (TypeError, ValueError):
        data["payload"] = {}
    return data


def _empty_to_none(value: str | None) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    return value


def _require_text(value: str | None, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    return value.strip()


def _as_list(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class Store:
    """Thin, typed facade over the meshdispatch SQLite schema."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else get_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        return conn

    # -- tasks ------------------------------------------------------------

    def add_task(
        self,
        *,
        title: str,
        body: str | None = None,
        origin: models.Origin | str = models.Origin.MANUAL,
        origin_ref: str | None = None,
        assignee: str | None = None,
        coordination: models.Coordination | str = models.Coordination.SINGLE,
        participants: Iterable[str] | None = None,
        status: models.Status | str = models.Status.PENDING,
    ) -> str:
        """Insert a new task and return its generated id.

        The id is retried on the (astronomically unlikely) primary-key
        collision with an existing row.
        """
        title = _require_text(title, "title")
        origin_v = models.coerce_enum(origin, models.Origin, "origin")
        coord_v = models.coerce_enum(coordination, models.Coordination, "coordination")
        status_v = models.coerce_enum(status, models.Status, "status")
        parts = _as_list(participants)
        now = models.normalize_ts(models.now_utc())
        body = _empty_to_none(body)
        origin_ref = _empty_to_none(origin_ref)
        assignee = _empty_to_none(assignee)

        conn = self.connect()
        try:
            for _ in range(128):
                task_id = models.generate_task_id()
                try:
                    conn.execute(
                        "INSERT INTO tasks (id, title, body, origin, origin_ref, "
                        "assignee, coordination, participants, status, created_at, "
                        "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            task_id,
                            title,
                            body,
                            origin_v,
                            origin_ref,
                            assignee,
                            coord_v,
                            json.dumps(parts, ensure_ascii=False),
                            status_v,
                            now,
                            now,
                        ),
                    )
                    conn.commit()
                    return task_id
                except sqlite3.IntegrityError:
                    # Retry only on a primary-key collision; re-raise other
                    # constraint violations (NOT NULL, etc.) so they surface
                    # instead of looping 128 times.
                    clash = conn.execute(
                        "SELECT 1 FROM tasks WHERE id=?", (task_id,)
                    ).fetchone()
                    if clash:
                        continue
                    raise
            raise RuntimeError("failed to allocate a unique task id after 128 attempts")
        finally:
            conn.close()

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            return _task_from_row(row) if row else None
        finally:
            conn.close()

    def find_by_origin_ref(self, origin: str, origin_ref: str) -> dict[str, Any] | None:
        """Return the first task registered for ``(origin, origin_ref)``."""
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM tasks WHERE origin=? AND origin_ref=? "
                "ORDER BY rowid ASC LIMIT 1",
                (origin, origin_ref),
            ).fetchone()
            return _task_from_row(row) if row else None
        finally:
            conn.close()

    def list_tasks(
        self,
        status: str | None = None,
        origin: str | None = None,
        assignee: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status=?")
            params.append(models.coerce_enum(status, models.Status, "status"))
        if origin is not None:
            clauses.append("origin=?")
            params.append(models.coerce_enum(origin, models.Origin, "origin"))
        if assignee is not None:
            clauses.append("assignee=?")
            params.append(assignee)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        conn = self.connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM tasks{where} ORDER BY created_at ASC, rowid ASC",
                params,
            ).fetchall()
            return [_task_from_row(r) for r in rows]
        finally:
            conn.close()

    # -- runs -------------------------------------------------------------

    def add_run_start(self, task_id: str, agent: str | None = None) -> dict[str, Any]:
        """Record the start of a run and flip the task to ``running``."""
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO runs (task_id, agent, status, started_at) VALUES (?,?,?,?)",
                (task_id, _empty_to_none(agent), models.Status.RUNNING.value, now),
            )
            run_id = cur.lastrowid
            conn.execute(
                "UPDATE tasks SET status=?, last_run_at=?, updated_at=? WHERE id=?",
                (models.Status.RUNNING.value, now, now, task_id),
            )
            conn.commit()
            return self._get_run(conn, run_id)
        finally:
            conn.close()

    def add_run_end(
        self,
        run_id: int,
        status: models.Status | str = models.Status.DONE,
        outcome: str | None = None,
        summary: str | None = None,
        error_type: str | None = None,
    ) -> dict[str, Any]:
        """Close a run and propagate its final status onto the task."""
        status_v = models.coerce_enum(status, models.Status, "status")
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            row = conn.execute("SELECT task_id FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise LookupError(f"no run with id {run_id}")
            task_id = row["task_id"]
            conn.execute(
                "UPDATE runs SET status=?, ended_at=?, outcome=?, summary=?, "
                "error_type=? WHERE id=?",
                (
                    status_v,
                    now,
                    _empty_to_none(outcome),
                    _empty_to_none(summary),
                    _empty_to_none(error_type),
                    run_id,
                ),
            )
            conn.execute(
                "UPDATE tasks SET status=?, last_run_at=?, updated_at=?, result=? "
                "WHERE id=?",
                (status_v, now, now, _empty_to_none(outcome), task_id),
            )
            conn.commit()
            return self._get_run(conn, run_id)
        finally:
            conn.close()

    def _get_run(self, conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return _row_to_dict(row)

    # -- messages ---------------------------------------------------------

    def add_message(
        self,
        task_id: str,
        author: str,
        author_kind: models.AuthorKind | str = models.AuthorKind.AGENT,
        body: str | None = None,
        run_id: int | None = None,
    ) -> dict[str, Any]:
        author = _require_text(author, "author")
        body = _require_text(body, "body")
        kind_v = models.coerce_enum(author_kind, models.AuthorKind, "author_kind")
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO messages (task_id, run_id, author, author_kind, body, "
                "created_at) VALUES (?,?,?,?,?,?)",
                (task_id, run_id, author, kind_v, body, now),
            )
            msg_id = cur.lastrowid
            conn.execute("UPDATE tasks SET updated_at=? WHERE id=?", (now, task_id))
            conn.commit()
            row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
            return _row_to_dict(row)
        finally:
            conn.close()

    def list_messages(self, task_id: str) -> list[dict[str, Any]]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM messages WHERE task_id=? ORDER BY id ASC", (task_id,)
            ).fetchall()
            return [_row_to_dict(r) for r in rows]
        finally:
            conn.close()

    # -- events -----------------------------------------------------------

    def add_event(
        self,
        task_id: str,
        kind: str,
        payload: dict[str, Any] | list[Any] | None = None,
        run_id: int | None = None,
    ) -> dict[str, Any]:
        kind = _require_text(kind, "kind")
        if payload is None:
            payload = {}
        elif not isinstance(payload, (dict, list)):
            raise ValueError("payload must be a JSON-serializable object")
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO events (task_id, run_id, kind, payload, created_at) "
                "VALUES (?,?,?,?,?)",
                (task_id, run_id, kind, json.dumps(payload, ensure_ascii=False), now),
            )
            ev_id = cur.lastrowid
            conn.execute("UPDATE tasks SET updated_at=? WHERE id=?", (now, task_id))
            conn.commit()
            row = conn.execute("SELECT * FROM events WHERE id=?", (ev_id,)).fetchone()
            return _event_from_row(row)
        finally:
            conn.close()

    # -- detail -----------------------------------------------------------

    def get_task_detail(self, task_id: str) -> dict[str, Any] | None:
        """Return a task plus its runs, messages, and events."""
        conn = self.connect()
        try:
            task_row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task_row is None:
                return None
            runs = [
                _row_to_dict(r)
                for r in conn.execute(
                    "SELECT * FROM runs WHERE task_id=? ORDER BY id ASC", (task_id,)
                ).fetchall()
            ]
            messages = [
                _row_to_dict(r)
                for r in conn.execute(
                    "SELECT * FROM messages WHERE task_id=? ORDER BY id ASC", (task_id,)
                ).fetchall()
            ]
            events = [
                _event_from_row(r)
                for r in conn.execute(
                    "SELECT * FROM events WHERE task_id=? ORDER BY id ASC", (task_id,)
                ).fetchall()
            ]
            return {
                "task": _task_from_row(task_row),
                "runs": runs,
                "messages": messages,
                "events": events,
            }
        finally:
            conn.close()


__all__ = ["DEFAULT_DB_PATH", "Store", "get_db_path"]
