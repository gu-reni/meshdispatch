"""SQLite storage layer for meshdispatch.

The database file defaults to ``./meshdispatch.db`` and can be overridden
with the ``MESHDISPATCH_DB`` environment variable.  Every connection runs in
WAL mode with foreign-key enforcement on; the schema and indexes are created
idempotently on open.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from . import models
from .auth.crypto import hash_password, verify_password
from .redact import redact

DEFAULT_DB_PATH = "meshdispatch.db"

#: Default lifetime of an approval request before it can no longer be decided.
DEFAULT_APPROVAL_TTL_SECONDS = 30 * 60

_APPROVAL_RISKS = ("low", "medium", "high")
_APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")
_APPROVAL_DECISIONS = ("approved", "rejected")

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
    error_type  TEXT,
    source_key  TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    run_id      INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    author      TEXT NOT NULL,
    author_kind TEXT NOT NULL,
    body        TEXT NOT NULL,
    visibility  TEXT NOT NULL DEFAULT 'local',
    source_key  TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    run_id      INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    source_key  TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    name        TEXT PRIMARY KEY,
    description TEXT,
    endpoint    TEXT,
    transport   TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id                  TEXT PRIMARY KEY,
    task_id             TEXT NOT NULL,
    agent               TEXT NOT NULL,
    command             TEXT NOT NULL,
    purpose             TEXT,
    impact              TEXT,
    risk                TEXT NOT NULL,
    status              TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    requested_at        TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    decided_at          TEXT,
    decided_by          TEXT,
    decision_signature  TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_runs_task_id ON runs(task_id);
CREATE INDEX IF NOT EXISTS idx_messages_task_id ON messages(task_id);
CREATE INDEX IF NOT EXISTS idx_events_task_id ON events(task_id);
CREATE TABLE IF NOT EXISTS ingest_tokens (
    id          TEXT PRIMARY KEY,
    agent       TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_requested_at ON approvals(requested_at);

CREATE TABLE IF NOT EXISTS pairings (
    id              TEXT PRIMARY KEY,
    code_hash       TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    decided_at      TEXT,
    decided_by      TEXT,
    device_id       TEXT
);

CREATE INDEX IF NOT EXISTS idx_pairings_status ON pairings(status);
"""

# Columns added since the phase-1 schema.  ``connect`` runs these as idempotent
# ``ALTER TABLE`` statements against any pre-existing database, so an old DB is
# upgraded in place and re-running never errors.
_COLUMN_MIGRATIONS: list[tuple[str, str, str]] = [
    ("messages", "visibility", "TEXT NOT NULL DEFAULT 'local'"),
    ("runs", "source_key", "TEXT"),
    ("messages", "source_key", "TEXT"),
    ("events", "source_key", "TEXT"),
]

# Partial unique indexes power adapter idempotency: a record with a non-NULL
# ``source_key`` can only exist once per task.  Created after ``_COLUMN_MIGRATIONS``
# because they reference the columns those migrations add.
_SOURCE_KEY_INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_source_key
    ON runs(task_id, source_key) WHERE source_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_source_key
    ON messages(task_id, source_key) WHERE source_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_key
    ON events(task_id, source_key) WHERE source_key IS NOT NULL;
"""

_VISIBILITY_VALUES = ("local", "public")


def _migrate(conn: sqlite3.Connection) -> None:
    """Add any columns that a phase-1 database is missing (idempotent)."""
    for table, column, decl in _COLUMN_MIGRATIONS:
        existing = {
            row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
        }
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    conn.commit()


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


def _agent_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = _row_to_dict(row)
    data["enabled"] = bool(data.get("enabled"))
    return data


def _approval_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return _row_to_dict(row)


def _pairing_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return _row_to_dict(row)


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


def _require_visibility(value: str) -> str:
    if value not in _VISIBILITY_VALUES:
        raise ValueError(
            f"visibility must be one of {', '.join(_VISIBILITY_VALUES)}; got {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Approval helpers
# ---------------------------------------------------------------------------


class ApprovalError(Exception):
    """Base class for approval workflow errors."""


class ApprovalNotFound(ApprovalError):
    """The requested approval id does not exist."""

    def __init__(self, approval_id: str) -> None:
        self.approval_id = approval_id
        super().__init__(f"no such approval: {approval_id}")


class ApprovalConflict(ApprovalError):
    """The approval has already been decided (or consumed) and cannot be."""

    def __init__(self, approval_id: str, status: str) -> None:
        self.approval_id = approval_id
        self.status = status
        super().__init__(f"approval {approval_id} is already {status}")


class ApprovalExpired(ApprovalError):
    """The approval is past its expiry and can no longer be decided."""

    def __init__(self, approval_id: str) -> None:
        self.approval_id = approval_id
        super().__init__(f"approval {approval_id} has expired")


def generate_approval_id(now: datetime | None = None) -> str:
    """Build an approval id of the form ``ap-<YYYYMMDD>-<6hex>``.

    Mirrors :func:`models.generate_task_id`; callers retry on the (astronomically
    unlikely) primary-key collision.
    """
    day = (now or models.now_utc()).strftime("%Y%m%d")
    suffix = secrets.token_hex(3)  # 6 lowercase hex chars
    return f"ap-{day}-{suffix}"


def _require_approval_risk(value: str) -> str:
    if value not in _APPROVAL_RISKS:
        raise ValueError(
            f"risk must be one of {', '.join(_APPROVAL_RISKS)}; got {value!r}"
        )
    return value


def _require_approval_status(value: str) -> str:
    if value not in _APPROVAL_STATUSES:
        raise ValueError(
            f"status must be one of {', '.join(_APPROVAL_STATUSES)}; got {value!r}"
        )
    return value


def _require_approval_decision(value: str) -> str:
    if value == "approve":
        value = "approved"
    elif value == "reject":
        value = "rejected"
    if value not in _APPROVAL_DECISIONS:
        raise ValueError(
            f"decision must be one of approved, rejected; got {value!r}"
        )
    return value


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _add_seconds(value: str, seconds: float) -> str:
    dt = _parse_ts(value) + timedelta(seconds=seconds)
    return models.normalize_ts(dt)


def sign_decision(
    key: str,
    approval_id: str,
    task_id: str,
    decision: str,
    decided_by: str,
    decided_at: str,
) -> str:
    """Return the HMAC-SHA256 signature binding a decision to its fields.

    The signature covers ``approval_id``, ``task_id``, ``decision``,
    ``decided_by`` and ``decided_at`` so a recorded decision cannot be replayed
    against a different approval, task, actor or time.
    """
    payload = "\n".join(
        [str(approval_id), str(task_id), str(decision), str(decided_by), str(decided_at)]
    )
    return hmac.new(key.encode("utf-8"), payload.encode("utf-8"), "sha256").hexdigest()


def verify_decision(
    key: str,
    approval_id: str,
    task_id: str,
    decision: str,
    decided_by: str,
    decided_at: str,
    signature: str | None,
) -> bool:
    """Constant-time check that ``signature`` matches the bound decision."""
    expected = sign_decision(key, approval_id, task_id, decision, decided_by, decided_at)
    return hmac.compare_digest(expected, signature or "")


def _as_list(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _redact_payload(payload: Any) -> Any:
    """Recursively redact credential-shaped strings inside a payload.

    Applied to event payloads before they are serialized so that a tool-call
    argument carrying a credential never reaches the database.  Only string
    *values* are rewritten; keys and non-string values pass through unchanged,
    so the redacted payload stays valid JSON.
    """
    if isinstance(payload, dict):
        return {key: _redact_payload(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_redact_payload(item) for item in payload]
    if isinstance(payload, str):
        return redact(payload)
    return payload


def _serialize_payload(payload: Any) -> str:
    """Redact and JSON-encode an event payload (any JSON value).

    ``None`` collapses to ``{}``.  Scalars (string, number, boolean) are valid
    JSON and are stored verbatim; only objects/lists are recursed into for
    redaction.  Anything the encoder rejects raises the same ``ValueError`` the
    ingest path turns into a clean per-record error.
    """
    if payload is None:
        payload = {}
    try:
        return json.dumps(_redact_payload(payload), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("payload must be a JSON-serializable object") from exc


def generate_ingest_token() -> tuple[str, str]:
    """Mint an ingest token, returning ``(token_id, plaintext_token)``.

    The token is ``<id>.<secret>``.  ``id`` is public (used to index the row,
    printed by ``token list`` and accepted by ``token revoke``); ``secret`` is
    the random part that is only ever stored *hashed*.  The plaintext is
    returned exactly once to the caller, who is responsible for handing it to
    the pushing agent and then discarding it.
    """
    token_id = "mdit-" + secrets.token_hex(6)
    secret = secrets.token_hex(32)
    return token_id, f"{token_id}.{secret}"


def _ingest_token_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = _row_to_dict(row)
    data.pop("token_hash", None)
    data["revoked"] = data.get("revoked_at") is not None
    return data


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class Store:
    """Thin, typed facade over the meshdispatch SQLite schema."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        approval_signing_key: str | None = None,
    ) -> None:
        self.db_path = Path(db_path) if db_path is not None else get_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.approval_signing_key = (
            approval_signing_key
            or os.environ.get("MESHDISPATCH_APPROVAL_SIGNING_KEY")
            or secrets.token_hex(32)
        )

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        _migrate(conn)
        conn.executescript(_SOURCE_KEY_INDEXES)
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

    def update_task(
        self,
        task_id: str,
        *,
        title: str | None = None,
        body: str | None = None,
        assignee: str | None = None,
        status: models.Status | str | None = None,
        coordination: models.Coordination | str | None = None,
        participants: Iterable[str] | None = None,
    ) -> dict[str, Any] | None:
        """Update the provided fields of a task and return the fresh row.

        Only fields explicitly passed (non-``None``) are touched; ``updated_at``
        is bumped.  Returns ``None`` when no such task exists.
        """
        sets: list[str] = []
        params: list[Any] = []
        if title is not None:
            sets.append("title=?")
            params.append(_require_text(title, "title"))
        if body is not None:
            sets.append("body=?")
            params.append(_empty_to_none(body))
        if assignee is not None:
            sets.append("assignee=?")
            params.append(_empty_to_none(assignee))
        if status is not None:
            sets.append("status=?")
            params.append(models.coerce_enum(status, models.Status, "status"))
        if coordination is not None:
            sets.append("coordination=?")
            params.append(
                models.coerce_enum(coordination, models.Coordination, "coordination")
            )
        if participants is not None:
            sets.append("participants=?")
            params.append(json.dumps(_as_list(participants), ensure_ascii=False))
        if not sets:
            return self.get_task(task_id)
        sets.append("updated_at=?")
        params.append(models.normalize_ts(models.now_utc()))
        params.append(task_id)

        conn = self.connect()
        try:
            cur = conn.execute(
                f"UPDATE tasks SET {', '.join(sets)} WHERE id=?", params
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
        finally:
            conn.close()
        return self.get_task(task_id)

    def insert_task(
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
        created_at: str | None = None,
        updated_at: str | None = None,
        last_run_at: str | None = None,
        result: str | None = None,
        task_id: str | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Insert a task with explicit timestamps/result and an optional id.

        Returns ``(task, True)``.  ``task_id`` is used verbatim when supplied
        and free; if it collides with an existing row a fresh id is generated
        instead (callers that need idempotency should resolve ``origin +
        origin_ref`` or the id *before* calling).  Unlike :meth:`add_task`,
        ``created_at`` / ``updated_at`` / ``last_run_at`` / ``result`` can be
        preserved from a remote host rather than stamped to "now".
        """
        title = _require_text(title, "title")
        origin_v = models.coerce_enum(origin, models.Origin, "origin")
        coord_v = models.coerce_enum(coordination, models.Coordination, "coordination")
        status_v = models.coerce_enum(status, models.Status, "status")
        parts = _as_list(participants)
        now = models.normalize_ts(models.now_utc())
        created = models.normalize_ts(created_at) or now
        updated = models.normalize_ts(updated_at) or created
        last_run = models.normalize_ts(last_run_at)
        body = _empty_to_none(body)
        origin_ref = _empty_to_none(origin_ref)
        assignee = _empty_to_none(assignee)
        result = _empty_to_none(result)

        conn = self.connect()
        try:
            candidate = task_id
            for _ in range(128):
                if candidate is None:
                    candidate = models.generate_task_id()
                try:
                    conn.execute(
                        "INSERT INTO tasks (id, title, body, origin, origin_ref, "
                        "assignee, coordination, participants, status, created_at, "
                        "updated_at, last_run_at, result) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            candidate,
                            title,
                            body,
                            origin_v,
                            origin_ref,
                            assignee,
                            coord_v,
                            json.dumps(parts, ensure_ascii=False),
                            status_v,
                            created,
                            updated,
                            last_run,
                            result,
                        ),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT * FROM tasks WHERE id=?", (candidate,)
                    ).fetchone()
                    return _task_from_row(row), True
                except sqlite3.IntegrityError:
                    clash = conn.execute(
                        "SELECT 1 FROM tasks WHERE id=?", (candidate,)
                    ).fetchone()
                    if clash:
                        candidate = None
                        continue
                    raise
            raise RuntimeError("failed to allocate a unique task id after 128 attempts")
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
                    _empty_to_none(redact(summary)),
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

    def insert_run(
        self,
        task_id: str,
        *,
        agent: str | None = None,
        status: models.Status | str = models.Status.DONE,
        started_at: str | None = None,
        ended_at: str | None = None,
        outcome: str | None = None,
        summary: str | None = None,
        error_type: str | None = None,
        source_key: str | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Insert a historical run row; idempotent on ``(task_id, source_key)``.

        Returns ``(run, inserted)``.  When a run with the same ``source_key``
        already exists the insert is a no-op and ``(None, False)`` is returned.
        """
        status_v = models.coerce_enum(status, models.Status, "status")
        started = models.normalize_ts(started_at)
        ended = models.normalize_ts(ended_at)
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO runs (task_id, agent, status, started_at, ended_at, "
                "outcome, summary, error_type, source_key) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(task_id, source_key) WHERE source_key IS NOT NULL "
                "DO NOTHING",
                (
                    task_id,
                    _empty_to_none(agent),
                    status_v,
                    started,
                    ended,
                    _empty_to_none(outcome),
                    _empty_to_none(redact(summary)),
                    _empty_to_none(error_type),
                    _empty_to_none(source_key),
                ),
            )
            if cur.rowcount == 0:
                return None, False
            run_id = cur.lastrowid
            conn.execute(
                "UPDATE tasks SET status=?, last_run_at=?, updated_at=? WHERE id=?",
                (status_v, ended or started, now, task_id),
            )
            conn.commit()
            return self._get_run(conn, run_id), True
        finally:
            conn.close()

    # -- messages ---------------------------------------------------------

    def add_message(
        self,
        task_id: str,
        author: str,
        author_kind: models.AuthorKind | str = models.AuthorKind.AGENT,
        body: str | None = None,
        run_id: int | None = None,
        visibility: str = "local",
    ) -> dict[str, Any]:
        author = _require_text(author, "author")
        body = _require_text(body, "body")
        kind_v = models.coerce_enum(author_kind, models.AuthorKind, "author_kind")
        vis_v = _require_visibility(visibility)
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO messages (task_id, run_id, author, author_kind, body, "
                "visibility, created_at) VALUES (?,?,?,?,?,?,?)",
                (task_id, run_id, author, kind_v, body, vis_v, now),
            )
            msg_id = cur.lastrowid
            conn.execute("UPDATE tasks SET updated_at=? WHERE id=?", (now, task_id))
            conn.commit()
            row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
            return _row_to_dict(row)
        finally:
            conn.close()

    def insert_message(
        self,
        task_id: str,
        author: str,
        author_kind: models.AuthorKind | str = models.AuthorKind.AGENT,
        body: str | None = None,
        *,
        run_id: int | None = None,
        created_at: str | None = None,
        visibility: str = "local",
        source_key: str | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Insert a message with an explicit timestamp; idempotent on source key.

        Returns ``(message, inserted)``.
        """
        author = _require_text(author, "author")
        body = _require_text(body, "body")
        kind_v = models.coerce_enum(author_kind, models.AuthorKind, "author_kind")
        vis_v = _require_visibility(visibility)
        ts = models.normalize_ts(created_at) or models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO messages (task_id, run_id, author, author_kind, body, "
                "visibility, source_key, created_at) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(task_id, source_key) WHERE source_key IS NOT NULL "
                "DO NOTHING",
                (task_id, run_id, author, kind_v, body, vis_v, _empty_to_none(source_key), ts),
            )
            if cur.rowcount == 0:
                return None, False
            msg_id = cur.lastrowid
            conn.execute(
                "UPDATE tasks SET updated_at=? WHERE id=?", (models.normalize_ts(models.now_utc()), task_id)
            )
            conn.commit()
            row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
            return _row_to_dict(row), True
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
        payload_json = _serialize_payload(payload)
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO events (task_id, run_id, kind, payload, created_at) "
                "VALUES (?,?,?,?,?)",
                (task_id, run_id, kind, payload_json, now),
            )
            ev_id = cur.lastrowid
            conn.execute("UPDATE tasks SET updated_at=? WHERE id=?", (now, task_id))
            conn.commit()
            row = conn.execute("SELECT * FROM events WHERE id=?", (ev_id,)).fetchone()
            return _event_from_row(row)
        finally:
            conn.close()

    # -- detail -----------------------------------------------------------

    def insert_event(
        self,
        task_id: str,
        kind: str,
        payload: dict[str, Any] | list[Any] | None = None,
        *,
        run_id: int | None = None,
        created_at: str | None = None,
        source_key: str | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Insert an event with an explicit timestamp; idempotent on source key.

        Returns ``(event, inserted)``.
        """
        kind = _require_text(kind, "kind")
        payload_json = _serialize_payload(payload)
        ts = models.normalize_ts(created_at) or models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO events (task_id, run_id, kind, payload, source_key, "
                "created_at) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(task_id, source_key) WHERE source_key IS NOT NULL "
                "DO NOTHING",
                (
                    task_id,
                    run_id,
                    kind,
                    payload_json,
                    _empty_to_none(source_key),
                    ts,
                ),
            )
            if cur.rowcount == 0:
                return None, False
            ev_id = cur.lastrowid
            conn.execute(
                "UPDATE tasks SET updated_at=? WHERE id=?",
                (models.normalize_ts(models.now_utc()), task_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM events WHERE id=?", (ev_id,)).fetchone()
            return _event_from_row(row), True
        finally:
            conn.close()

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

    # -- agents -----------------------------------------------------------

    def add_agent(
        self,
        *,
        name: str,
        description: str | None = None,
        endpoint: str | None = None,
        transport: str = "a2a",
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Insert or update an agent, keyed idempotently by ``name``.

        Re-registering an existing name overwrites its description, endpoint,
        transport and enabled flag (``created_at`` is preserved) and never
        creates a second row.
        """
        name = _require_text(name, "name")
        transport = _require_text(transport, "transport")
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO agents (name, description, endpoint, transport, "
                "enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET "
                "description=excluded.description, endpoint=excluded.endpoint, "
                "transport=excluded.transport, enabled=excluded.enabled, "
                "updated_at=excluded.updated_at",
                (
                    name,
                    _empty_to_none(description),
                    _empty_to_none(endpoint),
                    transport,
                    1 if enabled else 0,
                    now,
                    now,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
            return _agent_from_row(row)
        finally:
            conn.close()

    def get_agent(self, name: str) -> dict[str, Any] | None:
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
            return _agent_from_row(row) if row else None
        finally:
            conn.close()

    def list_agents(self) -> list[dict[str, Any]]:
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM agents ORDER BY name ASC").fetchall()
            return [_agent_from_row(r) for r in rows]
        finally:
            conn.close()

    # -- approvals --------------------------------------------------------

    def create_approval(
        self,
        *,
        task_id: str,
        agent: str,
        command: str,
        purpose: str | None = None,
        impact: str | None = None,
        risk: str = "low",
        nonce: str | None = None,
        ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
        requested_at: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        """Record a new approval request and return it.

        Returns a row with ``status == "pending"`` and a fresh ``nonce``.  The
        approval is independent of the tasks table (``task_id`` is recorded but
        not foreign-keyed) so a request can be raised for an operation that has
        no task row yet.
        """
        task_id = _require_text(task_id, "task_id")
        agent = _require_text(agent, "agent")
        command = _require_text(command, "command")
        risk = _require_approval_risk(risk)
        purpose = _empty_to_none(purpose)
        impact = _empty_to_none(impact)
        nonce = nonce or secrets.token_hex(16)
        requested = models.normalize_ts(requested_at or models.now_utc())
        expires = (
            models.normalize_ts(expires_at)
            if expires_at is not None
            else _add_seconds(requested, ttl_seconds)
        )
        conn = self.connect()
        try:
            for _ in range(128):
                approval_id = generate_approval_id()
                try:
                    conn.execute(
                        "INSERT INTO approvals (id, task_id, agent, command, "
                        "purpose, impact, risk, status, nonce, requested_at, "
                        "expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            approval_id,
                            task_id,
                            agent,
                            command,
                            purpose,
                            impact,
                            risk,
                            "pending",
                            nonce,
                            requested,
                            expires,
                        ),
                    )
                    conn.commit()
                    return self._get_approval(conn, approval_id)
                except sqlite3.IntegrityError:
                    clash = conn.execute(
                        "SELECT 1 FROM approvals WHERE id=?", (approval_id,)
                    ).fetchone()
                    if clash:
                        continue
                    raise
            raise RuntimeError("failed to allocate a unique approval id after 128 attempts")
        finally:
            conn.close()

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()
            return _approval_from_row(row) if row else None
        finally:
            conn.close()

    def _get_approval(
        self, conn: sqlite3.Connection, approval_id: str
    ) -> dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM approvals WHERE id=?", (approval_id,)
        ).fetchone()
        return _approval_from_row(row)

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        """List approvals, pending first, then most recently requested."""
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status=?")
            params.append(_require_approval_status(status))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        conn = self.connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM approvals{where} "
                "ORDER BY CASE WHEN status='pending' THEN 0 ELSE 1 END ASC, "
                "requested_at DESC, rowid DESC",
                params,
            ).fetchall()
            return [_approval_from_row(r) for r in rows]
        finally:
            conn.close()

    def decide_approval(
        self,
        approval_id: str,
        *,
        decision: str,
        decided_by: str,
        decided_at: str | None = None,
    ) -> dict[str, Any]:
        """Record a decision against a pending approval.

        Enforces the hard safety boundaries in-process:

        * single use -- a non-pending entry raises :class:`ApprovalConflict`;
        * expiry -- a past ``expires_at`` flips the row to ``expired`` and raises
          :class:`ApprovalExpired`;
        * binding -- the stored ``decision_signature`` covers the approval id,
          task id, decision, actor and time.

        This method only mutates the record; it never executes the command.
        """
        decision_v = _require_approval_decision(decision)
        decided_by = _require_text(decided_by, "decided_by")
        now = models.normalize_ts(decided_at or models.now_utc())
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()
            if row is None:
                raise ApprovalNotFound(approval_id)
            current = _approval_from_row(row)
            if current["status"] != "pending":
                raise ApprovalConflict(approval_id, current["status"])
            if _parse_ts(now) > _parse_ts(current["expires_at"]):
                conn.execute(
                    "UPDATE approvals SET status='expired' WHERE id=?", (approval_id,)
                )
                conn.commit()
                raise ApprovalExpired(approval_id)
            signature = sign_decision(
                self.approval_signing_key,
                approval_id,
                current["task_id"],
                decision_v,
                decided_by,
                now,
            )
            conn.execute(
                "UPDATE approvals SET status=?, decided_at=?, decided_by=?, "
                "decision_signature=? WHERE id=?",
                (decision_v, now, decided_by, signature, approval_id),
            )
            conn.commit()
            return self._get_approval(conn, approval_id)
        finally:
            conn.close()

    def verify_approval_signature(
        self,
        approval_id: str,
        task_id: str,
        decision: str,
        decided_by: str,
        decided_at: str,
        signature: str | None,
    ) -> bool:
        """Verify a recorded decision signature against the bound fields."""
        return verify_decision(
            self.approval_signing_key,
            approval_id,
            task_id,
            decision,
            decided_by,
            decided_at,
            signature,
        )

    # -- ingest tokens ----------------------------------------------------

    def create_ingest_token(self, agent: str) -> tuple[dict[str, Any], str]:
        """Mint an ingest token bound to ``agent``; return ``(record, plaintext)``.

        Only the plaintext returned here ever exists in the clear; the database
        stores an scrypt digest of the token's secret part and can never hand
        the token back.
        """
        agent = _require_text(agent, "agent")
        token_id, plaintext = generate_ingest_token()
        secret = plaintext.partition(".")[2]
        now = models.normalize_ts(models.now_utc())
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO ingest_tokens (id, agent, token_hash, created_at) "
                "VALUES (?,?,?,?)",
                (token_id, agent, hash_password(secret), now),
            )
            conn.commit()
        finally:
            conn.close()
        record = self.get_ingest_token(token_id)
        assert record is not None
        return record, plaintext

    def get_ingest_token(self, token_id: str) -> dict[str, Any] | None:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM ingest_tokens WHERE id=?", (token_id,)
            ).fetchone()
            return _ingest_token_from_row(row) if row else None
        finally:
            conn.close()

    def list_ingest_tokens(self) -> list[dict[str, Any]]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM ingest_tokens ORDER BY created_at ASC, id ASC"
            ).fetchall()
            return [_ingest_token_from_row(r) for r in rows]
        finally:
            conn.close()

    def revoke_ingest_token(self, token_id: str) -> bool:
        """Revoke a token; return ``False`` when it does not exist or is gone."""
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT id, revoked_at FROM ingest_tokens WHERE id=?", (token_id,)
            ).fetchone()
            if row is None or row["revoked_at"] is not None:
                return False
            now = models.normalize_ts(models.now_utc())
            conn.execute(
                "UPDATE ingest_tokens SET revoked_at=? WHERE id=?", (now, token_id)
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def verify_ingest_token(self, token: str) -> dict[str, Any] | None:
        """Resolve a plaintext ingest token to its binding, or ``None``.

        Returns ``{"id", "agent"}`` for a valid, non-revoked token.  The secret
        part is compared against the stored digest in constant time; nothing is
        ever read back in the clear.
        """
        if not isinstance(token, str) or "." not in token:
            return None
        token_id, _, secret = token.partition(".")
        if not token_id or not secret:
            return None
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT id, agent, token_hash, revoked_at FROM ingest_tokens "
                "WHERE id=?",
                (token_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or row["revoked_at"] is not None:
            return None
        if not verify_password(secret, row["token_hash"]):
            return None
        return {"id": row["id"], "agent": row["agent"]}

    # -- pairings ----------------------------------------------------------

    def insert_pairing(
        self,
        *,
        pairing_id: str,
        code_hash: str,
        display_name: str,
        public_key: str,
        key_fingerprint: str,
        status: str,
        created_at: str,
        expires_at: str,
    ) -> dict[str, Any]:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO pairings (id, code_hash, display_name, public_key, "
                "key_fingerprint, status, created_at, expires_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    pairing_id,
                    code_hash,
                    display_name,
                    public_key,
                    key_fingerprint,
                    status,
                    created_at,
                    expires_at,
                ),
            )
            conn.commit()
            return self._get_pairing(conn, pairing_id)
        finally:
            conn.close()

    def get_pairing(self, pairing_id: str) -> dict[str, Any] | None:
        conn = self.connect()
        try:
            return self._get_pairing(conn, pairing_id)
        finally:
            conn.close()

    def _get_pairing(
        self, conn: sqlite3.Connection, pairing_id: str
    ) -> dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM pairings WHERE id=?", (pairing_id,)
        ).fetchone()
        return _pairing_from_row(row) if row else None

    def list_pairings(self, status: str | None = None) -> list[dict[str, Any]]:
        """List pairings, pending first, then most recently created."""
        if status is not None:
            where = " WHERE status=?"
            params: list[Any] = [status]
        else:
            where = ""
            params = []
        conn = self.connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM pairings{where} "
                "ORDER BY CASE WHEN status='pending' THEN 0 ELSE 1 END ASC, "
                "created_at DESC, rowid DESC",
                params,
            ).fetchall()
            return [_pairing_from_row(r) for r in rows]
        finally:
            conn.close()

    def find_pairing_by_public_key(self, public_key: str) -> dict[str, Any] | None:
        """Return the most recent pairing carrying ``public_key``, if any."""
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM pairings WHERE public_key=? "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (public_key,),
            ).fetchone()
            return _pairing_from_row(row) if row else None
        finally:
            conn.close()

    def set_pairing_decision(
        self,
        pairing_id: str,
        *,
        status: str,
        decided_at: str | None = None,
        decided_by: str | None = None,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        conn = self.connect()
        try:
            conn.execute(
                "UPDATE pairings SET status=?, decided_at=?, decided_by=?, "
                "device_id=? WHERE id=?",
                (status, decided_at, decided_by, device_id, pairing_id),
            )
            conn.commit()
            return self._get_pairing(conn, pairing_id)
        finally:
            conn.close()



__all__ = [
    "ApprovalConflict",
    "ApprovalError",
    "ApprovalExpired",
    "ApprovalNotFound",
    "DEFAULT_APPROVAL_TTL_SECONDS",
    "DEFAULT_DB_PATH",
    "Store",
    "generate_approval_id",
    "generate_ingest_token",
    "get_db_path",
    "sign_decision",
    "verify_decision",
]
