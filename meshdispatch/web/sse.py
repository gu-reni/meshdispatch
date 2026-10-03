"""Server-sent events change detection over SQLite.

The web layer has no external broker to tell it when the store changes, so the
SSE endpoint detects new rows by polling SQLite for the highest ``rowid`` of
each table and diffing against a snapshot taken when a client connected.  Each
poll opens a fresh connection, so WAL mode always surfaces the latest committed
writes without a cross-process notification channel.
"""

from __future__ import annotations

from typing import Any

#: Tables watched for change detection.  ``tasks`` and ``approvals`` use a TEXT
#: primary key but still carry an implicit ``rowid``, so ``MAX(rowid)`` is a
#: uniform marker across every table.
_TABLES = ("tasks", "runs", "messages", "events", "approvals", "pairings")


class ChangeTracker:
    """Tracks the highest ``rowid`` per table and reports newly inserted rows.

    A tracker is created per SSE connection.  :meth:`poll` diffs the current
    maxima against the previously seen ones and returns one entry per table
    that grew.  Each entry carries the primary-key values of the new rows so a
    client can decide whether to refetch.
    """

    def __init__(self, store: Any) -> None:
        self._store = store
        self._max: dict[str, int] = self._read_maxes()

    def _read_maxes(self) -> dict[str, int]:
        conn = self._store.connect()
        try:
            return {
                table: int(
                    conn.execute(
                        f"SELECT COALESCE(MAX(rowid), 0) FROM {table}"
                    ).fetchone()[0]
                )
                for table in _TABLES
            }
        finally:
            conn.close()

    def poll(self) -> list[dict[str, Any]]:
        """Return the changes since the last poll and advance the snapshot."""
        conn = self._store.connect()
        try:
            current = {
                table: int(
                    conn.execute(
                        f"SELECT COALESCE(MAX(rowid), 0) FROM {table}"
                    ).fetchone()[0]
                )
                for table in _TABLES
            }
            changes: list[dict[str, Any]] = []
            for table in _TABLES:
                if current[table] <= self._max[table]:
                    continue
                previous = self._max[table]
                ids = [
                    row[0]
                    for row in conn.execute(
                        f"SELECT id FROM {table} WHERE rowid > ? ORDER BY rowid ASC",
                        (previous,),
                    )
                ]
                changes.append({"table": table, "ids": ids})
                self._max[table] = current[table]
            return changes
        finally:
            conn.close()


__all__ = ["ChangeTracker"]
