"""Append-only JSONL audit log.

Every login (success and failure), device approval, and session revocation is
appended as one JSON line containing timestamp, identity, method, result and
source IP.  Writes open the file in append mode and ``fsync``, so entries are
never rewritten and survive a crash of the writing process.

``AuditLog(None)`` keeps entries in memory (used by tests and by the default
in-memory manager).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._memory: list[dict[str, Any]] = []
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                self.path.touch()

    def record(
        self,
        event: str,
        *,
        principal: str | None = None,
        method: str | None = None,
        result: str | None = None,
        ip: str | None = None,
        device_id: str | None = None,
        ts: str | None = None,
        **details: Any,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": ts or _utcnow_iso(),
            "event": event,
            "principal": principal,
            "method": method,
            "result": result,
            "ip": ip,
            "device_id": device_id,
        }
        entry.update(details)
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
        if self.path is not None:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        self._memory.append(entry)
        return entry

    def entries(self) -> list[dict[str, Any]]:
        return list(self._memory)

    def read_from_disk(self) -> list[dict[str, Any]]:
        """Re-read entries from the backing file (independent of memory)."""
        if self.path is None or not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out


__all__ = ["AuditLog"]
