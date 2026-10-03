"""Persistence for auth runtime state.

When constructed with a ``state_dir``, the store persists three JSON files
(devices, sessions, credentials) plus an append-only ``audit.jsonl``.  With
``state_dir=None`` everything is held in memory.

Secrets policy: credentials store only *hashed* material (scrypt password
digests) and public SSH keys.  TOTP seeds, the GitHub client secret and the
cookie signing key are intentionally *not* persisted here -- they live only in
config/environment and in process memory.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .audit import AuditLog

_DEVICES_FILE = "devices.json"
_SESSIONS_FILE = "sessions.json"
_CREDENTIALS_FILE = "credentials.json"
_AUDIT_FILE = "audit.jsonl"


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return default


class StateStore:
    def __init__(self, state_dir: str | Path | None = None) -> None:
        self.state_dir = Path(state_dir) if state_dir else None
        self.devices: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.credentials: dict[str, dict[str, Any]] = {}
        if self.state_dir is not None:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            self.devices = _load_json(self.state_dir / _DEVICES_FILE, {})
            self.sessions = _load_json(self.state_dir / _SESSIONS_FILE, {})
            self.credentials = _load_json(self.state_dir / _CREDENTIALS_FILE, {})
        self.audit = AuditLog(
            self.state_dir / _AUDIT_FILE if self.state_dir is not None else None
        )

    # -- persistence -------------------------------------------------------

    def _persist(self, name: str, data: Any) -> None:
        if self.state_dir is not None:
            _atomic_write(self.state_dir / name, data)

    # -- devices -----------------------------------------------------------

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        return self.devices.get(device_id)

    def set_device(self, device_id: str, record: dict[str, Any]) -> None:
        self.devices[device_id] = record
        self._persist(_DEVICES_FILE, self.devices)

    def list_devices(self, principal: str | None = None) -> list[dict[str, Any]]:
        if principal is None:
            return list(self.devices.values())
        return [d for d in self.devices.values() if d.get("principal") == principal]

    # -- sessions ----------------------------------------------------------

    def get_session(self, sid: str) -> dict[str, Any] | None:
        return self.sessions.get(sid)

    def set_session(self, sid: str, record: dict[str, Any]) -> None:
        self.sessions[sid] = record
        self._persist(_SESSIONS_FILE, self.sessions)

    def delete_session(self, sid: str) -> None:
        if sid in self.sessions:
            del self.sessions[sid]
            self._persist(_SESSIONS_FILE, self.sessions)

    def list_sessions(self, principal: str | None = None) -> list[tuple[str, dict]]:
        if principal is None:
            return list(self.sessions.items())
        return [
            (sid, rec) for sid, rec in self.sessions.items() if rec.get("principal") == principal
        ]

    # -- credentials -------------------------------------------------------

    def get_credentials(self, principal: str) -> dict[str, Any] | None:
        return self.credentials.get(principal)

    def set_credentials(self, principal: str, record: dict[str, Any]) -> None:
        self.credentials[principal] = record
        self._persist(_CREDENTIALS_FILE, self.credentials)

    def list_principals(self) -> list[str]:
        return list(self.credentials.keys())


__all__ = ["StateStore"]
