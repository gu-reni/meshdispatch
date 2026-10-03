"""Push-path client (phase 5a).

Reads the local store and POSTs it to a remote panel's ``/api/ingest`` endpoint
in batches.  The sender side of cross-server onboarding: no dependency on the
remote host beyond the ingest endpoint and a per-agent token.

Standard library only -- the transport is :mod:`urllib.request`, matching the
A2A dispatch transport.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

from .. import models
from ..adapters.base import local_hostname, parse_since
from ..store import Store

#: Default number of tasks per batch (each task drags its runs/messages/events).
DEFAULT_BATCH_SIZE = 50

#: Per-request timeout for the ingest POST.
DEFAULT_TIMEOUT = 15.0


class PushError(Exception):
    """A batch could not be delivered (network/HTTP failure)."""


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = models.normalize_ts(value)
    if normalized is None:
        return None
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _collect(store: Store, since: str | None) -> list[dict[str, Any]]:
    """Return every task (with its runs/messages/events) after ``since``."""
    since_dt = parse_since(since)
    collected: list[dict[str, Any]] = []
    for task in store.list_tasks():
        created_dt = _parse_iso(task.get("created_at"))
        if since_dt is not None and created_dt is not None and created_dt < since_dt:
            continue
        detail = store.get_task_detail(task["id"])
        collected.append(
            detail
            or {"task": task, "runs": [], "messages": [], "events": []}
        )
    return collected


def _task_item(task: dict[str, Any]) -> dict[str, Any]:
    return {key: task.get(key) for key in (
        "id", "title", "body", "origin", "origin_ref", "assignee",
        "coordination", "participants", "status", "created_at", "updated_at",
        "last_run_at", "result",
    )}


def _run_item(task: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task["id"],
        "agent": run.get("agent"),
        "status": run.get("status"),
        "started_at": run.get("started_at"),
        "ended_at": run.get("ended_at"),
        "outcome": run.get("outcome"),
        "summary": run.get("summary"),
        "error_type": run.get("error_type"),
        "source_key": run.get("source_key")
        or f"push:{task['id']}:run:{run['id']}",
    }


def _message_item(task: dict[str, Any], msg: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task["id"],
        "author": msg.get("author"),
        "author_kind": msg.get("author_kind"),
        "body": msg.get("body"),
        "visibility": msg.get("visibility", "local"),
        "created_at": msg.get("created_at"),
        "source_key": msg.get("source_key")
        or f"push:{task['id']}:message:{msg['id']}",
    }


def _event_item(task: dict[str, Any], ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task["id"],
        "kind": ev.get("kind"),
        "payload": ev.get("payload", {}),
        "created_at": ev.get("created_at"),
        "source_key": ev.get("source_key")
        or f"push:{task['id']}:event:{ev['id']}",
    }


def build_batch(agent: str, details: list[dict[str, Any]]) -> dict[str, Any]:
    """Flatten ``details`` (task + nested relations) into one ingest payload."""
    tasks: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for detail in details:
        task = detail["task"]
        tasks.append(_task_item(task))
        for run in detail.get("runs", []):
            runs.append(_run_item(task, run))
        for msg in detail.get("messages", []):
            messages.append(_message_item(task, msg))
        for ev in detail.get("events", []):
            events.append(_event_item(task, ev))
    return {"agent": agent, "tasks": tasks, "runs": runs,
            "messages": messages, "events": events}


def post_batch(
    url: str,
    token: str,
    payload: dict[str, Any],
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """POST one batch; return ``{"status", "body"}`` or raise :class:`PushError`."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except TimeoutError as exc:
        raise PushError(f"timed out after {timeout}s") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise PushError(f"timed out after {timeout}s") from exc
        raise PushError(str(exc)) from exc

    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except json.JSONDecodeError:
        parsed = {}
    return {"status": status, "body": parsed if isinstance(parsed, dict) else {}}


def push_to(
    store: Store,
    *,
    url: str,
    token: str,
    agent: str | None = None,
    since: str | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    timeout: float = DEFAULT_TIMEOUT,
    sender: Any = None,
) -> dict[str, Any]:
    """Push the local store to ``url`` and return accepted counts + failures.

    Returns ``{"accepted": {...}, "batches": int, "failures": [str, ...]}``.
    A failed batch is recorded and does not abort the remaining ones.
    """
    agent = (agent or "").strip() or local_hostname()
    if batch_size < 1:
        batch_size = DEFAULT_BATCH_SIZE
    post = sender if sender is not None else post_batch

    details = _collect(store, since)
    accepted = {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    failures: list[str] = []
    batches = 0

    for offset in range(0, len(details), batch_size):
        batches += 1
        payload = build_batch(agent, details[offset:offset + batch_size])
        try:
            resp = post(url, token, payload, timeout)
        except PushError as exc:
            failures.append(f"batch {batches}: {exc}")
            continue
        if resp["status"] != 200:
            reason = resp["body"].get("error") if resp["body"] else ""
            failures.append(
                f"batch {batches}: HTTP {resp['status']}"
                + (f": {reason}" if reason else "")
            )
            continue
        acc = resp["body"].get("accepted", {}) or {}
        for key in accepted:
            accepted[key] += int(acc.get(key, 0))

    return {"accepted": accepted, "batches": batches, "failures": failures}


__all__ = [
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_TIMEOUT",
    "PushError",
    "build_batch",
    "post_batch",
    "push_to",
]
