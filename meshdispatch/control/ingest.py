"""Push-path ingest (phase 5a).

This is the receiver half of cross-server onboarding: an authenticated agent
posts a batch of ``{agent, tasks, runs, messages, events}`` and this module
reconciles it into the local store.

Idempotency mirrors the pull adapters exactly:

* **tasks** are deduplicated on ``origin + origin_ref`` (and, when that key is
  absent, on the sender's task id) so a re-pushed batch never creates a second
  task;
* **runs / messages / events** are deduplicated on ``(task_id, source_key)``,
  the same partial unique indexes the adapters rely on.

Each child record carries the *sender's* ``task_id`` or ``origin_ref``; the
receiver maps either to the local task id (preserved where possible) before
inserting.  This keeps a task's id stable across servers while still honouring
``origin + origin_ref`` as the source of truth for deduplication.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..store import Store

#: Fields copied verbatim from a local task row into the push payload.
_TASK_FIELDS = (
    "id",
    "title",
    "body",
    "origin",
    "origin_ref",
    "assignee",
    "coordination",
    "participants",
    "status",
    "created_at",
    "updated_at",
    "last_run_at",
    "result",
)

#: Fields that make up a child record's natural identity.  Used to synthesise a
#: stable ``source_key`` when the sender omitted one, so a re-pushed batch still
#: deduplicates children instead of writing them a second time.
_CHILD_IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "runs": ("agent", "status", "started_at", "ended_at", "outcome", "summary", "error_type"),
    "messages": ("author", "author_kind", "body", "visibility", "created_at"),
    "events": ("kind", "payload", "created_at"),
}


def _child_source_key(kind: str, local_id: str, item: dict[str, Any]) -> str:
    """Return the ``source_key`` for a child, synthesising one when absent.

    The sender's ``source_key`` (when present) is authoritative; otherwise a
    deterministic digest of the record's identity fields is used so that the
    same record pushed twice maps to the same key.
    """
    if item.get("source_key"):
        return str(item["source_key"])
    identity = {field: item.get(field) for field in _CHILD_IDENTITY_FIELDS[kind]}
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return f"ingest:{local_id}:{kind[:-1]}:{digest}"


def apply_ingest(
    store: Store,
    *,
    agent: str,
    tasks: Any = None,
    runs: Any = None,
    messages: Any = None,
    events: Any = None,
) -> dict[str, Any]:
    """Apply one ingest batch and return ``{accepted, skipped, errors}``.

    ``agent`` is the already-verified binding the request was authorised for.
    Counters under ``accepted`` are rows newly inserted; ``skipped`` counts
    rows that already existed (idempotent no-op).  A nested record that cannot
    be attributed to a task in the batch is reported under ``errors`` instead
    of being silently counted as skipped, so the report always matches what was
    actually written to the database.
    """
    tasks = [t for t in (tasks or []) if isinstance(t, dict)]
    runs = [r for r in (runs or []) if isinstance(r, dict)]
    messages = [m for m in (messages or []) if isinstance(m, dict)]
    events = [e for e in (events or []) if isinstance(e, dict)]

    accepted = {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    skipped = {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    errors: list[str] = []

    # Sender task references -> local task id.  Nested records may point at
    # their parent either by the sender's task ``id`` or by its ``origin_ref``,
    # so both keys are indexed up front (before any child is resolved) and no
    # ordering between a task and its children is assumed.
    by_id: dict[str, str] = {}
    by_ref: dict[str, str] = {}

    for index, item in enumerate(tasks):
        remote_id = item.get("id")
        origin = item.get("origin") or "manual"
        origin_ref = item.get("origin_ref")
        title = item.get("title") or "(untitled)"

        try:
            existing = None
            if origin_ref:
                existing = store.find_by_origin_ref(origin, origin_ref)
            elif remote_id:
                existing = store.get_task(remote_id)

            if existing is not None:
                local_id = existing["id"]
                skipped["tasks"] += 1
            else:
                task, _ = store.insert_task(
                    title=title,
                    body=item.get("body"),
                    origin=origin,
                    origin_ref=origin_ref,
                    assignee=item.get("assignee"),
                    coordination=item.get("coordination", "single"),
                    participants=item.get("participants"),
                    status=item.get("status", "pending"),
                    created_at=item.get("created_at"),
                    updated_at=item.get("updated_at"),
                    last_run_at=item.get("last_run_at"),
                    result=item.get("result"),
                    task_id=remote_id,
                )
                assert task is not None
                local_id = task["id"]
                accepted["tasks"] += 1
        except ValueError as exc:
            errors.append(f"tasks[{index}] {exc}")
            continue

        if remote_id:
            by_id[str(remote_id)] = local_id
        if origin_ref:
            by_ref[str(origin_ref)] = local_id

    def resolve(item: dict[str, Any], kind: str, index: int) -> str | None:
        """Map one child record to a local task id, or record an error."""
        task_id = item.get("task_id")
        origin_ref = item.get("origin_ref")
        if task_id is not None:
            key = str(task_id)
            if key in by_id:
                return by_id[key]
            if key in by_ref:
                return by_ref[key]
        if origin_ref is not None:
            key = str(origin_ref)
            if key in by_ref:
                return by_ref[key]
        reference = task_id if task_id is not None else origin_ref
        if reference is None:
            errors.append(
                f"{kind}[{index}] has no task reference; "
                f"provide 'task_id' or 'origin_ref'"
            )
        else:
            errors.append(f"{kind}[{index}] references unknown task {reference!r}")
        return None

    for index, item in enumerate(runs):
        local_id = resolve(item, "runs", index)
        if local_id is None:
            continue
        try:
            _, inserted = store.insert_run(
                local_id,
                agent=item.get("agent"),
                status=item.get("status", "done"),
                started_at=item.get("started_at"),
                ended_at=item.get("ended_at"),
                outcome=item.get("outcome"),
                summary=item.get("summary"),
                error_type=item.get("error_type"),
                source_key=_child_source_key("runs", local_id, item),
            )
        except ValueError as exc:
            errors.append(f"runs[{index}] {exc}")
            continue
        if inserted:
            accepted["runs"] += 1
        else:
            skipped["runs"] += 1

    for index, item in enumerate(messages):
        local_id = resolve(item, "messages", index)
        if local_id is None:
            continue
        try:
            _, inserted = store.insert_message(
                local_id,
                author=item.get("author") or "unknown",
                author_kind=item.get("author_kind", "agent"),
                body=item.get("body"),
                created_at=item.get("created_at"),
                visibility=item.get("visibility", "local"),
                source_key=_child_source_key("messages", local_id, item),
            )
        except ValueError as exc:
            errors.append(f"messages[{index}] {exc}")
            continue
        if inserted:
            accepted["messages"] += 1
        else:
            skipped["messages"] += 1

    for index, item in enumerate(events):
        local_id = resolve(item, "events", index)
        if local_id is None:
            continue
        try:
            _, inserted = store.insert_event(
                local_id,
                kind=item.get("kind") or "event",
                payload=item.get("payload"),
                created_at=item.get("created_at"),
                source_key=_child_source_key("events", local_id, item),
            )
        except ValueError as exc:
            errors.append(f"events[{index}] {exc}")
            continue
        if inserted:
            accepted["events"] += 1
        else:
            skipped["events"] += 1

    return {"accepted": accepted, "skipped": skipped, "errors": errors}


__all__ = ["apply_ingest"]
