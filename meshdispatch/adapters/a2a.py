"""A2A conversation adapter (origin = ``a2a``).

Reads ``~/.hermes/a2a_conversations/ctx-*.jsonl`` — one JSON object per line,
each ``{ts, role, text, task_id}``.  A single file is one conversation whose
context id is the filename between ``ctx-`` and ``.jsonl``.

Mapping:

* ``origin_ref``  — the context id from the filename.
* ``coordination`` — ``multi`` (local + remote participant).
* ``participants`` — the local machine plus the inferred peer; the peer name is
  derived from content signals only and left empty when it cannot be inferred
  reliably (never fabricated).

Each ``user`` / ``agent`` line becomes a message; both sides are agents in the
A2A protocol, so ``author_kind`` is ``agent`` for both and the ``author``
field (peer vs local) carries the distinction.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from meshdispatch import models
from meshdispatch.redact import redact
from meshdispatch.registry import Registry
from meshdispatch.store import Store

from .base import SyncStats, hermes_home, local_hostname, parse_since

_CTX_FILE_RE = re.compile(r"^ctx-(.+)\.jsonl$")

# Peer-name signals, in priority order.  ``A2A_TRUSTED_PEERS=`` is the most
# explicit "who am I configured to talk to" signal; ``来源 a2a / X`` and
# ``来自 X`` are progressively weaker.
_TRUSTED_PEERS_RE = re.compile(r"A2A_TRUSTED_PEERS=([A-Za-z0-9_.,-]+)")
_SOURCE_A2A_RE = re.compile(r"来源\s*a2a\s*/\s*([A-Za-z0-9_.-]+)")
_FROM_RE = re.compile(r"来自\s*([A-Za-z0-9_.-]+)")

_GENERIC_NAMES = {"self", "local", "remote", "peer", "agent", "user"}

_TITLE_MAX_CHARS = 200


def infer_peer(text: str, local_name: str) -> str | None:
    """Best-effort inference of the remote participant name from content.

    Returns a single name only when exactly one distinct non-local candidate is
    found; otherwise ``None`` (ambiguous or unavailable).
    """
    if not text:
        return None
    candidates: list[str] = []
    for m in _TRUSTED_PEERS_RE.finditer(text):
        candidates.extend(part.strip() for part in m.group(1).split(","))
    for m in _SOURCE_A2A_RE.finditer(text):
        candidates.append(m.group(1).strip())
    for m in _FROM_RE.finditer(text):
        candidates.append(m.group(1).strip())

    local_lower = local_name.lower()
    excluded = _GENERIC_NAMES | {local_lower}
    unique: list[str] = []
    for candidate in candidates:
        c = candidate.strip()
        if not c:
            continue
        if c.lower() in excluded:
            continue
        if c not in unique:
            unique.append(c)
    if len(unique) == 1:
        return unique[0]
    return None


def _ts_to_iso(ts: float | int | None) -> str | None:
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None
    return models.normalize_ts(dt)


def _derive_title(lines: list[dict]) -> str:
    """Use the first user message's first non-empty line as an honest title."""
    for line in lines:
        if line.get("role") != "user":
            continue
        text = str(line.get("text") or "").strip()
        if not text:
            continue
        first_line = next(
            (ln.strip() for ln in text.splitlines() if ln.strip()), ""
        )
        title = first_line or text
        if len(title) > _TITLE_MAX_CHARS:
            title = title[:_TITLE_MAX_CHARS] + "…"
        return title
    return ""


class A2AAdapter:
    """Pull A2A conversation transcripts into the store."""

    name = "a2a"

    def __init__(
        self,
        *,
        conversations_dir: str | Path | None = None,
        local_name: str | None = None,
    ) -> None:
        home = hermes_home()
        self.conversations_dir = Path(
            conversations_dir
            or os.environ.get("MESHDISPATCH_A2A_DIR")
            or home / "a2a_conversations"
        )
        self.local_name = local_name or local_hostname()

    # -- source discovery --------------------------------------------------

    def _iter_files(self) -> list[Path]:
        if not self.conversations_dir.is_dir():
            return []
        files = [
            p
            for p in self.conversations_dir.iterdir()
            if p.is_file() and _CTX_FILE_RE.match(p.name)
        ]
        return sorted(files, key=lambda p: p.name)

    # -- sync --------------------------------------------------------------

    def sync(self, registry: Registry, *, since: str | None = None) -> SyncStats:
        store: Store = registry.store
        stats = SyncStats()
        since_dt = parse_since(since)
        since_epoch = since_dt.timestamp() if since_dt is not None else None

        for path in self._iter_files():
            context_id = _CTX_FILE_RE.match(path.name).group(1)  # type: ignore[union-attr]

            lines: list[dict] = []
            for raw in path.read_text(encoding="utf-8").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    lines.append(obj)
            if not lines:
                continue

            if since_epoch is not None:
                lines = [
                    ln
                    for ln in lines
                    if ln.get("ts") is None or float(ln["ts"]) >= since_epoch
                ]
            if not lines:
                continue

            all_text = " ".join(str(ln.get("text") or "") for ln in lines)
            peer = infer_peer(all_text, self.local_name)
            participants = [self.local_name] + ([peer] if peer else [])
            title = _derive_title(lines) or f"a2a:{context_id}"

            task, created = registry.register(
                title=title,
                origin=models.Origin.A2A,
                origin_ref=context_id,
                coordination=models.Coordination.MULTI,
                participants=participants,
            )
            if created:
                stats.tasks_new += 1
            elif (
                task.get("title") != title
                or task.get("participants") != participants
            ):
                store.update_task(
                    task["id"], title=title, participants=participants
                )
                stats.tasks_updated += 1
            else:
                stats.tasks_skipped += 1

            for line in lines:
                role = line.get("role")
                text = str(line.get("text") or "")
                ts = line.get("ts")
                created_at = _ts_to_iso(ts)
                source_key = f"a2a:{context_id}:{role}:{ts}"

                if role == "user":
                    author = peer or "remote"
                    _, inserted = store.insert_message(
                        task["id"],
                        author=author,
                        author_kind=models.AuthorKind.AGENT,
                        body=redact(text) or "(empty)",
                        created_at=created_at,
                        visibility="local",
                        source_key=source_key,
                    )
                elif role == "agent":
                    _, inserted = store.insert_message(
                        task["id"],
                        author=self.local_name,
                        author_kind=models.AuthorKind.AGENT,
                        body=redact(text) or "(empty)",
                        created_at=created_at,
                        visibility="local",
                        source_key=source_key,
                    )
                else:
                    stats.messages_skipped += 1
                    continue

                if inserted:
                    stats.messages_new += 1
                else:
                    stats.messages_skipped += 1

        return stats


__all__ = ["A2AAdapter", "infer_peer"]
