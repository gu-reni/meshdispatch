"""Origin adapters: cron, subagent, and A2A sources.

Each adapter is read-only with respect to its source files and idempotent with
respect to the database (``origin + origin_ref`` for tasks; ``source_key`` for
runs/messages/events).
"""

from __future__ import annotations

from .base import OriginAdapter, SyncStats, hermes_home, local_hostname, parse_since
from .hermes_cron import CronAdapter
from .hermes_subagent import SubagentAdapter
from .a2a import A2AAdapter, infer_peer

# Canonical registry of adapters by their ``origin`` name, used by the CLI's
# ``sync --adapter`` selector.
ADAPTERS: dict[str, type] = {
    CronAdapter.name: CronAdapter,
    SubagentAdapter.name: SubagentAdapter,
    A2AAdapter.name: A2AAdapter,
}

__all__ = [
    "A2AAdapter",
    "ADAPTERS",
    "CronAdapter",
    "OriginAdapter",
    "SubagentAdapter",
    "SyncStats",
    "hermes_home",
    "infer_peer",
    "local_hostname",
    "parse_since",
]
