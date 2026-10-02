"""meshdispatch: cross-server multi-agent task scheduling and observability.

Phase 1 ships the unified task model, the SQLite storage layer, an
idempotent task registry, and a command-line interface.  Real origin
adapters (cron / a2a / subagent / manual) land in a later phase.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
