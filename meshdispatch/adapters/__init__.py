"""Adapter interfaces for task origin sources (phase 1: placeholders only).

Real adapters (cron / a2a / subagent / manual) arrive in a later phase.  This
package only declares the contract so the registry and future plugins have a
stable surface to program against.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class OriginAdapter(Protocol):
    """A source of tasks that can be pulled into the registry.

    Implementations receive a registry and translate their own event/data
    format into :meth:`meshdispatch.registry.Registry.register` calls.
    """

    origin: str

    def poll(self, registry: Any) -> list[dict[str, Any]]:
        """Fetch newly available tasks and return their registration results."""
        ...


__all__ = ["OriginAdapter"]
