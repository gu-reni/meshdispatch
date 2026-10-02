"""Idempotent task registration.

Registering the same ``(origin, origin_ref)`` twice returns the existing task
instead of creating a duplicate.
"""

from __future__ import annotations

from typing import Any, Iterable

from . import models
from .store import Store


class Registry:
    """Registers tasks idempotently on ``(origin, origin_ref)``."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def register(
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
    ) -> tuple[dict[str, Any], bool]:
        """Register a task; return ``(task, created)``.

        ``created`` is ``False`` when an existing task matched
        ``origin + origin_ref`` (idempotent re-registration).
        """
        origin_v = models.coerce_enum(origin, models.Origin, "origin")
        if origin_ref:
            existing = self.store.find_by_origin_ref(origin_v, origin_ref)
            if existing is not None:
                return existing, False

        task_id = self.store.add_task(
            title=title,
            body=body,
            origin=origin_v,
            origin_ref=origin_ref,
            assignee=assignee,
            coordination=coordination,
            participants=participants,
            status=status,
        )
        task = self.store.get_task(task_id)
        assert task is not None
        return task, True


__all__ = ["Registry"]
