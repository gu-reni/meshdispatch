"""Approvals workflow helpers (phase 4b).

This module wires the approval *decision* path to the two things only the
auth layer owns: a principal's TOTP secret (second factor for high-risk
entries) and the append-only audit log.

Nothing here executes a command.  ``meshdispatch`` only records decisions; the
requesting agent is the one that unblocks after reading an approved entry back
from the store.  This module (and everything it feeds) never shells out to, or
evaluates, the ``command`` field.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from ..auth.totp import totp_verify

__all__ = [
    "build_audit_logger",
    "build_totp_verifier",
    "audit_logger_from_manager",
    "totp_verifier_from_manager",
]


def build_totp_verifier(secrets: Mapping[str, str]) -> Callable[[str, str], bool]:
    """Build a ``(principal, code) -> bool`` verifier over ``secrets``.

    ``secrets`` maps a principal name to its base32 TOTP shared secret.  A
    principal with no secret (or a missing/blank code) always verifies false,
    so high-risk approvals default to deny.
    """
    mapping = dict(secrets or {})

    def verify(principal: str, code: str) -> bool:
        secret = mapping.get(principal)
        if not secret:
            return False
        return totp_verify(secret, code)

    return verify


def totp_verifier_from_manager(manager: Any) -> Callable[[str, str], bool]:
    """Build a verifier from an :class:`~meshdispatch.auth.AuthManager`.

    Reads only the public ``config.principals`` mapping (TOTP secrets are never
    persisted to disk, so they are seeded from config).
    """
    secrets: dict[str, str] = {}
    config = getattr(manager, "config", None)
    principals = getattr(config, "principals", None) or {}
    for principal, pc in principals.items():
        secret = getattr(pc, "totp_secret", None)
        if secret:
            secrets[principal] = secret
    return build_totp_verifier(secrets)


def build_audit_logger(audit_log: Any) -> Callable[..., Any]:
    """Wrap an auth :class:`AuditLog` into the approvals audit callback.

    The returned callback appends entries carrying ``ts`` (time), ``principal``,
    ``ip`` and the approval-specific ``approval_id`` / ``decision`` fields.
    """

    def log(
        event: str,
        *,
        principal: str | None = None,
        approval_id: str | None = None,
        decision: str | None = None,
        ip: str | None = None,
        **details: Any,
    ) -> Any:
        return audit_log.record(
            event,
            principal=principal,
            result="success",
            ip=ip,
            approval_id=approval_id,
            decision=decision,
            **details,
        )

    return log


def audit_logger_from_manager(manager: Any) -> Callable[..., Any] | None:
    """Build the approvals audit callback from an auth manager's audit log."""
    audit = getattr(getattr(manager, "store", None), "audit", None)
    if audit is None:
        return None
    return build_audit_logger(audit)
