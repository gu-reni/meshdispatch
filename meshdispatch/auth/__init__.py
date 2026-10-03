"""Layered authentication for meshdispatch (phase 3).

Five layers, all shipped in the open-source build:

* **Identity** -- SSH public-key signature (primary), account+TOTP, GitHub OAuth
* **Device**   -- first login claims a device; later devices need confirmation
* **Session**  -- short-lived signed cookie, revocable, "sign out everywhere"
* **Audit**    -- append-only JSONL of logins/approvals/revocations
* **MAC**      -- optional LAN-only whitelist (public traffic skips it)

The public, frozen interface is:

    Identity                                # dataclass
    authenticate(request) -> Identity | None
    enroll_device(...) -> str
    revoke_all_sessions(principal) -> int

``authenticate`` operates on a lightweight request object exposing
``.headers`` / ``.cookies`` / ``.client_ip`` / ``.path`` / ``.query`` and
never raises: an unauthenticated request is a ``None``.

Configuration and the full manager (for tests and the web layer) are available
through :class:`AuthManager` and :func:`configure`.
"""

from __future__ import annotations

from typing import Any

from .config import AuthConfig, PrincipalConfig
from .crypto import (
    build_ssh_signature,
    generate_rsa_keypair,
    hash_password,
    parse_ssh_public_key,
    serialize_ssh_public_key,
    verify_password,
)
from .device import DeviceRecord, generate_device_id, generate_device_key
from .manager import AuthManager, Identity
from .totp import totp_at, totp_verify

# Module-level manager backing the frozen module functions.  Configure it with
# :func:`configure` (or construct an :class:`AuthManager` directly and call its
# methods, which is what the tests do).
_manager: AuthManager | None = None


def configure(config: AuthConfig | dict | None = None, **kwargs: Any) -> AuthManager:
    """Configure the module-level manager and return it."""
    global _manager
    _manager = AuthManager(config, **kwargs)
    return _manager


def authenticate(request: Any) -> Identity | None:
    """Authenticate a request (frozen interface).  Never raises."""
    if _manager is None:
        return None
    return _manager.authenticate(request)


def enroll_device(principal: str, **kwargs: Any) -> str:
    """Enroll a device for ``principal`` (frozen interface)."""
    if _manager is None:
        raise RuntimeError("auth is not configured; call meshdispatch.auth.configure() first")
    return _manager.enroll_device(principal, **kwargs)


def revoke_all_sessions(principal: str) -> int:
    """Revoke every session for ``principal`` (frozen interface)."""
    if _manager is None:
        return 0
    return _manager.revoke_all_sessions(principal)


__all__ = [
    "Identity",
    "authenticate",
    "enroll_device",
    "revoke_all_sessions",
    "configure",
    "AuthManager",
    "AuthConfig",
    "PrincipalConfig",
    "DeviceRecord",
    "generate_device_id",
    "generate_device_key",
    "generate_rsa_keypair",
    "serialize_ssh_public_key",
    "parse_ssh_public_key",
    "build_ssh_signature",
    "hash_password",
    "verify_password",
    "totp_at",
    "totp_verify",
]
