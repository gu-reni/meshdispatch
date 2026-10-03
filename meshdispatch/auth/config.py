"""Configuration for the layered authentication module.

All secrets (GitHub client secret, cookie signing key, TOTP seeds) are read
from ``AuthConfig`` or the process environment -- never hard-coded and never
written back to the on-disk state store.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Environment variable names used when a secret is not supplied explicitly.
ENV_GITHUB_CLIENT_ID = "MESHDISPATCH_GITHUB_CLIENT_ID"
ENV_GITHUB_CLIENT_SECRET = "MESHDISPATCH_GITHUB_CLIENT_SECRET"
ENV_GITHUB_REDIRECT_URI = "MESHDISPATCH_GITHUB_REDIRECT_URI"
ENV_COOKIE_SIGNING_KEY = "MESHDISPATCH_COOKIE_SIGNING_KEY"


@dataclass
class PrincipalConfig:
    """Per-principal identity credentials.

    ``password_hash`` is a salted ``scrypt`` digest (see
    :func:`meshdispatch.auth.crypto.hash_password`); the plaintext password is
    never stored.  ``totp_secret`` is a base32 shared secret and is *never*
    persisted to disk -- it is held in memory only and seeded from config or
    the environment.  ``authorized_keys`` holds OpenSSH public keys.
    """

    password_hash: str | None = None
    authorized_keys: list[str] = field(default_factory=list)
    totp_secret: str | None = None


@dataclass
class AuthConfig:
    """Feature flags and credentials for every authentication layer.

    Every layer defaults to *off or deny* except the SSH-primary identity the
    owner has selected; the manager additionally requires an explicit success
    before it ever returns an identity.
    """

    # Identity layers.
    ssh_enabled: bool = True
    password_enabled: bool = True
    github_enabled: bool = False

    # Identity credentials, seeded from operator config (not from disk).
    principals: dict[str, PrincipalConfig] = field(default_factory=dict)

    # GitHub OAuth (authorization-code flow).
    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_redirect_uri: str | None = None

    # Session layer.
    session_ttl: int = 3600
    cookie_name: str = "meshdispatch_session"
    cookie_signing_key: str | None = None

    # SSH-signature challenge lifetime, in seconds.
    nonce_ttl: int = 120

    # Device layer.
    device_enforcement: bool = True

    # Optional LAN MAC whitelist (LAN-only; public traffic skips it).
    mac_whitelist_enabled: bool = False
    mac_whitelist: dict[str, list[str]] = field(default_factory=dict)

    # Require a valid TOTP for password logins arriving from a public address.
    public_network_totp_required: bool = True

    # Audit layer.
    audit_enabled: bool = True

    @classmethod
    def from_env(cls, **overrides: Any) -> "AuthConfig":
        """Build a config, falling back to environment variables for secrets."""
        data: dict[str, Any] = dict(overrides)
        data.setdefault(
            "github_client_id", os.environ.get(ENV_GITHUB_CLIENT_ID) or None
        )
        data.setdefault(
            "github_client_secret", os.environ.get(ENV_GITHUB_CLIENT_SECRET) or None
        )
        data.setdefault(
            "github_redirect_uri", os.environ.get(ENV_GITHUB_REDIRECT_URI) or None
        )
        data.setdefault(
            "cookie_signing_key", os.environ.get(ENV_COOKIE_SIGNING_KEY) or None
        )
        return cls(**data)


__all__ = [
    "AuthConfig",
    "PrincipalConfig",
    "ENV_GITHUB_CLIENT_ID",
    "ENV_GITHUB_CLIENT_SECRET",
    "ENV_GITHUB_REDIRECT_URI",
    "ENV_COOKIE_SIGNING_KEY",
]
