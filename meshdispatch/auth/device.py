"""Device layer: enrollment, persistent keys, and confirmation.

A device record holds a *hash* of the client's persistent key -- the raw key
is never written to disk.  The raw key is generated at enrollment and handed
back exactly once; afterwards only its SHA-256 fingerprint is verifiable.

Confirmation policy (per DESIGN.md): the first device a principal enrolls is
auto-confirmed; any later device is created *unconfirmed* and must be
confirmed by an already-claimed device or manually.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field, asdict
from typing import Any


def generate_device_id() -> str:
    return secrets.token_hex(16)


def generate_device_key() -> str:
    return secrets.token_urlsafe(32)


def hash_device_key(key: str) -> str:
    """SHA-256 hex digest of a device key; what actually gets persisted."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def device_key_matches(key: str, key_hash: str) -> bool:
    """Constant-time check of a presented device key against its stored hash."""
    if not isinstance(key, str) or not isinstance(key_hash, str):
        return False
    return hmac.compare_digest(hash_device_key(key), key_hash)


@dataclass
class DeviceRecord:
    device_id: str
    principal: str
    key_hash: str
    device_name: str | None = None
    confirmed: bool = False
    created_at: str | None = None
    confirmed_at: str | None = None
    confirmed_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceRecord":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


__all__ = [
    "DeviceRecord",
    "generate_device_id",
    "generate_device_key",
    "hash_device_key",
    "device_key_matches",
]
