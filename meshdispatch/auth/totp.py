"""RFC 6238 TOTP (time-based one-time password) using only the stdlib.

HMAC-SHA1, 30-second steps, 6 digits, with a ``+-1`` step tolerance on
verification.  Secrets are base32 (RFC 4648) strings as commonly produced by
authenticator apps.
"""

from __future__ import annotations

import base64
import hmac
import struct
import time
from typing import Callable

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_DIGITS = 6
_DEFAULT_STEP = 30

DEFAULT_STEP = _DEFAULT_STEP
DEFAULT_DIGITS = _DIGITS


def _base32_decode(secret: str) -> bytes:
    """Decode an RFC 4648 base32 string, tolerating whitespace and padding."""
    if not isinstance(secret, str):
        raise ValueError("secret must be a base32 string")
    secret = secret.strip().upper().replace(" ", "").replace("-", "")
    if not secret:
        raise ValueError("empty base32 secret")
    # Normalise padding, then strip it so we can decode the bare data.
    secret = secret.rstrip("=")
    bits = 0
    value = 0
    out = bytearray()
    for char in secret:
        if char == "=":
            continue
        idx = _ALPHABET.find(char)
        if idx < 0:
            raise ValueError(f"invalid base32 character: {char!r}")
        value = (value << 5) | idx
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
    return bytes(out)


def totp_at(secret: str, t: int, *, step: int = _DEFAULT_STEP, digits: int = _DIGITS) -> str:
    """Compute the TOTP code for the given unix time ``t``."""
    key = _base32_decode(secret)
    counter = t // step
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, "sha1").digest()
    offset = digest[-1] & 0x0F
    binary = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    code = binary % (10**digits)
    return str(code).zfill(digits)


def totp_verify(
    secret: str,
    code: str,
    *,
    step: int = _DEFAULT_STEP,
    window: int = 1,
    digits: int = _DIGITS,
    now: int | None = None,
) -> bool:
    """Return ``True`` iff ``code`` matches within ``+-window`` steps.

    Each candidate comparison is constant-time.  ``now`` defaults to the
    current wall-clock time; pass an explicit value for deterministic tests.
    """
    if not isinstance(code, str) or not code.isdigit():
        return False
    t = int(time.time()) if now is None else int(now)
    try:
        for offset in range(-window, window + 1):
            candidate_t = t + offset * step
            if candidate_t < 0:
                continue
            expected = totp_at(secret, candidate_t, step=step, digits=digits)
            if hmac.compare_digest(expected, code.zfill(digits)):
                return True
    except ValueError:
        return False
    return False


def generate_totp_secret(length: int = 16) -> str:
    """Generate a fresh base32 TOTP secret (``length`` random bytes)."""
    import secrets

    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


__all__ = [
    "totp_at",
    "totp_verify",
    "generate_totp_secret",
    "DEFAULT_STEP",
    "DEFAULT_DIGITS",
]
