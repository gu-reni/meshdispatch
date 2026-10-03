"""Signed session cookies.

A cookie is ``base64url(payload_json) . base64url(hmac_sha256(payload))``.
The signature makes tampering detectable without any server-side lookup; the
server-side session store (managed by :class:`AuthManager`) adds expiry and
the ability to revoke "everywhere".

``payload_json`` contains ``sid``, ``principal``, ``method``, ``device_id`` and
``expires_at`` (unix seconds).  Verification recomputes the MAC and compares it
in constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time


def generate_session_id() -> str:
    return secrets.token_urlsafe(32)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _mac(signing_key: str, payload: bytes) -> bytes:
    return hmac.new(signing_key.encode("utf-8"), payload, hashlib.sha256).digest()


def sign_cookie(payload: dict, signing_key: str) -> str:
    """Return ``payload.signature`` where signature is HMAC-SHA256."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(raw) + "." + _b64url_encode(_mac(signing_key, raw))


def verify_cookie(cookie: str, signing_key: str) -> dict | None:
    """Verify the cookie's signature and return its payload, or ``None``.

    ``None`` is returned for malformed input, a bad split, a tampered payload,
    or a signature mismatch.  Expiry is checked by the caller so that cookie
    issuance and the session store stay separable.
    """
    if not isinstance(cookie, str) or not signing_key:
        return None
    if "." not in cookie:
        return None
    payload_b64, sig_b64 = cookie.split(".", 1)
    try:
        payload = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(_mac(signing_key, payload), sig):
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def cookie_is_fresh(payload: dict, now: float | None = None) -> bool:
    """True iff the cookie's ``expires_at`` is still in the future."""
    expires_at = payload.get("expires_at")
    if not isinstance(expires_at, (int, float)):
        return False
    return (now if now is not None else time.time()) < expires_at


__all__ = [
    "generate_session_id",
    "sign_cookie",
    "verify_cookie",
    "cookie_is_fresh",
]
