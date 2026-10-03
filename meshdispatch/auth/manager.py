"""The layered authentication manager.

``AuthManager`` orchestrates the five layers from DESIGN.md:

1. **Identity** -- SSH public-key signature (primary), account+TOTP, GitHub
   OAuth.  Only the enabled, explicitly-successful method yields an identity;
   everything else is a deny.
2. **Device** -- first login claims a device; later devices need confirmation.
3. **Session** -- short-lived, signed, revocable cookies.
4. **Audit** -- every login/approval/revocation appended to a JSONL log.
5. **Optional LAN MAC whitelist** -- LAN-only; public traffic skips it.

``authenticate`` never raises: any failure collapses to ``None`` (default
deny).
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .config import AuthConfig, ENV_COOKIE_SIGNING_KEY
from .crypto import verify_password
from .device import (
    DeviceRecord,
    device_key_matches,
    generate_device_id,
    generate_device_key,
    hash_device_key,
)
from .github import GithubOAuth, generate_state
from .mac import check_mac_whitelist, is_private_ip
from .session import (
    cookie_is_fresh,
    generate_session_id,
    sign_cookie,
    verify_cookie,
)
from .ssh import generate_nonce, nonce_is_fresh, verify_signature_for_keys
from .state import StateStore
from .totp import totp_verify


@dataclass
class Identity:
    """An authenticated identity (frozen public contract)."""

    principal: str
    method: str  # 'ssh' | 'password' | 'github'
    device_id: str | None  # claimed device id; None for a brand-new device


def _utcnow_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _require_principal(principal: str) -> str:
    if not isinstance(principal, str) or not principal.strip():
        raise ValueError("principal is required")
    return principal.strip()


class AuthManager:
    def __init__(
        self,
        config: AuthConfig | dict | None = None,
        *,
        state_dir: str | None = None,
        now: Callable[[], float] | None = None,
        github_exchange: Callable[[str], dict] | None = None,
        github_user: Callable[[str], dict] | None = None,
        arp_reader: Callable[[], str] | None = None,
    ) -> None:
        if config is None:
            config = AuthConfig()
        elif isinstance(config, dict):
            config = AuthConfig(**config)
        self.config: AuthConfig = config
        self._now = now or time.time
        self.store = StateStore(state_dir)
        self._nonces: dict[str, dict[str, Any]] = {}
        self._oauth_states: dict[str, dict[str, Any]] = {}
        self._pending_device_keys: dict[str, str] = {}
        self._totp_secrets: dict[str, str] = {}
        self._arp_reader = arp_reader

        # Cookie signing key: config > env > ephemeral random (sessions do not
        # survive a restart when the ephemeral fallback is used).
        key = self.config.cookie_signing_key or os.environ.get(ENV_COOKIE_SIGNING_KEY)
        self._signing_key = key or secrets.token_hex(32)

        self._github: GithubOAuth | None = None
        if self.config.github_enabled:
            cid = self.config.github_client_id
            secret = self.config.github_client_secret
            redirect = self.config.github_redirect_uri
            if cid and secret and redirect:
                self._github = GithubOAuth(
                    cid,
                    secret,
                    redirect,
                    exchange=github_exchange,
                    user=github_user,
                )

        # Seed identity credentials from operator config.
        for principal, pc in self.config.principals.items():
            rec = self.store.get_credentials(principal) or {}
            if pc.password_hash:
                rec["password_hash"] = pc.password_hash
            if pc.authorized_keys:
                rec["authorized_keys"] = list(pc.authorized_keys)
            self.store.set_credentials(principal, rec)
            if pc.totp_secret:
                self._totp_secrets[principal] = pc.totp_secret

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit(
        self,
        event: str,
        *,
        principal: str | None = None,
        method: str | None = None,
        result: str | None = None,
        ip: str | None = None,
        device_id: str | None = None,
        **details: Any,
    ) -> None:
        if self.config.audit_enabled:
            self.store.audit.record(
                event,
                principal=principal,
                method=method,
                result=result,
                ip=ip,
                device_id=device_id,
                **details,
            )

    # ------------------------------------------------------------------
    # Request plumbing
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_headers(request: Any) -> dict[str, Any]:
        h = getattr(request, "headers", None)
        if not isinstance(h, dict):
            return {}
        return {k.lower(): v for k, v in h.items() if isinstance(k, str)}

    @staticmethod
    def _extract_cookies(request: Any, headers: dict[str, Any]) -> dict[str, Any]:
        c = getattr(request, "cookies", None)
        if isinstance(c, dict) and c:
            return c
        cookie_header = headers.get("cookie")
        if not cookie_header:
            return {}
        out: dict[str, Any] = {}
        for part in str(cookie_header).split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                out[k.strip()] = v.strip()
        return out

    # ------------------------------------------------------------------
    # Public entry point (frozen contract)
    # ------------------------------------------------------------------

    def authenticate(self, request: Any) -> Identity | None:
        """Return an :class:`Identity` or ``None`` (never raises)."""
        try:
            return self._authenticate(request)
        except Exception:
            return None

    def _authenticate(self, request: Any) -> Identity | None:
        headers = self._normalize_headers(request)
        cookies = self._extract_cookies(request, headers)
        ip = getattr(request, "client_ip", None)
        path = getattr(request, "path", "") or ""
        query = getattr(request, "query", None) or {}

        # 1. Session resume (already-authenticated cookie).
        sid = self._cookie_to_session_id(cookies)
        if sid is not None:
            ident = self._session_identity(sid)
            if ident is not None:
                return ident

        # 2. Identity.
        principal, method = self._identify(headers, path, query, ip)
        if principal is None:
            self._audit("login", result="failure", ip=ip, method=None)
            return None

        # 3. Device layer.
        device_id = self._device_layer(principal, headers, ip)
        if device_id is False:
            return None  # already audited

        # 4. Optional LAN MAC whitelist (public traffic skips this).
        if self.config.mac_whitelist_enabled and self.config.mac_whitelist:
            if not check_mac_whitelist(
                principal,
                ip or "",
                self.config.mac_whitelist,
                arp_reader=self._arp_reader,
            ):
                self._audit(
                    "login",
                    principal=principal,
                    method=method,
                    result="failure",
                    ip=ip,
                    device_id=device_id,
                    reason="mac_mismatch",
                )
                return None

        identity = Identity(principal=principal, method=method, device_id=device_id)
        self._audit(
            "login",
            principal=principal,
            method=method,
            result="success",
            ip=ip,
            device_id=device_id,
        )
        return identity

    # ------------------------------------------------------------------
    # Identity layer
    # ------------------------------------------------------------------

    def _identify(
        self, headers: dict[str, Any], path: str, query: Any, ip: str | None
    ) -> tuple[str | None, str | None]:
        if self.config.ssh_enabled:
            principal = self._identify_ssh(headers)
            if principal:
                return principal, "ssh"
        if self.config.password_enabled:
            principal = self._identify_password(headers, ip)
            if principal:
                return principal, "password"
        if self.config.github_enabled:
            principal = self._identify_github(query)
            if principal:
                return principal, "github"
        return None, None

    def _identify_ssh(self, headers: dict[str, Any]) -> str | None:
        principal = headers.get("x-mesh-principal")
        nonce = headers.get("x-mesh-nonce")
        sig = headers.get("x-mesh-signature")
        if not principal or not nonce or not sig:
            return None
        rec = self._nonces.get(nonce)
        if not nonce_is_fresh(nonce, rec, self._now()):
            return None
        creds = self.store.get_credentials(principal)
        keys = (creds or {}).get("authorized_keys") or []
        if not keys:
            return None
        if not verify_signature_for_keys(nonce, sig, keys, principal=principal):
            return None
        rec["used"] = True  # single-use: consume
        return principal

    def _identify_password(self, headers: dict[str, Any], ip: str | None) -> str | None:
        auth = headers.get("authorization")
        if not isinstance(auth, str) or not auth.lower().startswith("basic "):
            return None
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
            principal, _, password = decoded.partition(":")
        except (ValueError, UnicodeDecodeError):
            return None
        if not principal or not password:
            return None
        creds = self.store.get_credentials(principal)
        stored_hash = (creds or {}).get("password_hash")
        if not stored_hash or not verify_password(password, stored_hash):
            return None

        public = not is_private_ip(ip or "")
        totp_secret = self._totp_secrets.get(principal)
        code = headers.get("x-mesh-totp")
        if self.config.public_network_totp_required and public:
            # Public access forces TOTP.
            if not totp_secret or not totp_verify(
                totp_secret, code, now=int(self._now())
            ):
                return None
        elif totp_secret and code:
            # Optional TOTP on the LAN: if configured and supplied, verify it.
            if not totp_verify(totp_secret, code, now=int(self._now())):
                return None
        return principal

    def _identify_github(self, query: Any) -> str | None:
        if self._github is None or not isinstance(query, dict):
            return None
        code = query.get("code")
        state = query.get("state")
        if not code or not state:
            return None
        rec = self._oauth_states.get(state)
        if not rec or rec.get("used"):
            return None
        if self._now() >= rec.get("expires_at", 0.0):
            return None
        rec["used"] = True
        try:
            return self._github.principal_for_code(code)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Device layer
    # ------------------------------------------------------------------

    def _create_device(
        self, principal: str, device_name: str | None, auto_confirm: bool
    ) -> tuple[str, str]:
        device_id = generate_device_id()
        key = generate_device_key()
        record = DeviceRecord(
            device_id=device_id,
            principal=principal,
            key_hash=hash_device_key(key),
            device_name=device_name,
            confirmed=auto_confirm,
            created_at=_utcnow_iso(),
            confirmed_at=_utcnow_iso() if auto_confirm else None,
        )
        self.store.set_device(device_id, record.to_dict())
        return device_id, key

    def _device_layer(
        self, principal: str, headers: dict[str, Any], ip: str | None
    ) -> str | bool | None:
        if not self.config.device_enforcement:
            return None
        device_id = headers.get("x-mesh-device-id")
        device_key = headers.get("x-mesh-device-key")
        if device_id and device_key:
            rec = self.store.get_device(device_id)
            if rec is None:
                self._audit(
                    "login", principal=principal, result="failure", ip=ip,
                    device_id=device_id, reason="unknown_device",
                )
                return False
            if rec.get("principal") != principal:
                self._audit(
                    "login", principal=principal, result="failure", ip=ip,
                    device_id=device_id, reason="device_principal_mismatch",
                )
                return False
            if not device_key_matches(device_key, rec.get("key_hash")):
                self._audit(
                    "login", principal=principal, result="failure", ip=ip,
                    device_id=device_id, reason="bad_device_key",
                )
                return False
            if not rec.get("confirmed"):
                self._audit(
                    "login", principal=principal, result="failure", ip=ip,
                    device_id=device_id, reason="device_unconfirmed",
                )
                return False
            return device_id

        # No device headers: first login claims a device; a later login from a
        # fresh (credential-less) device must go through confirmation.
        confirmed = [d for d in self.store.list_devices(principal) if d.get("confirmed")]
        if not confirmed:
            new_id, key = self._create_device(principal, None, auto_confirm=True)
            self._pending_device_keys[new_id] = key
            self._audit(
                "device_claimed", principal=principal, result="success",
                ip=ip, device_id=new_id,
            )
            return new_id
        self._audit(
            "login", principal=principal, result="failure", ip=ip,
            reason="new_device_requires_confirmation",
        )
        return False

    # ------------------------------------------------------------------
    # Device management (public)
    # ------------------------------------------------------------------

    def enroll_device(self, principal: str, *, device_name: str | None = None) -> str:
        """Enroll a device for ``principal``; return the new device id.

        The first device is auto-confirmed; any later device is created
        unconfirmed (pending confirmation).  The one-time persistent key is
        retrievable via :meth:`get_device_key` for handover to the client.
        """
        principal = _require_principal(principal)
        has_confirmed = any(
            d.get("confirmed") for d in self.store.list_devices(principal)
        )
        device_id, key = self._create_device(
            principal, device_name=device_name, auto_confirm=not has_confirmed
        )
        self._pending_device_keys[device_id] = key
        self._audit(
            "device_enroll",
            principal=principal,
            result="success",
            device_id=device_id,
            details={"confirmed": not has_confirmed},
        )
        return device_id

    def get_device_key(self, device_id: str) -> str | None:
        """Return the one-time persistent key for a just-enrolled device."""
        return self._pending_device_keys.get(device_id)

    def confirm_device(
        self,
        device_id: str,
        *,
        approver_principal: str | None = None,
        approver_device_id: str | None = None,
    ) -> bool:
        """Confirm a pending device (manual or by an already-claimed device)."""
        rec = self.store.get_device(device_id)
        if rec is None:
            return False
        if approver_device_id is not None:
            approver = self.store.get_device(approver_device_id)
            if (
                approver is None
                or not approver.get("confirmed")
                or approver.get("principal") != rec.get("principal")
            ):
                return False
        if approver_principal is not None and approver_principal != rec.get("principal"):
            return False
        rec["confirmed"] = True
        rec["confirmed_at"] = _utcnow_iso()
        rec["confirmed_by"] = approver_device_id or approver_principal or "manual"
        self.store.set_device(device_id, rec)
        self._audit(
            "device_approve",
            principal=rec["principal"],
            result="success",
            device_id=device_id,
            details={"by": rec["confirmed_by"]},
        )
        return True

    # ------------------------------------------------------------------
    # Nonce / OAuth state
    # ------------------------------------------------------------------

    def issue_nonce(self, principal: str, *, ttl: int | None = None) -> str:
        """Issue a one-time challenge nonce for the SSH-signature flow."""
        principal = _require_principal(principal)
        nonce = generate_nonce()
        life = self.config.nonce_ttl if ttl is None else ttl
        self._nonces[nonce] = {
            "principal": principal,
            "expires_at": self._now() + life,
            "used": False,
        }
        return nonce

    def issue_oauth_state(self) -> str:
        """Issue a single-use CSRF ``state`` for a GitHub OAuth attempt."""
        state = generate_state()
        self._oauth_states[state] = {"expires_at": self._now() + 300, "used": False}
        return state

    # ------------------------------------------------------------------
    # Session layer
    # ------------------------------------------------------------------

    def issue_session(
        self,
        principal: str,
        method: str,
        device_id: str | None = None,
        ip: str | None = None,
    ) -> str:
        """Create a short-lived session and return its signed cookie value."""
        sid = generate_session_id()
        now = self._now()
        record = {
            "sid": sid,
            "principal": principal,
            "method": method,
            "device_id": device_id,
            "ip": ip,
            "expires_at": now + self.config.session_ttl,
            "issued_at": now,
        }
        self.store.set_session(sid, record)
        return sign_cookie(record, self._signing_key)

    def _cookie_to_session_id(self, cookies: dict[str, Any]) -> str | None:
        value = cookies.get(self.config.cookie_name)
        if not isinstance(value, str):
            return None
        payload = verify_cookie(value, self._signing_key)
        if payload is None or not cookie_is_fresh(payload, self._now()):
            return None
        sid = payload.get("sid")
        return sid if isinstance(sid, str) else None

    def _session_identity(self, sid: str) -> Identity | None:
        rec = self.store.get_session(sid)
        if rec is None:
            return None
        if self._now() >= rec.get("expires_at", 0.0):
            return None
        return Identity(
            principal=rec["principal"],
            method=rec.get("method", "ssh"),
            device_id=rec.get("device_id"),
        )

    def revoke_session(self, session_id: str) -> bool:
        rec = self.store.get_session(session_id)
        if rec is None:
            return False
        principal = rec.get("principal")
        self.store.delete_session(session_id)
        self._audit(
            "session_revoke", principal=principal, result="success",
            details={"sid": session_id},
        )
        return True

    def revoke_all_sessions(self, principal: str) -> int:
        """Revoke every session for ``principal``; return the number revoked."""
        sids = [sid for sid, _ in self.store.list_sessions(principal)]
        for sid in sids:
            self.store.delete_session(sid)
        if sids:
            self._audit(
                "session_revoke_all",
                principal=principal,
                result="success",
                details={"count": len(sids)},
            )
        return len(sids)

    # ------------------------------------------------------------------
    # Credential management (public)
    # ------------------------------------------------------------------

    def set_password(self, principal: str, password: str) -> None:
        """Set a principal's password (hashed with scrypt; plaintext discarded)."""
        from .crypto import hash_password

        principal = _require_principal(principal)
        rec = self.store.get_credentials(principal) or {}
        rec["password_hash"] = hash_password(password)
        self.store.set_credentials(principal, rec)

    def add_authorized_key(self, principal: str, public_key_line: str) -> None:
        principal = _require_principal(principal)
        rec = self.store.get_credentials(principal) or {}
        keys = list(rec.get("authorized_keys") or [])
        if public_key_line not in keys:
            keys.append(public_key_line)
        rec["authorized_keys"] = keys
        self.store.set_credentials(principal, rec)

    def set_totp_secret(self, principal: str, secret: str) -> None:
        """Register a principal's TOTP secret (kept in memory only)."""
        self._totp_secrets[_require_principal(principal)] = secret


__all__ = ["AuthManager", "Identity"]
