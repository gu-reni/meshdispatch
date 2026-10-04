"""Standard-library HTTP + SSE server exposing the meshdispatch Store as JSON.

No third-party dependencies: transport is built on :mod:`http.server` and
:mod:`socketserver`.  Authentication is delegated to
:func:`meshdispatch.auth.authenticate`; every route except the login/bootstrap
route is gated behind it and returns HTTP 401 when it yields ``None``.
"""

from __future__ import annotations

import base64
import json
import os
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

from ..control.dispatch import UnknownAgent, dispatch as dispatch_task
from ..control.ingest import apply_ingest
from ..control.pairing import (
    DuplicatePublicKey,
    PairingConflict,
    PairingExpired,
    PairingNotFound,
    approve_pairing,
    create_pairing,
    get_pairing,
    list_pairings,
    validate_public_key,
    reject_pairing,
)
from ..store import (
    ApprovalConflict,
    ApprovalExpired,
    ApprovalNotFound,
    Store,
)
from .sse import ChangeTracker

if TYPE_CHECKING:
    from meshdispatch.auth import Identity

try:
    from meshdispatch.auth import authenticate as _auth_authenticate
    from meshdispatch.auth import get_manager as _auth_get_manager
except ImportError:  # pragma: no cover - auth lands later in phase 3
    _auth_authenticate = None
    _auth_get_manager = None


#: Path(s) exempt from authentication: the login API and the login *page*.
#: Nothing else is exempt.  ``/index.html`` and ``/static/app.js`` stay behind
#: the auth gate; only the stylesheet the login page needs is added below.
PUBLIC_PATHS = frozenset({"/api/login", "/login"})

#: Static assets that may be fetched without a session.  This is the login
#: page's own assets and nothing more: the shared stylesheet, the login script,
#: and the shared string table (none carries data or secrets).  ``/index.html``
#: and ``app.js`` remain behind the gate, so the dashboard itself is never
#: reachable without a session.
PUBLIC_STATIC_PATHS = frozenset(
    {"/static/style.css", "/static/login.js", "/static/i18n.js"}
)

#: Fallback session cookie name when no auth manager config is available.
DEFAULT_COOKIE_NAME = "meshdispatch_session"

#: Per-source-IP rate limit for the unauthenticated pairing bootstrap: a small
#: window so a stranger cannot flood the owner's pending list.
PAIRING_RATE_LIMIT = 5
PAIRING_RATE_WINDOW_SECONDS = 60

#: Poll cadence for SSE change detection.  Well under the 3-second push budget.
_SSE_POLL_SECONDS = 0.5

_SSE_HEADERS = {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}

#: Directory holding the single-page dashboard assets.  Served read-only.
_STATIC_DIR = Path(__file__).resolve().parent / "static"

#: Content types for the static assets we ship (no extension guessing needed
#: beyond these, and no third-party content is ever served).
_STATIC_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


class Request:
    """Lightweight request view passed to :func:`authenticate`.

    Mirrors the frozen auth contract: ``.headers`` (dict), ``.cookies`` (dict),
    ``.client_ip`` (str), ``.path`` (str), and ``.query`` (dict).
    """

    __slots__ = ("headers", "cookies", "client_ip", "path", "query")

    def __init__(
        self,
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
        client_ip: str,
        path: str,
        query: dict[str, str],
    ) -> None:
        self.headers = headers
        self.cookies = cookies
        self.client_ip = client_ip
        self.path = path
        self.query = query


Authenticator = Callable[[Request], "Identity | None"]


def _locked_down(request: Request) -> "Identity | None":
    """Deny every request; used before the real auth module exists."""
    return None


_DEFAULT_AUTHENTICATOR: Authenticator = (
    _auth_authenticate if _auth_authenticate is not None else _locked_down
)


def _deny_totp(principal: str, code: str) -> bool:
    """Default TOTP verifier: deny (no secret configured)."""
    del principal, code
    return False


def _deny_enroll(principal: str, device_name: str) -> str:
    """Default device enroller: fail closed (no auth manager wired)."""
    del principal, device_name
    raise RuntimeError("device enrolment is not configured")


def _empty_devices(principal: str | None = None) -> list[Any]:
    """Default device lister: no devices visible (no auth manager wired)."""
    del principal
    return []


def _deny_revoke(device_id: str) -> bool:
    """Default device revoker: fail closed."""
    del device_id
    return False


def _noop_audit(*args: Any, **kwargs: Any) -> None:
    """Default audit sink: discard."""
    del args, kwargs
    return None


def _build_request(
    headers: Mapping[str, str],
    client_ip: str,
    raw_path: str,
) -> Request:
    lowered = {key.lower(): value for key, value in headers.items()}
    cookies: dict[str, str] = {}
    cookie_header = lowered.get("cookie")
    if cookie_header:
        jar = SimpleCookie()
        jar.load(cookie_header)
        cookies = {key: morsel.value for key, morsel in jar.items()}
    split = urlsplit(raw_path)
    query = {
        key: (values[0] if values else "")
        for key, values in parse_qs(split.query, keep_blank_values=True).items()
    }
    return Request(
        headers=lowered,
        cookies=cookies,
        client_ip=client_ip,
        path=split.path,
        query=query,
    )


def _compute_stats(store: Store) -> dict[str, dict[str, int]]:
    conn = store.connect()
    try:
        by_origin = {
            row["origin"]: row["count"]
            for row in conn.execute(
                "SELECT origin, COUNT(*) AS count FROM tasks GROUP BY origin"
            )
        }
        by_status = {
            row["status"]: row["count"]
            for row in conn.execute(
                "SELECT status, COUNT(*) AS count FROM tasks GROUP BY status"
            )
        }
    finally:
        conn.close()
    return {"by_origin": by_origin, "by_status": by_status}


def _resolve_auth_manager(authenticator: Authenticator | None) -> Any | None:
    """Recover the :class:`AuthManager` behind ``authenticator``, if any.

    The login route needs the manager's session/nonce helpers in addition to
    the plain ``authenticate`` callable.  We accept it when the caller passes a
    manager instance directly, a bound ``manager.authenticate`` method, or (via
    :func:`meshdispatch.auth.get_manager`) the module-level manager that backs
    the frozen ``meshdispatch.auth.authenticate`` function.  Anything else means
    login is simply unconfigured and fails closed.
    """
    if authenticator is None:
        return None
    candidate = getattr(authenticator, "__self__", None)
    if candidate is not None and hasattr(candidate, "issue_session"):
        return candidate
    if hasattr(authenticator, "issue_session") and hasattr(
        authenticator, "authenticate"
    ):
        return authenticator
    if authenticator is _auth_authenticate and _auth_get_manager is not None:
        return _auth_get_manager()
    return None


def create_app(
    store: Store,
    authenticator: Authenticator | None = None,
    totp_verifier: Callable[[str, str], bool] | None = None,
    audit: Callable[..., Any] | None = None,
    enroll_device: Callable[[str, str], str] | None = None,
    list_devices: Callable[[], list[Any]] | None = None,
    revoke_device: Callable[[str], bool] | None = None,
    auth_manager: Any | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to ``store`` and ``authenticator``.

    ``totp_verifier`` verifies a TOTP code for the authenticated principal (used
    for high-risk approvals and every pairing decision; defaults to deny).
    ``enroll_device`` / ``list_devices`` / ``revoke_device`` wire the pairing
    approval to the auth layer's device store (defaults fail closed).  ``audit``
    receives approval audit events as
    ``audit(event, *, principal, approval_id, decision, ip)``.

    ``auth_manager`` provides the session/nonce helpers used by ``POST
    /api/login`` and ``POST /api/logout``.  It is optional: when omitted the
    manager is recovered from ``authenticator`` (a bound ``manager.authenticate``
    method or the module-level manager behind ``meshdispatch.auth.authenticate``)
    and, if it cannot be, login returns 501 rather than weakening the gate.
    """
    managed: Any | None = auth_manager or _resolve_auth_manager(authenticator)
    if authenticator is not None:
        auth: Authenticator = authenticator
    elif managed is not None:
        auth = managed.authenticate
    else:
        auth = _DEFAULT_AUTHENTICATOR
    totp_check: Callable[[str, str], bool] = (
        totp_verifier if totp_verifier is not None else _deny_totp
    )
    audit_hook: Callable[..., Any] = audit if audit is not None else _noop_audit
    enroll: Callable[[str, str], str] = (
        enroll_device if enroll_device is not None else _deny_enroll
    )
    list_devices_fn: Callable[[], list[Any]] = (
        list_devices if list_devices is not None else _empty_devices
    )
    revoke_device_fn: Callable[[str], bool] = (
        revoke_device if revoke_device is not None else _deny_revoke
    )

    #: In-memory plaintext pairing codes (never persisted) and rate-limit state.
    pairing_codes: dict[str, str] = {}
    pairing_attempts: dict[str, list[float]] = {}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "meshdispatch/0.1"

        def do_GET(self) -> None:
            self._dispatch()

        def do_HEAD(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch_post()

        # -- routing -----------------------------------------------------

        def _authorize(self, request: Request) -> "Identity | None":
            """Run the request through auth; send a response on failure.

            Returns the authenticated :class:`Identity` (or ``None`` once a 401
            response has already been written).  Public paths are dispatched by
            the caller before this is reached, never here.
            """
            identity = auth(request)
            if identity is None:
                self.close_connection = True
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "authentication required"},
                    headers={"WWW-Authenticate": 'Bearer realm="meshdispatch"'},
                )
                return None
            return identity

        def _dispatch(self) -> None:
            request = _build_request(
                self.headers,
                self.client_address[0],
                self.path,
            )
            # Public documents: the login page and the shared stylesheet it
            # needs.  Served before the gate; nothing else is reachable here.
            if request.path == "/login":
                self._serve_static("login.html")
                return
            if request.path in PUBLIC_STATIC_PATHS:
                self._serve_static(request.path[len("/static/") :])
                return
            if self._authorize(request) is None:
                return

            if request.path == "/api/tasks":
                self._handle_task_list(request)
            elif request.path.startswith("/api/tasks/"):
                self._handle_task_detail(request)
            elif request.path == "/api/agents":
                self._handle_agent_list()
            elif request.path == "/api/approvals":
                self._handle_approval_list(request)
            elif request.path.startswith("/api/approvals/"):
                self._handle_approval_detail(request)
            elif request.path == "/api/pairings":
                self._handle_pairing_list()
            elif request.path == "/api/devices":
                self._handle_device_list()
            elif request.path == "/api/stats":
                self._handle_stats()
            elif request.path == "/api/stream":
                self._handle_stream()
            elif request.path == "/":
                self._serve_static("index.html")
            elif request.path.startswith("/static/"):
                self._serve_static(request.path[len("/static/") :])
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _dispatch_post(self) -> None:
            request = _build_request(
                self.headers,
                self.client_address[0],
                self.path,
            )
            # /api/ingest is a deliberately separate authentication path: it
            # takes a per-agent bearer token (never a session cookie) and must
            # never be reachable with session credentials.
            if request.path == "/api/ingest":
                self._handle_ingest(request)
                return
            # /api/pairings (exact match only) is the unauthenticated bootstrap:
            # it can only ever create a *pending* request and never reads or
            # decides anything.  /api/pairings/<id>/decide is authenticated.
            if request.path == "/api/pairings":
                self._handle_pairing_create(request)
                return
            # The browser login exchange.  Reaching this route never grants a
            # session by itself: the credentials are verified through the same
            # AuthManager the rest of the server uses.
            if request.path == "/api/login":
                self._handle_login(request)
                return
            identity = self._authorize(request)
            if identity is None:
                return

            if request.path == "/api/logout":
                self._handle_logout(request)
            elif request.path == "/api/tasks":
                self._handle_task_create(request)
            elif request.path == "/api/approvals":
                self._handle_approval_create(request, identity)
            elif request.path.startswith("/api/approvals/") and request.path.endswith(
                "/decide"
            ):
                self._handle_approval_decide(request, identity)
            elif request.path.startswith("/api/pairings/") and request.path.endswith(
                "/decide"
            ):
                self._handle_pairing_decide(request, identity)
            elif request.path.startswith("/api/devices/") and request.path.endswith(
                "/revoke"
            ):
                self._handle_device_revoke(request, identity)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        # -- endpoints ---------------------------------------------------

        def _read_body(self) -> str:
            length = self.headers.get("Content-Length")
            if not length:
                return ""
            try:
                size = int(length)
            except ValueError:
                return ""
            if size <= 0:
                return ""
            return self.rfile.read(size).decode("utf-8", errors="replace")

        # -- login / logout ---------------------------------------------

        def _session_cookie_name(self) -> str:
            config = getattr(managed, "config", None)
            name = getattr(config, "cookie_name", None)
            return name if isinstance(name, str) and name else DEFAULT_COOKIE_NAME

        def _session_cookie(self, value: str, *, max_age: int | None = None) -> str:
            """Build a ``Set-Cookie`` value for the session.

            Always ``HttpOnly`` + ``SameSite=Lax`` + ``Path=/``.  ``Secure`` is
            only added when the auth config asks for it, so a plain-HTTP LAN
            deployment still works by default.
            """
            parts = [
                f"{self._session_cookie_name()}={value}",
                "Path=/",
                "HttpOnly",
                "SameSite=Lax",
            ]
            if max_age is not None:
                parts.append(f"Max-Age={max_age}")
            config = getattr(managed, "config", None)
            if bool(getattr(config, "cookie_secure", False)):
                parts.append("Secure")
            return "; ".join(parts)

        def _login_request(self, headers: dict[str, str], request: Request) -> Request:
            return Request(
                headers={k.lower(): v for k, v in headers.items()},
                cookies={},
                client_ip=request.client_ip,
                path="/api/login",
                query={},
            )

        def _finish_login(self, request: Request, identity: Any) -> None:
            """Issue a session for an authenticated identity, or deny."""
            if identity is None:
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "invalid credentials"},
                    headers={"WWW-Authenticate": 'Bearer realm="meshdispatch"'},
                )
                return
            try:
                cookie = managed.issue_session(
                    identity.principal,
                    identity.method,
                    identity.device_id,
                    request.client_ip,
                )
            except Exception:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "could not issue a session"},
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "principal": identity.principal,
                    "method": identity.method,
                },
                headers={"Set-Cookie": self._session_cookie(cookie)},
            )

        def _handle_login(self, request: Request) -> None:
            if managed is None:
                self._send_json(
                    HTTPStatus.NOT_IMPLEMENTED,
                    {"error": "login is not configured"},
                )
                return
            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"}
                )
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return
            method = data.get("method")
            if method == "ssh":
                self._login_ssh(request, data)
            elif method == "password":
                self._login_password(request, data)
            else:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "method must be 'ssh' or 'password'"},
                )

        def _login_ssh(self, request: Request, data: dict[str, Any]) -> None:
            """Challenge/response SSH login, delegated to the auth manager."""
            principal = data.get("principal")
            if not isinstance(principal, str) or not principal.strip():
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "principal is required"}
                )
                return
            principal = principal.strip()
            nonce = data.get("nonce")
            signature = data.get("signature")
            # No signature yet (or an explicit challenge request): hand back a
            # one-time nonce the client signs with ``ssh-keygen -Y sign``.
            if data.get("action") == "challenge" or not nonce or not signature:
                try:
                    from ..auth.ssh import SSH_SIGN_NAMESPACE
                except ImportError:  # pragma: no cover - auth always present
                    SSH_SIGN_NAMESPACE = "meshdispatch"
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "nonce": managed.issue_nonce(principal),
                        "namespace": SSH_SIGN_NAMESPACE,
                    },
                )
                return
            if not isinstance(nonce, str) or not isinstance(signature, str):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "nonce and signature must be strings"},
                )
                return
            verify_request = self._login_request(
                {
                    "X-Mesh-Principal": principal,
                    "X-Mesh-Nonce": nonce,
                    "X-Mesh-Signature": signature,
                },
                request,
            )
            # The manager verifies the signature (ssh-keygen -Y verify for
            # ed25519/ecdsa/rsa), applies the device layer and audits the result.
            self._finish_login(request, managed.authenticate(verify_request))

        def _login_password(self, request: Request, data: dict[str, Any]) -> None:
            """Password (+ optional/required TOTP) login via the auth manager."""
            principal = data.get("principal")
            password = data.get("password")
            if (
                not isinstance(principal, str)
                or not principal.strip()
                or not isinstance(password, str)
                or not password
            ):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "principal and password are required"},
                )
                return
            token = base64.b64encode(
                f"{principal.strip()}:{password}".encode("utf-8")
            ).decode("ascii")
            headers = {"Authorization": f"Basic {token}"}
            totp = data.get("totp")
            if isinstance(totp, str) and totp:
                headers["X-Mesh-TOTP"] = totp
            verify_request = self._login_request(headers, request)
            self._finish_login(request, managed.authenticate(verify_request))

        def _handle_logout(self, request: Request) -> None:
            """Revoke the caller's session and clear the cookie (authenticated)."""
            cookie = request.cookies.get(self._session_cookie_name(), "")
            if managed is not None and isinstance(cookie, str) and cookie:
                sid = managed.session_id_from_cookie(cookie)
                if sid:
                    managed.revoke_session(sid)
            self._send_json(
                HTTPStatus.OK,
                {"ok": True},
                headers={"Set-Cookie": self._session_cookie("", max_age=0)},
            )

        def _handle_ingest(self, request: Request) -> None:
            """Accept a push batch authenticated by a per-agent bearer token."""
            authorization = request.headers.get("authorization", "")
            token = None
            if isinstance(authorization, str) and authorization.lower().startswith(
                "bearer "
            ):
                token = authorization[7:].strip()
            if not token:
                self.close_connection = True
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "ingest token required"})
                return
            binding = store.verify_ingest_token(token)
            if binding is None:
                self.close_connection = True
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid ingest token"})
                return

            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return

            agent = data.get("agent")
            if not isinstance(agent, str) or not agent.strip():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "agent is required"})
                return
            if agent.strip() != binding["agent"]:
                self.close_connection = True
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "token is bound to a different agent"},
                )
                return

            try:
                result = apply_ingest(
                    store,
                    agent=binding["agent"],
                    tasks=data.get("tasks"),
                    runs=data.get("runs"),
                    messages=data.get("messages"),
                    events=data.get("events"),
                )
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, result)

        def _handle_agent_list(self) -> None:
            self._send_json(HTTPStatus.OK, store.list_agents())

        def _audit(
            self,
            event: str,
            *,
            principal: str | None = None,
            approval_id: str | None = None,
            decision: str | None = None,
            ip: str | None = None,
        ) -> None:
            audit_hook(
                event,
                principal=principal,
                approval_id=approval_id,
                decision=decision,
                ip=ip,
            )

        def _handle_approval_list(self, request: Request) -> None:
            status = request.query.get("status") or None
            try:
                approvals = store.list_approvals(status=status)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, approvals)

        def _handle_approval_detail(self, request: Request) -> None:
            approval_id = request.path[len("/api/approvals/") :]
            if not approval_id or "/" in approval_id:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            approval = store.get_approval(approval_id)
            if approval is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such approval"})
                return
            self._send_json(HTTPStatus.OK, approval)

        def _handle_approval_create(self, request: Request, identity: Any) -> None:
            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return
            try:
                approval = store.create_approval(
                    task_id=data.get("task_id"),
                    agent=data.get("agent"),
                    command=data.get("command"),
                    purpose=data.get("purpose"),
                    impact=data.get("impact"),
                    risk=data.get("risk", "low"),
                )
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._audit(
                "approval_create",
                principal=identity.principal,
                approval_id=approval["id"],
                ip=request.client_ip,
            )
            self._send_json(HTTPStatus.CREATED, approval)

        def _handle_approval_decide(self, request: Request, identity: Any) -> None:
            approval_id = request.path[len("/api/approvals/") : -len("/decide")]
            if not approval_id or "/" in approval_id:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return
            decision = data.get("decision")
            if decision == "approve":
                decision_v = "approved"
            elif decision == "reject":
                decision_v = "rejected"
            else:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "decision must be 'approve' or 'reject'"},
                )
                return

            approval = store.get_approval(approval_id)
            if approval is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such approval"})
                return

            if approval["status"] != "pending":
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": f"approval {approval_id} is already "
                        f"{approval['status']}"
                    },
                )
                return

            if approval["risk"] == "high" and not totp_check(
                identity.principal, data.get("totp") or ""
            ):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "a valid TOTP code is required for high-risk approvals"},
                )
                return

            try:
                updated = store.decide_approval(
                    approval_id, decision=decision_v, decided_by=identity.principal
                )
            except ApprovalNotFound:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such approval"})
                return
            except (ApprovalConflict, ApprovalExpired) as exc:
                self._send_json(HTTPStatus.CONFLICT, {"error": str(exc)})
                return

            self._audit(
                "approval_decide",
                principal=identity.principal,
                approval_id=approval_id,
                decision=decision_v,
                ip=request.client_ip,
            )
            self._send_json(HTTPStatus.OK, updated)

        def _pairing_rate_limited(self, ip: str) -> tuple[bool, int]:
            """Return ``(limited, retry_after_seconds)`` for a pairing POST.

            Keeps a small rolling window per source IP so a stranger cannot
            flood the owner's pending list; the 6th request inside the window
            (and every one after) is refused with ``Retry-After``.
            """
            now = time.monotonic()
            attempts = pairing_attempts.setdefault(ip, [])
            attempts[:] = [t for t in attempts if now - t < PAIRING_RATE_WINDOW_SECONDS]
            if len(attempts) >= PAIRING_RATE_LIMIT:
                retry = max(1, int(PAIRING_RATE_WINDOW_SECONDS - (now - attempts[0])))
                return True, retry
            attempts.append(now)
            return False, 0

        def _handle_pairing_create(self, request: Request) -> None:
            """Accept a public key + display name and create a pending pairing.

            Deliberately unauthenticated: this is the bootstrap path.  It can
            only ever create a *pending* request, never enrol a device or read
            anything, and returns only the pairing id, code and expiry.
            """
            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return
            # Validate BEFORE consulting the rate limiter.  A malformed request is
            # not an enrolment attempt: counting it would let a stranger burn the
            # allowance of a legitimate client behind the same address, and anyone
            # could lock the owner out simply by posting garbage.
            try:
                validate_public_key(data.get("public_key"))
                _name = data.get("display_name")
                if not isinstance(_name, str) or not _name.strip():
                    raise ValueError("display_name is required")
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            limited, retry_after = self._pairing_rate_limited(
                request.client_ip or "unknown"
            )
            if limited:
                self.close_connection = True
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "too many pairing requests"},
                    headers={"Retry-After": str(retry_after)},
                )
                return
            try:
                result = create_pairing(
                    store,
                    public_key=data.get("public_key"),
                    display_name=data.get("display_name"),
                )
            except DuplicatePublicKey as exc:
                self._send_json(HTTPStatus.CONFLICT, {"error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            pairing_codes[result["id"]] = result["code"]
            self._send_json(
                HTTPStatus.CREATED,
                {
                    "id": result["id"],
                    "code": result["code"],
                    "expires_at": result["expires_at"],
                },
            )

        def _handle_pairing_list(self) -> None:
            """List pairings (authenticated); pending first."""
            out: list[dict[str, Any]] = []
            for pairing in list_pairings(store):
                item = dict(pairing)
                item.pop("code_hash", None)
                if pairing["status"] == "pending":
                    # Prefer the persisted code, so the owner can still compare it
                    # after a restart; the in-memory copy covers a request created
                    # moments ago in this process.
                    code = pairing.get("code") or pairing_codes.get(pairing["id"])
                    if code:
                        item["code"] = code
                out.append(item)
            self._send_json(HTTPStatus.OK, out)

        def _handle_pairing_decide(self, request: Request, identity: Any) -> None:
            """Approve or reject a pending pairing (authenticated + TOTP)."""
            pairing_id = request.path[len("/api/pairings/") : -len("/decide")]
            if not pairing_id or "/" in pairing_id:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return
            decision = data.get("decision")
            if decision == "approve":
                decision_v = "approved"
            elif decision == "reject":
                decision_v = "rejected"
            else:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "decision must be 'approve' or 'reject'"},
                )
                return
            pairing = get_pairing(store, pairing_id)
            if pairing is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such pairing"})
                return
            if pairing["status"] != "pending":
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": f"pairing {pairing_id} is already "
                        f"{pairing['status']}"
                    },
                )
                return

            # Enrolling a device is high risk: a valid TOTP is required for
            # both approval and rejection (default deny when unconfigured).
            if not totp_check(identity.principal, data.get("totp") or ""):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "a valid TOTP code is required to decide a pairing"},
                )
                return

            try:
                if decision_v == "approved":
                    updated = approve_pairing(
                        store,
                        pairing_id,
                        decided_by=identity.principal,
                        enroll=enroll,
                    )
                else:
                    updated = reject_pairing(
                        store, pairing_id, decided_by=identity.principal
                    )
            except PairingNotFound:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such pairing"})
                return
            except (PairingConflict, PairingExpired) as exc:
                self._send_json(HTTPStatus.CONFLICT, {"error": str(exc)})
                return

            pairing_codes.pop(pairing_id, None)
            updated.pop("code_hash", None)
            self._send_json(HTTPStatus.OK, updated)

        def _handle_device_list(self) -> None:
            """List authorised devices (authenticated) from the auth store."""
            self._send_json(HTTPStatus.OK, list_devices_fn())

        def _handle_device_revoke(self, request: Request, identity: Any) -> None:
            """Revoke a device (authenticated) from the auth store."""
            del identity
            device_id = request.path[len("/api/devices/") : -len("/revoke")]
            if not device_id or "/" in device_id:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not revoke_device_fn(device_id):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such device"})
                return
            self._send_json(HTTPStatus.OK, {"id": device_id, "revoked": True})

        def _handle_task_create(self, request: Request) -> None:
            del request
            raw = self._read_body()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            if not isinstance(data, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"}
                )
                return
            try:
                result = dispatch_task(
                    store,
                    title=data.get("title"),
                    body=data.get("body"),
                    assignee=data.get("assignee"),
                    coordination=data.get("coordination", "single"),
                    participants=data.get("participants"),
                    send=bool(data.get("dispatch", True)),
                )
            except UnknownAgent as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.CREATED, result)

        def _handle_task_list(self, request: Request) -> None:
            status = request.query.get("status")
            origin = request.query.get("origin")
            assignee = request.query.get("assignee")
            try:
                tasks = store.list_tasks(
                    status=status, origin=origin, assignee=assignee
                )
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, tasks)

        def _handle_task_detail(self, request: Request) -> None:
            task_id = request.path[len("/api/tasks/") :]
            if not task_id or "/" in task_id:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            detail = store.get_task_detail(task_id)
            if detail is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such task"})
                return
            self._send_json(HTTPStatus.OK, detail)

        def _handle_stats(self) -> None:
            self._send_json(HTTPStatus.OK, _compute_stats(store))

        def _handle_stream(self) -> None:
            self.send_response(HTTPStatus.OK)
            for name, value in _SSE_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()

            tracker = ChangeTracker(store)
            self.wfile.write(b"retry: 1000\n")
            self.wfile.write(b"event: hello\n")
            self.wfile.write(b"data: {\"ready\": true}\n\n")
            self.wfile.flush()

            try:
                while True:
                    for change in tracker.poll():
                        payload = json.dumps(change, ensure_ascii=False)
                        self.wfile.write(
                            f"event: {change['table']}\n".encode("utf-8")
                        )
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    time.sleep(_SSE_POLL_SECONDS)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        # -- static assets ----------------------------------------------

        def _serve_static(self, relative: str) -> None:
            """Serve one dashboard asset from :data:`_STATIC_DIR`.

            ``relative`` is taken straight from the URL, so it is resolved and
            then checked to still live under the static directory before any
            byte is read, blocking ``..`` traversal.
            """
            if not relative or relative.startswith("/") or relative.startswith("\\"):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            candidate = (_STATIC_DIR / relative).resolve()
            if not candidate.is_relative_to(_STATIC_DIR):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not candidate.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                body = candidate.read_bytes()
            except OSError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            content_type = _STATIC_TYPES.get(
                candidate.suffix.lower(), "application/octet-stream"
            )
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        # -- plumbing ----------------------------------------------------

        def _send_json(
            self,
            status: HTTPStatus,
            payload: Any,
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    return Handler


def create_server(
    host: str = "127.0.0.1",
    port: int = 0,
    store: Store | None = None,
    authenticator: Authenticator | None = None,
    totp_verifier: Callable[[str, str], bool] | None = None,
    audit: Callable[..., Any] | None = None,
    enroll_device: Callable[[str, str], str] | None = None,
    list_devices: Callable[[], list[Any]] | None = None,
    revoke_device: Callable[[str], bool] | None = None,
    auth_manager: Any | None = None,
) -> ThreadingHTTPServer:
    """Create a threaded HTTP server serving ``store`` over JSON + SSE.

    ``port=0`` selects an ephemeral port (read ``server.server_address``).
    ``authenticator`` overrides the default (the real auth module when present,
    otherwise deny-all); tests inject a stub here.  ``totp_verifier`` and
    ``audit`` wire the high-risk second factor and the approval audit log.
    ``enroll_device`` / ``list_devices`` / ``revoke_device`` wire pairing
    approval to the auth layer's device store (defaults fail closed).
    ``auth_manager`` supplies the session/nonce helpers for ``/api/login`` and
    ``/api/logout``; when omitted it is recovered from ``authenticator``.
    """
    store = store if store is not None else Store()
    handler = create_app(
        store,
        authenticator,
        totp_verifier=totp_verifier,
        audit=audit,
        enroll_device=enroll_device,
        list_devices=list_devices,
        revoke_device=revoke_device,
        auth_manager=auth_manager,
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main(argv: list[str] | None = None) -> None:
    """Run the web server (host/port from ``MESHDISPATCH_WEB_*`` env vars)."""
    del argv
    host = os.environ.get("MESHDISPATCH_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("MESHDISPATCH_WEB_PORT", "8080"))
    server = create_server(host, port)
    print(f"meshdispatch web serving on http://{host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


__all__ = [
    "PAIRING_RATE_LIMIT",
    "PAIRING_RATE_WINDOW_SECONDS",
    "PUBLIC_PATHS",
    "PUBLIC_STATIC_PATHS",
    "Request",
    "create_app",
    "create_server",
    "main",
]


def _main() -> int:
    """Entry point for ``python -m meshdispatch.web.server``.

    Everything is configurable through the environment so the dashboard can be
    started without arguments::

        MESHDISPATCH_HOST   interface to bind (default 127.0.0.1)
        MESHDISPATCH_PORT   port to bind (default 8080)
        MESHDISPATCH_DB     SQLite database to read (see meshdispatch.store)

    Authentication uses the real ``meshdispatch.auth`` implementation; if that
    package is unavailable every request is denied rather than allowed.
    """
    import os

    host = os.environ.get("MESHDISPATCH_HOST", "127.0.0.1")
    port = int(os.environ.get("MESHDISPATCH_PORT", "8080"))
    server = create_server(host, port)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(f"meshdispatch dashboard on http://{bound_host}:{bound_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
