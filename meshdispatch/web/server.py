"""Standard-library HTTP + SSE server exposing the meshdispatch Store as JSON.

No third-party dependencies: transport is built on :mod:`http.server` and
:mod:`socketserver`.  Authentication is delegated to
:func:`meshdispatch.auth.authenticate`; every route except the login/bootstrap
route is gated behind it and returns HTTP 401 when it yields ``None``.
"""

from __future__ import annotations

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
except ImportError:  # pragma: no cover - auth lands later in phase 3
    _auth_authenticate = None


#: Path(s) exempt from authentication (the login/bootstrap entrypoint).  The
#: auth layer owns what happens here; this module only guarantees the route is
#: reachable without a session.
PUBLIC_PATHS = frozenset({"/api/login"})

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


def create_app(
    store: Store,
    authenticator: Authenticator | None = None,
    totp_verifier: Callable[[str, str], bool] | None = None,
    audit: Callable[..., Any] | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to ``store`` and ``authenticator``.

    ``totp_verifier`` verifies a TOTP code for the authenticated principal (used
    for high-risk approvals; defaults to deny).  ``audit`` receives approval
    audit events as ``audit(event, *, principal, approval_id, decision, ip)``.
    """
    auth: Authenticator = (
        authenticator if authenticator is not None else _DEFAULT_AUTHENTICATOR
    )
    totp_check: Callable[[str, str], bool] = (
        totp_verifier if totp_verifier is not None else _deny_totp
    )
    audit_hook: Callable[..., Any] = audit if audit is not None else _noop_audit

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

            Returns the authenticated :class:`Identity` (or ``None`` once a
            501/401 response has already been written).
            """
            if request.path in PUBLIC_PATHS:
                self.close_connection = True
                self._send_json(
                    HTTPStatus.NOT_IMPLEMENTED,
                    {"error": "login/bootstrap is handled by the auth layer"},
                )
                return None
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
            identity = self._authorize(request)
            if identity is None:
                return

            if request.path == "/api/tasks":
                self._handle_task_create(request)
            elif request.path == "/api/approvals":
                self._handle_approval_create(request, identity)
            elif request.path.startswith("/api/approvals/") and request.path.endswith(
                "/decide"
            ):
                self._handle_approval_decide(request, identity)
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
) -> ThreadingHTTPServer:
    """Create a threaded HTTP server serving ``store`` over JSON + SSE.

    ``port=0`` selects an ephemeral port (read ``server.server_address``).
    ``authenticator`` overrides the default (the real auth module when present,
    otherwise deny-all); tests inject a stub here.  ``totp_verifier`` and
    ``audit`` wire the high-risk second factor and the approval audit log.
    """
    store = store if store is not None else Store()
    handler = create_app(
        store, authenticator, totp_verifier=totp_verifier, audit=audit
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
    "PUBLIC_PATHS",
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
