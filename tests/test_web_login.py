"""Tests for the browser login flow: POST /api/login, /api/logout, the public
login page, and the device-revocation path.

The SSH case is deliberately exercised end to end with a real throwaway
``ssh-keygen`` ed25519 key: the bug this guards against is an RSA-only verifier,
and the owner's own key is ed25519.
"""

from __future__ import annotations

import http.client
import json
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from meshdispatch.auth import AuthConfig, AuthManager, authenticate as module_authenticate
from meshdispatch.auth import configure as module_configure
from meshdispatch.auth.totp import totp_at
from meshdispatch.control.pairing import device_revoker_from_manager
from meshdispatch.store import Store
from meshdispatch.web.server import create_server

TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # base64/base32 RFC test vector
STATIC_DIR = Path(__file__).resolve().parent.parent / "meshdispatch" / "web" / "static"


class _Deny:
    def __call__(self, request: Any) -> None:
        return None


_deny = _Deny()


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


@pytest.fixture
def manager(tmp_path):
    return AuthManager(
        AuthConfig(cookie_signing_key="login-test-signing-key"),
        state_dir=str(tmp_path / "auth"),
    )


@pytest.fixture
def make_server(store):
    servers: list[tuple[Any, threading.Thread]] = []

    def _make(**kwargs):
        server = create_server("127.0.0.1", 0, store, **kwargs)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server, server.server_address[1]

    yield _make

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    port: int,
    method: str,
    path: str,
    *,
    payload: Any = None,
    raw_body: Any = None,
    cookie: str | None = None,
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if raw_body is not None:
        body = raw_body
    elif payload is not None:
        body = json.dumps(payload)
    else:
        body = None
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    set_cookie = resp.getheader("Set-Cookie")
    status = resp.status
    conn.close()
    try:
        data = json.loads(raw) if raw else None
    except ValueError:
        data = raw
    return status, data, set_cookie


def _get_raw(port: int, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    content_type = resp.getheader("Content-Type", "")
    conn.close()
    return resp.status, content_type, body


def _cookie_pair(set_cookie: str) -> str:
    """Reduce a ``Set-Cookie`` header to the ``name=value`` cookie pair."""
    return set_cookie.split(";", 1)[0].strip()


def _sign_nonce(key_path: str, nonce: str, namespace: str = "meshdispatch") -> str:
    proc = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-n", namespace, "-f", key_path, "-"],
        input=nonce.encode("utf-8"),
        capture_output=True,
        timeout=15,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc.stdout.decode("utf-8")


def _make_keypair(tmp_path: Path, name: str) -> tuple[str, str]:
    key_path = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key_path)],
        check=True,
        capture_output=True,
    )
    return str(key_path), key_path.with_suffix(".pub").read_text().strip()


# ---------------------------------------------------------------------------
# public login page / locked dashboard
# ---------------------------------------------------------------------------


def test_login_page_is_public_but_dashboard_is_not(make_server):
    _, port = make_server(authenticator=_deny)

    status, content_type, body = _get_raw(port, "/login")
    assert status == 200
    assert content_type.startswith("text/html")
    assert b"meshdispatch" in body

    # The dashboard itself and its script stay behind the gate.
    assert _get_raw(port, "/")[0] == 401
    assert _get_raw(port, "/index.html")[0] == 401
    assert _get_raw(port, "/static/app.js")[0] == 401

    # The login page's own assets are reachable so it can render.
    assert _get_raw(port, "/static/style.css")[0] == 200
    assert _get_raw(port, "/static/login.js")[0] == 200


def test_login_without_manager_fails_closed(make_server):
    _, port = make_server(authenticator=_deny)
    status, body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={"method": "password", "principal": "alice", "password": "x"},
    )
    assert status == 501
    assert set_cookie is None
    assert _get_raw(port, "/api/tasks")[0] == 401


# ---------------------------------------------------------------------------
# password path
# ---------------------------------------------------------------------------


def test_wrong_password_is_401_and_no_cookie(make_server, manager):
    manager.set_password("alice", "correct horse")
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    status, _body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={"method": "password", "principal": "alice", "password": "wrong"},
    )
    assert status == 401
    assert set_cookie is None
    assert _get_raw(port, "/api/tasks")[0] == 401


def test_garbage_login_body_is_rejected_without_crash(make_server, manager):
    manager.set_password("alice", "correct horse")
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    for raw in ("", "not json at all", "[]", "null"):
        status, _body, set_cookie = _request(
            port, "POST", "/api/login", raw_body=raw
        )
        assert status == 400, raw
        assert set_cookie is None

    # Unknown method is a client error, never a session.
    status, _body, set_cookie = _request(
        port, "POST", "/api/login", payload={"method": "carrier-pigeon"}
    )
    assert status == 400
    assert set_cookie is None

    # Missing password is a client error.
    status, _body, set_cookie = _request(
        port, "POST", "/api/login", payload={"method": "password", "principal": "alice"}
    )
    assert status == 400
    assert set_cookie is None


def test_password_login_issues_cookie_and_unlocks_api(make_server, manager, store):
    manager.set_password("alice", "correct horse")
    store.add_task(title="readable after login")
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    status, body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={"method": "password", "principal": "alice", "password": "correct horse"},
    )
    assert status == 200
    assert body["ok"] is True
    assert body["principal"] == "alice"
    assert set_cookie is not None
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie
    assert "Path=/" in set_cookie
    # Plain-HTTP default: the cookie must not be marked Secure.
    assert "Secure" not in set_cookie

    cookie = _cookie_pair(set_cookie)
    status, tasks, _ = _request(port, "GET", "/api/tasks", cookie=cookie)
    assert status == 200
    assert any(t["title"] == "readable after login" for t in tasks)


def test_password_login_with_totp(make_server, manager):
    manager.set_password("alice", "correct horse")
    manager.set_totp_secret("alice", TOTP_SECRET)
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    good = totp_at(TOTP_SECRET, int(time.time()))
    status, _body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={
            "method": "password",
            "principal": "alice",
            "password": "correct horse",
            "totp": good,
        },
    )
    assert status == 200
    assert set_cookie is not None

    status, _body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={
            "method": "password",
            "principal": "alice",
            "password": "correct horse",
            "totp": "000000",
        },
    )
    assert status == 401
    assert set_cookie is None


def test_module_level_manager_fallback(make_server, store, tmp_path):
    """A server wired only with ``meshdispatch.auth.authenticate`` can still log
    in, using the module-level manager that backs that function."""
    import meshdispatch.auth as authpkg

    previous = authpkg._manager
    manager = module_configure(
        AuthConfig(cookie_signing_key="k"), state_dir=str(tmp_path / "auth")
    )
    try:
        manager.set_password("alice", "pw")
        _, port = make_server(authenticator=module_authenticate)
        status, _body, set_cookie = _request(
            port,
            "POST",
            "/api/login",
            payload={"method": "password", "principal": "alice", "password": "pw"},
        )
        assert status == 200
        assert set_cookie is not None
        cookie = _cookie_pair(set_cookie)
        assert _request(port, "GET", "/api/tasks", cookie=cookie)[0] == 200
    finally:
        authpkg._manager = previous


def test_cookie_secure_is_configurable(tmp_path, store):
    manager = AuthManager(
        AuthConfig(cookie_signing_key="k", cookie_secure=True),
        state_dir=str(tmp_path / "auth"),
    )
    manager.set_password("alice", "pw")
    server = create_server(
        "127.0.0.1", 0, store, authenticator=manager.authenticate, auth_manager=manager
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        status, _body, set_cookie = _request(
            port,
            "POST",
            "/api/login",
            payload={"method": "password", "principal": "alice", "password": "pw"},
        )
        assert status == 200
        assert set_cookie is not None and "Secure" in set_cookie
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# SSH path (real ssh-keygen ed25519)
# ---------------------------------------------------------------------------

requires_ssh_keygen = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen is required"
)


@requires_ssh_keygen
def test_ssh_ed25519_challenge_response_login(make_server, manager, store, tmp_path):
    key_path, public_key = _make_keypair(tmp_path, "owner")
    manager.add_authorized_key("gu-reni", public_key)
    store.add_task(title="ssh unlocked")
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    status, body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={"method": "ssh", "action": "challenge", "principal": "gu-reni"},
    )
    assert status == 200
    assert set_cookie is None
    nonce = body["nonce"]
    assert nonce

    signature = _sign_nonce(key_path, nonce, body.get("namespace", "meshdispatch"))
    status, body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={
            "method": "ssh",
            "principal": "gu-reni",
            "nonce": nonce,
            "signature": signature,
        },
    )
    assert status == 200, body
    assert set_cookie is not None

    cookie = _cookie_pair(set_cookie)
    status, tasks, _ = _request(port, "GET", "/api/tasks", cookie=cookie)
    assert status == 200
    assert any(t["title"] == "ssh unlocked" for t in tasks)


@requires_ssh_keygen
def test_ssh_login_with_wrong_key_is_401(make_server, manager, tmp_path):
    _good_key, public_key = _make_keypair(tmp_path, "good")
    bad_key, _bad_pub = _make_keypair(tmp_path, "bad")
    manager.add_authorized_key("gu-reni", public_key)
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    status, body, _ = _request(
        port,
        "POST",
        "/api/login",
        payload={"method": "ssh", "action": "challenge", "principal": "gu-reni"},
    )
    nonce = body["nonce"]
    signature = _sign_nonce(bad_key, nonce)

    status, _body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={
            "method": "ssh",
            "principal": "gu-reni",
            "nonce": nonce,
            "signature": signature,
        },
    )
    assert status == 401
    assert set_cookie is None


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


def test_logout_requires_auth(make_server, manager):
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)
    assert _request(port, "POST", "/api/logout")[0] == 401


def test_logout_revokes_session_and_clears_cookie(make_server, manager):
    manager.set_password("alice", "pw")
    _, port = make_server(authenticator=manager.authenticate, auth_manager=manager)

    status, _body, set_cookie = _request(
        port,
        "POST",
        "/api/login",
        payload={"method": "password", "principal": "alice", "password": "pw"},
    )
    assert status == 200
    cookie = _cookie_pair(set_cookie)

    status, _body, cleared = _request(
        port, "POST", "/api/logout", cookie=cookie
    )
    assert status == 200
    assert cleared is not None
    assert "Max-Age=0" in cleared

    # The revoked session no longer authenticates.
    assert _request(port, "GET", "/api/tasks", cookie=cookie)[0] == 401


# ---------------------------------------------------------------------------
# device revocation (the "dead button")
# ---------------------------------------------------------------------------


def test_manager_revoke_device_unconfirms(manager):
    device_id = manager.enroll_device("alice", device_name="laptop")
    manager.confirm_device(device_id, approver_principal="alice")
    assert manager.store.get_device(device_id)["confirmed"] is True

    assert manager.revoke_device(device_id) is True
    rec = manager.store.get_device(device_id)
    assert rec["confirmed"] is False
    assert rec["confirmed_by"] is None

    # Unknown devices report honestly, and an idempotent re-revoke still finds it.
    assert manager.revoke_device("dev-does-not-exist") is False
    assert manager.revoke_device(device_id) is True


def test_device_revoker_helper_uses_real_method(manager):
    device_id = manager.enroll_device("alice")
    manager.confirm_device(device_id, approver_principal="alice")
    revoke = device_revoker_from_manager(manager)
    assert revoke(device_id) is True
    assert manager.store.get_device(device_id)["confirmed"] is False
    assert revoke("missing") is False


# ---------------------------------------------------------------------------
# static asset safety
# ---------------------------------------------------------------------------


def test_no_innerhtml_assignment_in_static_assets():
    offenders: list[str] = []
    for path in sorted(STATIC_DIR.glob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if ".innerHTML" in text or "innerHTML =" in text:
            offenders.append(path.name)
    assert offenders == [], f"dynamic innerHTML use in: {offenders}"


def test_login_page_has_no_external_resources():
    html = (STATIC_DIR / "login.html").read_text(encoding="utf-8")
    assert "http://" not in html
    assert "https://" not in html
    assert "<script src=\"/static/login.js\"></script>" in html
