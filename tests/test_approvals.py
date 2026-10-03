"""Tests for phase 4b: the approvals queue and its security boundaries.

Covers the store API (create/get/list/decide), the six security requirements
(single use, expiry, binding, high-risk second factor, audit, default deny),
and the web API status codes.
"""

from __future__ import annotations

import http.client
import json
import re
import threading
import time
from typing import Any

import pytest

from meshdispatch.auth import AuthConfig, AuthManager, PrincipalConfig
from meshdispatch.auth.totp import totp_at
from meshdispatch.control.approvals import build_audit_logger, build_totp_verifier
from meshdispatch.store import (
    ApprovalConflict,
    ApprovalExpired,
    ApprovalNotFound,
    Store,
    verify_decision,
)
from meshdispatch.web.server import create_server

TOTP_SECRET = "JBSWY3DPEHPK3PXP"


class StubIdentity:
    def __init__(self, principal="alice", method="stub", device_id=None):
        self.principal = principal
        self.method = method
        self.device_id = device_id


def _allow(request: Any) -> StubIdentity:
    return StubIdentity()


def _deny(request: Any) -> None:
    return None


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db", approval_signing_key="test-signing-key")


@pytest.fixture
def make_server(store):
    servers: list[tuple[Any, threading.Thread]] = []

    def _make(auth=_allow, totp_verifier=None, audit=None):
        server = create_server(
            "127.0.0.1",
            0,
            store,
            authenticator=auth,
            totp_verifier=totp_verifier,
            audit=audit,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server, server.server_address[1]

    yield _make

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(port: int, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()
    return resp.status, json.loads(body) if body else None


def _post(port: int, path: str, payload: Any):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = json.dumps(payload)
    conn.request(
        "POST", path, body=body, headers={"Content-Type": "application/json"}
    )
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()
    return resp.status, json.loads(raw) if raw else None


def _mk(store, **kw):
    defaults = {"task_id": "md-20261003-000001", "agent": "worker", "command": "ls"}
    defaults.update(kw)
    return store.create_approval(**defaults)


def _next_sse_event(resp):
    event_type = None
    data_lines = []
    while True:
        raw = resp.readline()
        if not raw:
            return None, {}
        line = raw.decode("utf-8").rstrip("\r\n")
        if line == "":
            if data_lines:
                return event_type, json.loads("\n".join(data_lines))
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_type = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:") :].strip())


# ---------------------------------------------------------------------------
# store API
# ---------------------------------------------------------------------------


def test_approval_id_format(store):
    a = _mk(store)
    assert re.match(r"^ap-\d{8}-[0-9a-f]{6}$", a["id"])


def test_create_approval_pending_with_expiry(store):
    a = _mk(store)
    assert a["status"] == "pending"
    assert a["nonce"]
    assert a["requested_at"].endswith("Z")
    assert a["expires_at"].endswith("Z")
    assert a["expires_at"] > a["requested_at"]
    assert a["decided_at"] is None
    assert a["decision_signature"] is None


def test_invalid_risk_rejected(store):
    with pytest.raises(ValueError):
        _mk(store, risk="critical")


def test_list_approvals_pending_first(store):
    decided = _mk(store)
    store.decide_approval(decided["id"], decision="approve", decided_by="owner")
    pending = _mk(store)

    ids = [a["id"] for a in store.list_approvals()]
    assert ids[0] == pending["id"]
    assert decided["id"] in ids


def test_list_approvals_status_filter(store):
    _mk(store)
    approved = _mk(store)
    store.decide_approval(approved["id"], decision="reject", decided_by="owner")

    pending = [a for a in store.list_approvals(status="pending")]
    assert len(pending) == 1
    rejected = [a for a in store.list_approvals(status="rejected")]
    assert len(rejected) == 1
    assert rejected[0]["id"] == approved["id"]


def test_get_approval_missing(store):
    assert store.get_approval("ap-20261003-000000") is None


# ---------------------------------------------------------------------------
# security requirement 1: single use
# ---------------------------------------------------------------------------


def test_decide_twice_raises_conflict(store):
    a = _mk(store)
    first = store.decide_approval(a["id"], decision="approve", decided_by="owner")
    assert first["status"] == "approved"
    with pytest.raises(ApprovalConflict):
        store.decide_approval(a["id"], decision="reject", decided_by="owner")


# ---------------------------------------------------------------------------
# security requirement 2: expiry
# ---------------------------------------------------------------------------


def test_expired_approval_flips_to_expired(store):
    a = _mk(store, expires_at="2000-01-01T00:00:00Z")
    with pytest.raises(ApprovalExpired):
        store.decide_approval(a["id"], decision="approve", decided_by="owner")
    assert store.get_approval(a["id"])["status"] == "expired"


def test_not_found_raises(store):
    with pytest.raises(ApprovalNotFound):
        store.decide_approval("ap-20261003-000000", decision="approve", decided_by="owner")


# ---------------------------------------------------------------------------
# security requirement 3: binding signature
# ---------------------------------------------------------------------------


def test_decision_signature_covers_fields(store):
    a = _mk(store, task_id="md-1234", command="rm -rf /")
    dec = store.decide_approval(a["id"], decision="approve", decided_by="gu-reni")
    sig = dec["decision_signature"]

    assert verify_decision(
        store.approval_signing_key,
        a["id"],
        "md-1234",
        "approved",
        "gu-reni",
        dec["decided_at"],
        sig,
    )

    # Tampering with any bound field invalidates the signature.
    assert not verify_decision(
        store.approval_signing_key, a["id"], "md-1234", "rejected", "gu-reni",
        dec["decided_at"], sig,
    )
    assert not verify_decision(
        store.approval_signing_key, "other-id", "md-1234", "approved", "gu-reni",
        dec["decided_at"], sig,
    )
    assert not verify_decision(
        store.approval_signing_key, a["id"], "md-1234", "approved", "mallory",
        dec["decided_at"], sig,
    )


# ---------------------------------------------------------------------------
# web API: default deny
# ---------------------------------------------------------------------------


def test_approvals_require_auth(make_server, store):
    _mk(store)
    _, port = make_server(auth=_deny)

    assert _get(port, "/api/approvals")[0] == 401
    assert _get(port, "/api/approvals/ap-20261003-000000")[0] == 401
    status, _ = _post(
        port, "/api/approvals",
        {"task_id": "t", "agent": "a", "command": "x"},
    )
    assert status == 401
    status, _ = _post(
        port, "/api/approvals/ap-20261003-000000/decide", {"decision": "approve"}
    )
    assert status == 401


# ---------------------------------------------------------------------------
# web API: create / list / detail
# ---------------------------------------------------------------------------


def test_create_approval_201(make_server, store):
    _, port = make_server()
    status, body = _post(
        port,
        "/api/approvals",
        {
            "task_id": "md-1",
            "agent": "worker",
            "command": "kubectl apply -f x",
            "purpose": "deploy",
            "impact": "prod",
            "risk": "medium",
        },
    )
    assert status == 201
    assert body["id"].startswith("ap-")
    assert body["status"] == "pending"
    assert body["risk"] == "medium"
    assert body["nonce"]


def test_create_approval_missing_fields_400(make_server, store):
    _, port = make_server()
    status, body = _post(port, "/api/approvals", {"agent": "a"})
    assert status == 400
    assert "task_id" in body["error"]


def test_approval_list_and_detail(make_server, store):
    a = _mk(store, command="sudo reboot")
    _, port = make_server()

    status, body = _get(port, "/api/approvals")
    assert status == 200
    assert isinstance(body, list)
    assert body[0]["id"] == a["id"]

    status, body = _get(port, f"/api/approvals/{a['id']}")
    assert status == 200
    assert body["command"] == "sudo reboot"


def test_approval_detail_unknown_404(make_server):
    _, port = make_server()
    status, _ = _get(port, "/api/approvals/ap-20261003-000000")
    assert status == 404


# ---------------------------------------------------------------------------
# web API: decide
# ---------------------------------------------------------------------------


def test_decide_bad_value_400(make_server, store):
    a = _mk(store)
    _, port = make_server()
    status, body = _post(port, f"/api/approvals/{a['id']}/decide", {"decision": "maybe"})
    assert status == 400
    assert store.get_approval(a["id"])["status"] == "pending"


def test_decide_unknown_id_404(make_server):
    _, port = make_server()
    status, _ = _post(
        port, "/api/approvals/ap-20261003-000000/decide", {"decision": "approve"}
    )
    assert status == 404


def test_decide_twice_409(make_server, store):
    a = _mk(store)
    _, port = make_server()

    status, body = _post(port, f"/api/approvals/{a['id']}/decide", {"decision": "approve"})
    assert status == 200
    assert body["status"] == "approved"
    assert body["decided_by"] == "alice"

    status, body = _post(port, f"/api/approvals/{a['id']}/decide", {"decision": "reject"})
    assert status == 409


def test_decide_expired_409(make_server, store):
    a = _mk(store, expires_at="2000-01-01T00:00:00Z")
    _, port = make_server()
    status, body = _post(port, f"/api/approvals/{a['id']}/decide", {"decision": "approve"})
    assert status == 409
    assert store.get_approval(a["id"])["status"] == "expired"


def test_low_risk_decide_without_totp(make_server, store):
    a = _mk(store, risk="low")
    _, port = make_server(totp_verifier=build_totp_verifier({"alice": TOTP_SECRET}))
    status, body = _post(port, f"/api/approvals/{a['id']}/decide", {"decision": "approve"})
    assert status == 200
    assert body["status"] == "approved"


# ---------------------------------------------------------------------------
# security requirement 4: high risk requires TOTP
# ---------------------------------------------------------------------------


def test_high_risk_requires_totp(make_server, store):
    a = _mk(store, risk="high")
    verifier = build_totp_verifier({"alice": TOTP_SECRET})
    _, port = make_server(totp_verifier=verifier)

    # Missing code -> 403.
    status, _ = _post(port, f"/api/approvals/{a['id']}/decide", {"decision": "approve"})
    assert status == 403

    # Wrong code -> 403.
    status, _ = _post(
        port, f"/api/approvals/{a['id']}/decide",
        {"decision": "approve", "totp": "000000"},
    )
    assert status == 403

    # Still pending: a denied decide must never consume the nonce.
    assert store.get_approval(a["id"])["status"] == "pending"

    # Valid code -> 200.
    code = totp_at(TOTP_SECRET, int(time.time()))
    status, body = _post(
        port, f"/api/approvals/{a['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 200
    assert body["status"] == "approved"


def test_high_risk_without_configured_verifier_denies(make_server, store):
    a = _mk(store, risk="high")
    _, port = make_server()  # default totp_verifier denies
    code = totp_at(TOTP_SECRET, int(time.time()))
    status, _ = _post(
        port, f"/api/approvals/{a['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 403


def test_high_risk_already_decided_returns_409(make_server, store):
    a = _mk(store, risk="high")
    verifier = build_totp_verifier({"alice": TOTP_SECRET})
    _, port = make_server(totp_verifier=verifier)
    code = totp_at(TOTP_SECRET, int(time.time()))

    status, _ = _post(
        port, f"/api/approvals/{a['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 200

    # A second decide on an already-decided entry is a conflict, not a
    # misleading 403 (and does not consume a TOTP).
    status, _ = _post(
        port, f"/api/approvals/{a['id']}/decide", {"decision": "approve"}
    )
    assert status == 409


# ---------------------------------------------------------------------------
# security requirement 5: audit
# ---------------------------------------------------------------------------


def test_audit_create_and_decide(tmp_path, store):
    manager = AuthManager(
        AuthConfig(principals={"alice": PrincipalConfig(totp_secret=TOTP_SECRET)}),
        state_dir=str(tmp_path / "auth"),
    )
    audit = build_audit_logger(manager.store.audit)

    servers = []
    server = create_server("127.0.0.1", 0, store, authenticator=_allow, audit=audit)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    servers.append((server, thread))
    port = server.server_address[1]

    try:
        status, body = _post(
            port,
            "/api/approvals",
            {"task_id": "t", "agent": "a", "command": "x", "risk": "low"},
        )
        assert status == 201
        aid = body["id"]
        status, _ = _post(port, f"/api/approvals/{aid}/decide", {"decision": "approve"})
        assert status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    entries = manager.store.audit.read_from_disk()
    by_event = {e["event"]: e for e in entries}
    assert "approval_create" in by_event
    assert "approval_decide" in by_event

    create_entry = by_event["approval_create"]
    assert create_entry["approval_id"] == aid
    assert create_entry["principal"] == "alice"
    assert create_entry["ip"] == "127.0.0.1"
    assert create_entry["ts"].endswith("Z")

    decide_entry = by_event["approval_decide"]
    assert decide_entry["approval_id"] == aid
    assert decide_entry["decision"] == "approved"
    assert decide_entry["principal"] == "alice"
    assert decide_entry["ts"].endswith("Z")


# ---------------------------------------------------------------------------
# SSE push: a new approval appears without a manual reload
# ---------------------------------------------------------------------------


def test_sse_emits_approval_event(make_server, store):
    _, port = make_server()

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/stream")
    resp = conn.getresponse()
    assert resp.status == 200

    event_type, _data = _next_sse_event(resp)
    assert event_type == "hello"

    a = _mk(store)

    found = None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        event_type, data = _next_sse_event(resp)
        if event_type == "approvals" and a["id"] in data.get("ids", []):
            found = data
            break
    conn.close()

    assert found is not None, "no approvals SSE event observed within 5 seconds"
    assert found["table"] == "approvals"
    assert a["id"] in found["ids"]
