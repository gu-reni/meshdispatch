"""Tests for phase 6a: device pairing (bootstrap enrolment + owner approval).

Covers the pairing store module, the unauthenticated/authenticated HTTP routes,
the rate limit on the bootstrap path, the TOTP second factor, and the security
boundaries (no enrol/read/decide without auth, single use, expiry, duplicate
public keys).
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any

import pytest

from meshdispatch.auth.crypto import generate_rsa_keypair, serialize_ssh_public_key
from meshdispatch.auth.totp import totp_at
from meshdispatch.control.approvals import build_totp_verifier
from meshdispatch.control.pairing import (
    DuplicatePublicKey,
    PairingConflict,
    PairingExpired,
    PairingNotFound,
    approve_pairing,
    compute_key_fingerprint,
    create_pairing,
    hash_pairing_code,
    list_pairings,
    reject_pairing,
)
from meshdispatch.store import Store
from meshdispatch.web.server import (
    PAIRING_RATE_LIMIT,
    create_server,
)

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


@pytest.fixture(scope="module")
def keypair():
    return generate_rsa_keypair(bits=1024)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


def _pub(keypair, comment="test-device"):
    return serialize_ssh_public_key(keypair, comment)


# ---------------------------------------------------------------------------
# store module: create / validate / fingerprint
# ---------------------------------------------------------------------------


def test_create_pairing_returns_code_once_and_stores_only_hash(store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")

    assert result["status"] == "pending"
    assert result["display_name"] == "host-b"
    assert result["key_fingerprint"].startswith("SHA256:")
    assert result["expires_at"] > result["created_at"]

    code = result["code"]
    assert isinstance(code, str) and len(code) == 8

    stored = store.get_pairing(result["id"])
    assert stored is not None
    assert stored["code_hash"] == hash_pairing_code(code)
    assert "code" not in stored
    assert code not in stored["code_hash"]


def test_create_pairing_rejects_bad_key(store):
    with pytest.raises(ValueError):
        create_pairing(store, public_key="not-a-key", display_name="x")
    with pytest.raises(ValueError):
        create_pairing(store, public_key="", display_name="x")


def test_create_pairing_requires_display_name(store, keypair):
    with pytest.raises(ValueError):
        create_pairing(store, public_key=_pub(keypair), display_name="  ")


def test_compute_fingerprint_stable(store, keypair):
    line = _pub(keypair)
    assert compute_key_fingerprint(line) == compute_key_fingerprint(line)
    assert compute_key_fingerprint(line).startswith("SHA256:")


def test_duplicate_public_key_rejected(store, keypair):
    create_pairing(store, public_key=_pub(keypair), display_name="a")
    with pytest.raises(DuplicatePublicKey):
        create_pairing(store, public_key=_pub(keypair), display_name="b")


# ---------------------------------------------------------------------------
# store module: decide (approve / reject / expiry / single use)
# ---------------------------------------------------------------------------


def test_approve_registers_device_via_enroll(store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    calls: list[tuple[str, str]] = []

    def enroll(principal, device_name):
        calls.append((principal, device_name))
        return "dev-42"

    updated = approve_pairing(
        store, result["id"], decided_by="alice", enroll=enroll
    )
    assert updated["status"] == "approved"
    assert updated["device_id"] == "dev-42"
    assert updated["decided_by"] == "alice"
    assert updated["decided_at"]
    assert calls == [("alice", "host-b")]


def test_reject_does_not_enrol(store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    calls: list[Any] = []

    updated = reject_pairing(
        store, result["id"], decided_by="alice",
        now=datetime.now(timezone.utc),
    )
    assert updated["status"] == "rejected"
    assert updated["device_id"] is None
    assert calls == []


def test_replayed_approval_fails(store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")

    def enroll(principal, device_name):
        return "dev-1"

    approve_pairing(store, result["id"], decided_by="alice", enroll=enroll)
    with pytest.raises(PairingConflict):
        approve_pairing(store, result["id"], decided_by="alice", enroll=enroll)
    with pytest.raises(PairingConflict):
        reject_pairing(store, result["id"], decided_by="alice")


def test_expired_cannot_be_approved(store, keypair):
    created = datetime(2020, 1, 1, tzinfo=timezone.utc)
    result = create_pairing(
        store, public_key=_pub(keypair), display_name="host-b", now=created
    )
    later = datetime(2020, 1, 1, 0, 20, tzinfo=timezone.utc)

    with pytest.raises(PairingExpired):
        approve_pairing(
            store, result["id"], decided_by="alice",
            enroll=lambda p, n: "dev-1", now=later,
        )
    assert store.get_pairing(result["id"])["status"] == "expired"


def test_decide_unknown_raises_not_found(store):
    with pytest.raises(PairingNotFound):
        approve_pairing(
            store, "pr-20261003-000000", decided_by="alice",
            enroll=lambda p, n: "dev-1",
        )


def test_list_pairings_pending_first(store, keypair):
    approved = create_pairing(store, public_key=_pub(keypair), display_name="a")
    approve_pairing(
        store, approved["id"], decided_by="alice", enroll=lambda p, n: "dev-1"
    )
    pending = create_pairing(store, public_key=_pub(keypair, "other"), display_name="b")

    ids = [p["id"] for p in list_pairings(store)]
    assert ids[0] == pending["id"]
    assert approved["id"] in ids


# ---------------------------------------------------------------------------
# web API
# ---------------------------------------------------------------------------


@pytest.fixture
def make_server(store):
    servers: list[tuple[Any, threading.Thread]] = []

    def _make(
        auth=_allow,
        totp_verifier=None,
        enroll_device=None,
        list_devices=None,
        revoke_device=None,
    ):
        server = create_server(
            "127.0.0.1",
            0,
            store,
            authenticator=auth,
            totp_verifier=totp_verifier,
            enroll_device=enroll_device,
            list_devices=list_devices,
            revoke_device=revoke_device,
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


def _request(method, port, path, payload=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = json.dumps(payload) if payload is not None else None
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, (json.loads(raw) if raw else None), resp_headers


def _get(port, path):
    status, body, _ = _request("GET", port, path)
    return status, body


def _post(port, path, payload=None):
    status, body, _ = _request("POST", port, path, payload)
    return status, body


# ---------------------------------------------------------------------------
# unauthenticated bootstrap: cannot enrol / read / decide
# ---------------------------------------------------------------------------


def test_unauthenticated_post_cannot_enrol_or_read(make_server, store, keypair):
    enrolled: list[Any] = []
    devices: list[Any] = []

    _, port = make_server(
        auth=_deny,
        enroll_device=lambda p, n: (enrolled.append((p, n)), "dev-1")[1],
        list_devices=lambda: list(devices),
    )

    status, body, _ = _request(
        "POST", port, "/api/pairings",
        {"public_key": _pub(keypair), "display_name": "host-b"},
    )
    assert status == 201
    assert set(body.keys()) == {"id", "code", "expires_at"}
    assert body["code"]

    # The inbound request never enrols a device and never reads anything.
    assert enrolled == []
    assert devices == []
    assert store.get_pairing(body["id"])["status"] == "pending"


def test_unauthenticated_cannot_read(make_server, store, keypair):
    create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    _, port = make_server(auth=_deny)

    assert _get(port, "/api/pairings")[0] == 401
    assert _get(port, "/api/devices")[0] == 401


def test_unauthenticated_cannot_decide(make_server, store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    _, port = make_server(auth=_deny)

    status, _ = _post(
        port, f"/api/pairings/{result['id']}/decide", {"decision": "approve"}
    )
    assert status == 401
    assert store.get_pairing(result["id"])["status"] == "pending"


# ---------------------------------------------------------------------------
# rate limit
# ---------------------------------------------------------------------------


def test_pairing_rate_limit_triggers(make_server, store, keypair):
    _, port = make_server()

    statuses = []
    for _ in range(PAIRING_RATE_LIMIT + 1):
        status, body, headers = _request(
            "POST", port, "/api/pairings",
            {"public_key": _pub(keypair), "display_name": "host-b"},
        )
        statuses.append((status, headers))

    assert all(s != 429 for s, _ in statuses[:PAIRING_RATE_LIMIT])
    last_status, last_headers = statuses[PAIRING_RATE_LIMIT]
    assert last_status == 429
    assert "retry-after" in last_headers


# ---------------------------------------------------------------------------
# decide: TOTP + status codes
# ---------------------------------------------------------------------------


def test_approve_without_totp_returns_403(make_server, store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    verifier = build_totp_verifier({"alice": TOTP_SECRET})
    _, port = make_server(totp_verifier=verifier)

    status, body = _post(
        port, f"/api/pairings/{result['id']}/decide", {"decision": "approve"}
    )
    assert status == 403

    status, body = _post(
        port, f"/api/pairings/{result['id']}/decide",
        {"decision": "approve", "totp": "000000"},
    )
    assert status == 403
    assert store.get_pairing(result["id"])["status"] == "pending"


def test_approve_without_configured_verifier_denies(make_server, store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    _, port = make_server()  # default totp_verifier denies

    code = totp_at(TOTP_SECRET, int(time.time()))
    status, _ = _post(
        port, f"/api/pairings/{result['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 403


def test_approve_with_totp_enrols_device(make_server, store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    enrolled: list[tuple[str, str]] = []

    def enroll(principal, device_name):
        enrolled.append((principal, device_name))
        return "dev-9"

    verifier = build_totp_verifier({"alice": TOTP_SECRET})
    _, port = make_server(totp_verifier=verifier, enroll_device=enroll)

    code = totp_at(TOTP_SECRET, int(time.time()))
    status, body = _post(
        port, f"/api/pairings/{result['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 200
    assert body["status"] == "approved"
    assert body["device_id"] == "dev-9"
    assert enrolled == [("alice", "host-b")]


def test_decide_twice_returns_409(make_server, store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    verifier = build_totp_verifier({"alice": TOTP_SECRET})
    _, port = make_server(totp_verifier=verifier, enroll_device=lambda p, n: "dev-1")
    code = totp_at(TOTP_SECRET, int(time.time()))

    status, _ = _post(
        port, f"/api/pairings/{result['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 200

    status, _ = _post(
        port, f"/api/pairings/{result['id']}/decide",
        {"decision": "approve", "totp": code},
    )
    assert status == 409


def test_decide_unknown_returns_404(make_server, store):
    _, port = make_server()
    status, _ = _post(
        port, "/api/pairings/pr-20261003-000000/decide", {"decision": "approve"}
    )
    assert status == 404


def test_decide_bad_value_returns_400(make_server, store, keypair):
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    _, port = make_server()
    status, _ = _post(
        port, f"/api/pairings/{result['id']}/decide", {"decision": "maybe"}
    )
    assert status == 400


def test_pairing_list_pending_first_and_includes_code(make_server, store, keypair):
    _, port = make_server()

    # A pending request created over the (unauthenticated) HTTP route holds its
    # plaintext code in memory, so the authenticated list can show it.
    status, created, _ = _request(
        "POST", port, "/api/pairings",
        {"public_key": _pub(keypair), "display_name": "host-b"},
    )
    assert status == 201
    pending_id = created["id"]

    approved = create_pairing(store, public_key=_pub(keypair, "other"), display_name="host-c")
    approve_pairing(
        store, approved["id"], decided_by="alice", enroll=lambda p, n: "dev-1"
    )

    status, body = _get(port, "/api/pairings")
    assert status == 200
    assert body[0]["id"] == pending_id
    by_id = {p["id"]: p for p in body}
    assert by_id[pending_id]["code"] == created["code"]
    assert "code_hash" not in by_id[pending_id]


def test_duplicate_public_key_web_conflict(make_server, store, keypair):
    _, port = make_server()
    payload = {"public_key": _pub(keypair), "display_name": "host-b"}
    assert _post(port, "/api/pairings", payload)[0] == 201
    assert _post(port, "/api/pairings", payload)[0] == 409


# ---------------------------------------------------------------------------
# ingest token is never accepted on pairing routes
# ---------------------------------------------------------------------------


def test_ingest_token_not_accepted_on_pairing_routes(make_server, store, keypair):
    _, plaintext = store.create_ingest_token("host-b")
    result = create_pairing(store, public_key=_pub(keypair), display_name="host-b")
    _, port = make_server(auth=_deny)

    status, _, _ = _request(
        "GET", port, "/api/pairings", headers={"Authorization": "Bearer " + plaintext}
    )
    assert status == 401

    status, _, _ = _request(
        "POST", port, f"/api/pairings/{result['id']}/decide",
        {"decision": "approve"}, headers={"Authorization": "Bearer " + plaintext},
    )
    assert status == 401


# ---------------------------------------------------------------------------
# device list / revoke endpoints
# ---------------------------------------------------------------------------


def test_device_list_and_revoke_endpoints(make_server, store):
    devices = [
        {
            "device_id": "dev-1",
            "principal": "alice",
            "device_name": "host-b",
            "confirmed": True,
            "created_at": "2026-10-03T00:00:00Z",
        }
    ]
    revoked: list[str] = []

    def list_devices():
        return list(devices)

    def revoke_device(device_id):
        revoked.append(device_id)
        return True

    _, port = make_server(list_devices=list_devices, revoke_device=revoke_device)

    status, body = _get(port, "/api/devices")
    assert status == 200
    assert body == devices

    status, body = _post(port, "/api/devices/dev-1/revoke")
    assert status == 200
    assert body == {"id": "dev-1", "revoked": True}
    assert revoked == ["dev-1"]


def test_device_revoke_unknown_returns_404(make_server, store):
    _, port = make_server(revoke_device=lambda d: False)
    status, _ = _post(port, "/api/devices/dev-missing/revoke")
    assert status == 404


def test_device_routes_require_auth(make_server, store):
    _, port = make_server(auth=_deny)
    assert _get(port, "/api/devices")[0] == 401
    assert _post(port, "/api/devices/dev-1/revoke")[0] == 401
