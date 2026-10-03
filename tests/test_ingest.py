"""Tests for phase 5a: cross-server push path (ingest API, tokens, push CLI)."""

from __future__ import annotations

import http.client
import json
import sqlite3
import threading
from typing import Any

import pytest

from meshdispatch.auth import AuthConfig, AuthManager
from meshdispatch.cli import main as cli_main
from meshdispatch.control.ingest import apply_ingest
from meshdispatch.control.push import PushError, build_batch, push_to
from meshdispatch.store import Store
from meshdispatch.web.server import create_server


class Req:
    def __init__(self, headers=None, cookies=None, client_ip=None, path="", query=None):
        self.headers = dict(headers or {})
        self.cookies = dict(cookies or {})
        self.client_ip = client_ip
        self.path = path
        self.query = dict(query or {})


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
    return Store(tmp_path / "test.db")


# ---------------------------------------------------------------------------
# 1. ingest tokens (storage, hashing, revocation)
# ---------------------------------------------------------------------------


def test_create_token_hashed_at_rest(store, tmp_path):
    record, plaintext = store.create_ingest_token("host-b")

    assert record["agent"] == "host-b"
    assert record["revoked"] is False
    assert "token_hash" not in record  # never exposed through the record API
    assert plaintext.startswith(record["id"] + ".")

    secret = plaintext.partition(".")[2]
    conn = sqlite3.connect(tmp_path / "test.db")
    row = conn.execute(
        "SELECT token_hash, revoked_at FROM ingest_tokens WHERE id=?", (record["id"],)
    ).fetchone()
    conn.close()
    stored_hash = row[0]
    assert stored_hash.startswith("scrypt$")
    assert secret not in stored_hash
    assert plaintext not in stored_hash
    assert row[1] is None

    # The plaintext never lands anywhere else in the file.
    raw = (tmp_path / "test.db").read_bytes()
    assert plaintext.encode() not in raw
    assert secret.encode() not in raw


def test_token_verify_round_trip(store):
    _, plaintext = store.create_ingest_token("host-b")
    binding = store.verify_ingest_token(plaintext)
    assert binding == {"id": plaintext.partition(".")[0], "agent": "host-b"}


def test_token_verify_rejects_bad(store):
    _, plaintext = store.create_ingest_token("host-b")
    assert store.verify_ingest_token("mdit-nope.aaaa") is None
    assert store.verify_ingest_token("") is None
    assert store.verify_ingest_token("no-dot") is None
    # Wrong secret on the right id.
    prefix, _, _secret = plaintext.partition(".")
    assert store.verify_ingest_token(f"{prefix}.{'0' * 64}") is None


def test_token_revocation(store):
    _, plaintext = store.create_ingest_token("host-b")
    token_id = plaintext.partition(".")[0]

    assert store.revoke_ingest_token(token_id) is True
    assert store.verify_ingest_token(plaintext) is None
    # Revoking an already-revoked id is a no-op.
    assert store.revoke_ingest_token(token_id) is False

    listed = store.list_ingest_tokens()
    assert len(listed) == 1
    assert listed[0]["revoked"] is True
    assert listed[0]["revoked_at"] is not None


def test_token_list_sorted_and_no_secret(store):
    a, _ = store.create_ingest_token("zeta")
    b, _ = store.create_ingest_token("alpha")

    tokens = store.list_ingest_tokens()
    ids = [t["id"] for t in tokens]
    assert ids == [a["id"], b["id"]]  # created_at order (both same second, then id)
    for t in tokens:
        assert set(t.keys()) == {"id", "agent", "created_at", "revoked_at", "revoked"}


def test_token_create_rejects_blank_agent(store):
    with pytest.raises(ValueError):
        store.create_ingest_token("  ")


# ---------------------------------------------------------------------------
# 2. apply_ingest (idempotency + attribution mapping)
# ---------------------------------------------------------------------------


def _batch(remote_id="md-20990101-000001", origin_ref="ctx-1", agent="host-b"):
    return {
        "agent": agent,
        "tasks": [
            {
                "id": remote_id,
                "title": "sync",
                "origin": "a2a",
                "origin_ref": origin_ref,
                "assignee": agent,
                "coordination": "multi",
                "participants": ["host-a", "host-b"],
                "status": "done",
                "created_at": "2026-10-03T00:00:00Z",
                "result": "accepted",
            }
        ],
        "runs": [
            {
                "task_id": remote_id,
                "agent": agent,
                "status": "done",
                "started_at": "2026-10-03T00:00:00Z",
                "ended_at": "2026-10-03T00:00:05Z",
                "outcome": "accepted",
                "summary": "ok",
                "source_key": "a2a:ctx-1:run:1",
            }
        ],
        "messages": [
            {
                "task_id": remote_id,
                "author": agent,
                "author_kind": "agent",
                "body": "hello",
                "visibility": "local",
                "created_at": "2026-10-03T00:00:01Z",
                "source_key": "a2a:ctx-1:msg:1",
            }
        ],
        "events": [
            {
                "task_id": remote_id,
                "kind": "handoff",
                "payload": {"to": "host-a"},
                "created_at": "2026-10-03T00:00:02Z",
                "source_key": "a2a:ctx-1:event:1",
            }
        ],
    }


def _row_counts(store):
    conn = store.connect()
    try:
        return {
            "tasks": conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0],
            "runs": conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
            "messages": conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        }
    finally:
        conn.close()


def _origin_ref_batch():
    """A batch whose children reference the task by ``origin_ref``, not id."""
    return {
        "agent": "host-b",
        "tasks": [
            {
                "id": "md-20990101-000001",
                "title": "sync",
                "origin": "a2a",
                "origin_ref": "ctx-1",
                "assignee": "host-b",
                "status": "done",
                "created_at": "2026-10-03T00:00:00Z",
            }
        ],
        "runs": [
            {"task_id": "ctx-1", "status": "done", "source_key": "a2a:ctx-1:run:1"}
        ],
        "messages": [
            {
                "task_id": "ctx-1",
                "author": "host-b",
                "body": "hello",
                "source_key": "a2a:ctx-1:msg:1",
            }
        ],
        "events": [
            {
                "task_id": "ctx-1",
                "kind": "handoff",
                "payload": {"to": "host-a"},
                "source_key": "a2a:ctx-1:event:1",
            }
        ],
    }


def test_apply_ingest_inserts_everything(store):
    result = apply_ingest(store, **_batch())
    assert result["accepted"] == {"tasks": 1, "runs": 1, "messages": 1, "events": 1}

    tasks = store.list_tasks()
    assert len(tasks) == 1
    task = tasks[0]
    assert task["id"] == "md-20990101-000001"  # preserved id
    assert task["origin_ref"] == "ctx-1"
    assert task["participants"] == ["host-a", "host-b"]
    assert task["created_at"] == "2026-10-03T00:00:00Z"

    detail = store.get_task_detail(task["id"])
    assert len(detail["runs"]) == 1
    assert len(detail["messages"]) == 1
    assert len(detail["events"]) == 1
    assert detail["events"][0]["payload"] == {"to": "host-a"}


def test_apply_ingest_idempotent(store):
    first = apply_ingest(store, **_batch())
    assert first["accepted"]["tasks"] == 1

    second = apply_ingest(store, **_batch())
    assert second["accepted"] == {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    assert second["skipped"] == {"tasks": 1, "runs": 1, "messages": 1, "events": 1}
    assert len(store.list_tasks()) == 1


def test_apply_ingest_dedup_by_origin_ref_with_different_id(store):
    apply_ingest(store, **_batch(remote_id="md-20990101-000001", origin_ref="ctx-1"))
    # Same origin_ref but a fresh sender id -> must dedup onto the existing task.
    result = apply_ingest(
        store, **_batch(remote_id="md-20990101-000002", origin_ref="ctx-1")
    )
    assert result["accepted"]["tasks"] == 0
    assert result["skipped"]["tasks"] == 1
    assert len(store.list_tasks()) == 1
    # The run under the new id still maps onto the existing local task.
    assert result["skipped"]["runs"] == 1


def test_apply_ingest_reports_unresolvable_child(store):
    batch = _batch()
    batch["runs"] = [{"task_id": "md-20990101-ffffff", "status": "done"}]
    result = apply_ingest(store, **batch)
    assert result["accepted"]["runs"] == 0
    assert result["skipped"]["runs"] == 0
    assert any("md-20990101-ffffff" in err for err in result["errors"])


def test_apply_ingest_reported_counts_match_database(store):
    before = _row_counts(store)
    result = apply_ingest(store, **_origin_ref_batch())
    after = _row_counts(store)

    deltas = {table: after[table] - before[table] for table in before}
    assert result["accepted"] == deltas
    assert result["skipped"] == {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    assert result["errors"] == []


def test_apply_ingest_resolves_children_by_origin_ref(store):
    result = apply_ingest(store, **_origin_ref_batch())
    assert result["accepted"] == {"tasks": 1, "runs": 1, "messages": 1, "events": 1}
    assert result["errors"] == []

    task = store.list_tasks()[0]
    detail = store.get_task_detail(task["id"])
    assert len(detail["runs"]) == 1
    assert len(detail["messages"]) == 1
    assert len(detail["events"]) == 1


def test_apply_ingest_origin_ref_idempotent(store):
    first = apply_ingest(store, **_origin_ref_batch())
    assert first["accepted"]["tasks"] == 1

    second = apply_ingest(store, **_origin_ref_batch())
    assert second["accepted"] == {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    assert second["skipped"] == {"tasks": 1, "runs": 1, "messages": 1, "events": 1}
    assert second["errors"] == []
    assert len(store.list_tasks()) == 1


def test_apply_ingest_missing_title_uses_placeholder(store):
    batch = _batch()
    batch["tasks"][0].pop("title")
    result = apply_ingest(store, **batch)
    assert result["accepted"]["tasks"] == 1
    assert store.list_tasks()[0]["title"] == "(untitled)"


def _raw_batch():
    """A batch with no source_keys and a scalar event payload (defect repro).

    Matches the real batches that triggered the ingest defects: children carry
    no ``source_key`` and the event payload is a plain JSON string.
    """
    return {
        "agent": "host-b",
        "tasks": [
            {
                "id": "md-20990101-000001",
                "title": "sync",
                "origin": "a2a",
                "origin_ref": "ctx-1",
                "status": "done",
            }
        ],
        "runs": [
            {"task_id": "md-20990101-000001", "agent": "host-b", "status": "done"}
        ],
        "messages": [
            {"task_id": "md-20990101-000001", "author": "host-b", "body": "one"},
            {"task_id": "md-20990101-000001", "author": "host-b", "body": "two"},
        ],
        "events": [
            {
                "task_id": "md-20990101-000001",
                "kind": "log",
                "payload": "plain text payload",
            }
        ],
    }


def test_apply_ingest_children_idempotent_without_source_key(store):
    first = apply_ingest(store, **_raw_batch())
    assert first["accepted"] == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}

    second = apply_ingest(store, **_raw_batch())
    assert second["accepted"] == {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    assert second["skipped"] == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}
    assert _row_counts(store) == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}


def test_apply_ingest_event_accepts_scalar_payload(store):
    batch = {
        "agent": "host-b",
        "tasks": [{"id": "md-20990101-000001", "title": "sync"}],
        "events": [
            {
                "task_id": "md-20990101-000001",
                "kind": "log",
                "payload": "plain text",
            }
        ],
    }
    result = apply_ingest(store, **batch)
    assert result["accepted"]["events"] == 1
    assert result["errors"] == []

    detail = store.get_task_detail("md-20990101-000001")
    assert detail["events"][0]["payload"] == "plain text"


def test_apply_ingest_error_names_reference_keys(store):
    batch = _batch()
    batch["runs"] = [{"status": "done"}]  # neither task_id nor origin_ref
    result = apply_ingest(store, **batch)
    assert result["errors"]
    assert any("task_id" in err and "origin_ref" in err for err in result["errors"])


# ---------------------------------------------------------------------------
# 3. push client
# ---------------------------------------------------------------------------


def _populate(store):
    tid = store.add_task(
        title="backup", origin="cron", origin_ref="job1",
        assignee="host-b", status="done",
    )
    run = store.add_run_start(tid, agent="host-b")
    store.add_run_end(run["id"], status="done", outcome="accepted")
    store.add_message(tid, author="host-b", body="done", run_id=run["id"])
    store.add_event(tid, kind="finish", payload={"ok": True}, run_id=run["id"])
    return tid


def test_build_batch_shape(store):
    tid = _populate(store)
    details = [store.get_task_detail(tid)]
    batch = build_batch("host-b", details)

    assert batch["agent"] == "host-b"
    assert len(batch["tasks"]) == 1
    assert batch["tasks"][0]["id"] == tid
    assert batch["tasks"][0]["origin_ref"] == "job1"
    assert len(batch["runs"]) == 1
    assert batch["runs"][0]["task_id"] == tid
    # The manual run has no source_key, so a stable one is synthesized.
    assert batch["runs"][0]["source_key"].startswith(f"push:{tid}:run:")
    assert len(batch["messages"]) == 1
    assert len(batch["events"]) == 1


def test_push_to_reports_accepted(store):
    _populate(store)
    calls: list[Any] = []

    def sender(url, token, payload, timeout):
        calls.append((url, token, payload))
        return {"status": 200, "body": {
            "accepted": {
                "tasks": len(payload["tasks"]),
                "runs": len(payload["runs"]),
                "messages": len(payload["messages"]),
                "events": len(payload["events"]),
            }
        }}

    result = push_to(
        store, url="http://panel/api/ingest", token="t", agent="host-b", sender=sender
    )
    assert result["accepted"]["tasks"] == 1
    assert result["accepted"]["runs"] == 1
    assert result["accepted"]["messages"] == 1
    assert result["accepted"]["events"] == 1
    assert result["failures"] == []
    assert len(calls) == 1
    _, _, payload = calls[0]
    assert payload["agent"] == "host-b"


def test_push_to_continues_after_failed_batch(store):
    _populate(store)
    _populate(store)
    _populate(store)
    batch_size = 1
    seq = iter([200, 500, 200])

    def sender(url, token, payload, timeout):
        status = next(seq)
        if status == 200:
            return {"status": 200, "body": {"accepted": {"tasks": 1, "runs": 1,
                                                         "messages": 1, "events": 1}}}
        return {"status": 500, "body": {"error": "boom"}}

    result = push_to(
        store, url="http://panel/api/ingest", token="t", agent="host-b",
        batch_size=batch_size, sender=sender,
    )
    assert result["accepted"]["tasks"] == 2
    assert result["batches"] == 3
    assert len(result["failures"]) == 1
    assert "batch 2" in result["failures"][0]


def test_push_to_network_error_reported_not_raised(store):
    _populate(store)

    def sender(url, token, payload, timeout):
        raise PushError("connection refused")

    result = push_to(
        store, url="http://panel/api/ingest", token="t", agent="host-b", sender=sender
    )
    assert result["accepted"]["tasks"] == 0
    assert result["failures"] and "connection refused" in result["failures"][0]


# ---------------------------------------------------------------------------
# 4. ingest token is never a session credential
# ---------------------------------------------------------------------------


def test_ingest_token_not_a_session_credential():
    m = AuthManager(AuthConfig(cookie_signing_key="k"))
    req = Req(
        headers={"Authorization": "Bearer mdit-aaaa.bbbb"}, client_ip="127.0.0.1"
    )
    assert m.authenticate(req) is None


# ---------------------------------------------------------------------------
# 5. web /api/ingest endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def make_server(store):
    servers: list[tuple[Any, threading.Thread]] = []

    def _make(auth=_deny):
        server = create_server("127.0.0.1", 0, store, authenticator=auth)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server, server.server_address[1]

    yield _make

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post_bearer(port: int, path: str, payload: Any, token: str | None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(payload)
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()
    return resp.status, json.loads(raw) if raw else None


def _get_bearer(port: int, path: str, token: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers={"Authorization": "Bearer " + token})
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8")
    conn.close()
    return resp.status, json.loads(raw) if raw else None


def test_ingest_requires_token(make_server, store):
    _, port = make_server()
    status, body = _post_bearer(port, "/api/ingest", _batch(), None)
    assert status == 401
    status, body = _post_bearer(port, "/api/ingest", _batch(), "mdit-nope.aaaa")
    assert status == 401


def test_ingest_rejects_wrong_agent(make_server, store):
    _, plaintext = store.create_ingest_token("host-b")
    _, port = make_server()
    status, body = _post_bearer(port, "/api/ingest", _batch(agent="host-c"), plaintext)
    assert status == 403


def test_ingest_accepts_bound_agent(make_server, store):
    _, plaintext = store.create_ingest_token("host-b")
    _, port = make_server()
    status, body = _post_bearer(port, "/api/ingest", _batch(agent="host-b"), plaintext)
    assert status == 200
    assert body["accepted"] == {"tasks": 1, "runs": 1, "messages": 1, "events": 1}

    # Idempotent re-push.
    status, body = _post_bearer(port, "/api/ingest", _batch(agent="host-b"), plaintext)
    assert status == 200
    assert body["accepted"] == {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    assert len(store.list_tasks()) == 1


def test_ingest_response_serialized_with_scalar_event(make_server, store):
    # A batch whose event payload is a plain string must still return 200 with a
    # JSON-serialisable body; the write must never be reported as a 4xx.
    _, plaintext = store.create_ingest_token("host-b")
    _, port = make_server()
    status, body = _post_bearer(port, "/api/ingest", _raw_batch(), plaintext)
    assert status == 200
    assert body["accepted"] == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}
    assert body["errors"] == []
    assert _row_counts(store) == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}


def test_ingest_same_batch_twice_no_duplication(make_server, store):
    # The same (source_key-less) batch pushed twice must report zero accepted the
    # second time and leave every real row count unchanged.
    _, plaintext = store.create_ingest_token("host-b")
    _, port = make_server()

    status, body = _post_bearer(port, "/api/ingest", _raw_batch(), plaintext)
    assert status == 200
    assert body["accepted"] == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}

    status, body = _post_bearer(port, "/api/ingest", _raw_batch(), plaintext)
    assert status == 200
    assert body["accepted"] == {"tasks": 0, "runs": 0, "messages": 0, "events": 0}
    assert _row_counts(store) == {"tasks": 1, "runs": 1, "messages": 2, "events": 1}


def test_ingest_token_cannot_access_session_routes(make_server, store):
    _, plaintext = store.create_ingest_token("host-b")
    _, port = make_server(auth=_deny)

    # Read.
    assert _get_bearer(port, "/api/tasks", plaintext)[0] == 401
    assert _get_bearer(port, "/api/stats", plaintext)[0] == 401
    # Dispatch a task.
    assert _post_bearer(
        port, "/api/tasks", {"title": "t", "assignee": "x"}, plaintext
    )[0] == 401
    # Create an approval.
    assert _post_bearer(
        port, "/api/approvals", {"task_id": "t", "agent": "a", "command": "x"},
        plaintext,
    )[0] == 401
    # Decide an approval.
    assert _post_bearer(
        port, "/api/approvals/ap-20261003-000000/decide", {"decision": "approve"},
        plaintext,
    )[0] == 401


def test_ingest_does_not_use_session_auth(make_server, store):
    # Even with session auth deny-all, the ingest endpoint still accepts a
    # valid bearer token: the two paths are independent.
    _, plaintext = store.create_ingest_token("host-b")
    _, port = make_server(auth=_deny)
    status, _ = _post_bearer(port, "/api/ingest", _batch(agent="host-b"), plaintext)
    assert status == 200


# ---------------------------------------------------------------------------
# 6. CLI token commands
# ---------------------------------------------------------------------------


def test_cli_token_create_prints_plaintext_once(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    code = cli_main(["--db", db, "token", "create", "--agent", "host-b"])
    assert code == 0
    out = capsys.readouterr().out

    plaintext = [line for line in out.splitlines() if line.startswith("mdit-")]
    assert len(plaintext) == 1
    assert out.count(plaintext[0]) == 1  # printed exactly once


def test_cli_token_list_never_reveals_secret(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    cli_main(["--db", db, "token", "create", "--agent", "host-b"])
    capsys.readouterr()

    code = cli_main(["--db", db, "token", "list"])
    assert code == 0
    out = capsys.readouterr().out
    # The list shows the public id, not the secret half.
    assert "mdit-" in out
    assert "scrypt$" not in out


def test_cli_token_revoke(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    cli_main(["--db", db, "token", "create", "--agent", "host-b"])
    capsys.readouterr()
    store = Store(db)
    token_id = store.list_ingest_tokens()[0]["id"]

    code = cli_main(["--db", db, "token", "revoke", token_id])
    assert code == 0
    assert f"revoked token {token_id}" in capsys.readouterr().out

    # Revoking again fails cleanly.
    code = cli_main(["--db", db, "token", "revoke", token_id])
    assert code == 1
