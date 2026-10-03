"""Tests for phase 3 web layer: JSON API, auth gate, and SSE push."""

from __future__ import annotations

import http.client
import json
import threading
import time
from typing import Any

import pytest

from meshdispatch.store import Store
from meshdispatch.web.server import create_server


class StubIdentity:
    """Minimal stand-in for ``meshdispatch.auth.Identity``."""

    def __init__(
        self,
        principal: str = "alice",
        method: str = "stub",
        device_id: str | None = None,
    ) -> None:
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


@pytest.fixture
def make_server(store):
    servers: list[tuple[Any, threading.Thread]] = []

    def _make(auth=_allow):
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


def _get(port: int, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()
    return resp.status, json.loads(body) if body else None


def _get_raw(port: int, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    content_type = resp.getheader("Content-Type", "")
    conn.close()
    return resp.status, content_type, body


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


# ---------------------------------------------------------------------------
# 1. auth gate
# ---------------------------------------------------------------------------


def test_unauthenticated_request_returns_401(make_server, store):
    store.add_task(title="secret")
    _, port = make_server(auth=_deny)
    status, body = _get(port, "/api/tasks")
    assert status == 401
    assert body["error"]


def test_authenticated_request_succeeds(make_server, store):
    store.add_task(title="ok")
    _, port = make_server(auth=_allow)
    status, body = _get(port, "/api/tasks")
    assert status == 200
    assert isinstance(body, list)
    assert len(body) == 1


# ---------------------------------------------------------------------------
# 2. task list
# ---------------------------------------------------------------------------


def test_task_list_endpoint(make_server, store):
    store.add_task(title="cron-a", origin="cron", status="pending", assignee="x")
    store.add_task(title="a2a-b", origin="a2a", status="done", assignee="y")
    store.add_task(title="manual-c", origin="manual", status="pending", assignee="x")

    _, port = make_server()

    status, body = _get(port, "/api/tasks")
    assert status == 200
    assert len(body) == 3

    status, body = _get(port, "/api/tasks?status=pending")
    assert len(body) == 2

    status, body = _get(port, "/api/tasks?origin=a2a")
    assert len(body) == 1
    assert body[0]["title"] == "a2a-b"

    status, body = _get(port, "/api/tasks?assignee=x")
    assert len(body) == 2

    status, body = _get(port, "/api/tasks?status=bogus")
    assert status == 400


# ---------------------------------------------------------------------------
# 3. task detail
# ---------------------------------------------------------------------------


def test_task_detail_endpoint(make_server, store):
    tid = store.add_task(title="multi", coordination="multi", participants=["a", "b"])
    run = store.add_run_start(tid, agent="a")
    store.add_message(tid, author="a", body="hi", run_id=run["id"])
    store.add_event(tid, kind="handoff", payload={"from": "a", "to": "b"})

    _, port = make_server()

    status, body = _get(port, f"/api/tasks/{tid}")
    assert status == 200
    assert body["task"]["id"] == tid
    assert body["task"]["participants"] == ["a", "b"]
    assert len(body["runs"]) == 1
    assert len(body["messages"]) == 1
    assert len(body["events"]) == 1
    assert body["events"][0]["payload"] == {"from": "a", "to": "b"}


def test_task_detail_missing_returns_404(make_server):
    _, port = make_server()
    status, body = _get(port, "/api/tasks/md-00000000-000000")
    assert status == 404


# ---------------------------------------------------------------------------
# 4. stats
# ---------------------------------------------------------------------------


def test_stats_endpoint(make_server, store):
    store.add_task(title="a", origin="cron", status="pending")
    store.add_task(title="b", origin="cron", status="done")
    store.add_task(title="c", origin="manual", status="done")

    _, port = make_server()

    status, body = _get(port, "/api/stats")
    assert status == 200
    assert body["by_origin"] == {"cron": 2, "manual": 1}
    assert body["by_status"] == {"pending": 1, "done": 2}


# ---------------------------------------------------------------------------
# 5. SSE push
# ---------------------------------------------------------------------------


def _next_event(resp: http.client.HTTPResponse) -> tuple[str | None, dict[str, Any]]:
    """Read one SSE event (event type + parsed data) from ``resp``."""
    event_type: str | None = None
    data_lines: list[str] = []
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


def test_sse_emits_event_after_insert(make_server, store):
    _, port = make_server()

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/stream")
    resp = conn.getresponse()
    assert resp.status == 200
    assert "text/event-stream" in resp.getheader("Content-Type", "")

    event_type, _data = _next_event(resp)
    assert event_type == "hello"

    tid = store.add_task(title="sse-task")

    found: dict[str, Any] | None = None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        event_type, data = _next_event(resp)
        if event_type == "tasks" and tid in data.get("ids", []):
            found = data
            break
    conn.close()

    assert found is not None, "no SSE event observed within 5 seconds"
    assert found["table"] == "tasks"
    assert tid in found["ids"]


# ---------------------------------------------------------------------------
# 6. events payload + run summary redaction (phase 3 known-issue fix)
# ---------------------------------------------------------------------------


def test_event_payload_redacted(store):
    tid = store.add_task(title="leaky command")
    run = store.add_run_start(tid, agent="worker")

    ev = store.add_event(
        tid,
        kind="tool_call",
        payload={
            "command": "curl -H 'Authorization: Bearer abcdefghijklmnop' https://example",
            "env": {"API_KEY": "sk-abc123def456ghi789"},
        },
        run_id=run["id"],
    )

    assert ev["payload"]["command"] == "curl -H 'Authorization: [REDACTED]' https://example"
    assert ev["payload"]["env"]["API_KEY"] == "[REDACTED]"
    assert "abcdefghijklmnop" not in json.dumps(ev["payload"])
    assert "abc123def456ghi789" not in json.dumps(ev["payload"])


def test_run_summary_redacted(store):
    tid = store.add_task(title="leaky summary")
    run = store.add_run_start(tid, agent="worker")

    ended = store.add_run_end(run["id"], summary="deployed with ghp_ABCDEFGHIJKLMNOP token")

    assert ended["summary"] == "deployed with [REDACTED] token"
    assert "ABCDEFGHIJKLMNOP" not in ended["summary"]


def test_event_redaction_persisted(store):
    tid = store.add_task(title="persisted redaction")
    run = store.add_run_start(tid, agent="worker")
    store.add_event(
        tid,
        kind="tool_call",
        payload={"args": "login --token=superSecretValue123"},
        run_id=run["id"],
    )

    detail = store.get_task_detail(tid)
    stored = json.dumps(detail["events"][0]["payload"])
    assert "superSecretValue123" not in stored
    assert "[REDACTED]" in stored


# ---------------------------------------------------------------------------
# 7. static dashboard assets
# ---------------------------------------------------------------------------


def test_root_serves_dashboard(make_server):
    _, port = make_server()
    status, content_type, body = _get_raw(port, "/")
    assert status == 200
    assert content_type.startswith("text/html")
    assert b"meshdispatch" in body


def test_static_assets_served(make_server):
    _, port = make_server()
    status, content_type, body = _get_raw(port, "/static/app.js")
    assert status == 200
    assert content_type.startswith("application/javascript")
    assert b"EventSource" in body

    status, content_type, body = _get_raw(port, "/static/style.css")
    assert status == 200
    assert content_type.startswith("text/css")


def test_static_assets_require_auth(make_server):
    _, port = make_server(auth=_deny)
    status, _, _ = _get_raw(port, "/")
    assert status == 401


def test_static_path_traversal_blocked(make_server):
    _, port = make_server()
    status, _, _ = _get_raw(port, "/static/../store.py")
    assert status == 404


# ---------------------------------------------------------------------------
# 8. agent registry API
# ---------------------------------------------------------------------------


def test_agents_endpoint_lists_registered(make_server, store):
    store.add_agent(name="alpha", endpoint="http://a", transport="a2a")
    store.add_agent(name="beta", endpoint="http://b", transport="a2a", enabled=False)

    _, port = make_server()
    status, body = _get(port, "/api/agents")
    assert status == 200
    assert len(body) == 2
    by_name = {a["name"]: a for a in body}
    assert by_name["alpha"]["endpoint"] == "http://a"
    assert by_name["alpha"]["enabled"] is True
    assert by_name["beta"]["enabled"] is False


def test_agents_endpoint_requires_auth(make_server):
    _, port = make_server(auth=_deny)
    status, _ = _get(port, "/api/agents")
    assert status == 401


# ---------------------------------------------------------------------------
# 9. task dispatch API
# ---------------------------------------------------------------------------


def test_post_task_registers_only(make_server, store):
    store.add_agent(name="worker", endpoint="http://worker")
    _, port = make_server()

    status, body = _post(
        port,
        "/api/tasks",
        {
            "title": "deploy",
            "body": "ship it",
            "assignee": "worker",
            "coordination": "single",
            "dispatch": False,
        },
    )
    assert status == 201
    assert body["dispatched"] is False
    assert body["task"]["origin"] == "manual"
    assert body["task"]["assignee"] == "worker"
    assert body["task"]["status"] == "pending"

    _, tasks = _get(port, "/api/tasks")
    assert any(t["id"] == body["task"]["id"] for t in tasks)


def test_post_task_unknown_assignee_returns_400(make_server, store):
    _, port = make_server()
    status, body = _post(
        port,
        "/api/tasks",
        {"title": "t", "assignee": "ghost"},
    )
    assert status == 400
    assert "ghost" in body["error"]


def test_post_task_requires_auth(make_server, store):
    store.add_agent(name="worker", endpoint="http://worker")
    _, port = make_server(auth=_deny)
    status, _ = _post(
        port, "/api/tasks", {"title": "t", "assignee": "worker"}
    )
    assert status == 401


def test_post_task_transport_failure_surfaces_as_failed_task(make_server, store):
    # Point at a closed port so the default A2A transport fails fast; the
    # request must still succeed (201) with the task recorded as failed rather
    # than an exception escaping to a 500.
    store.add_agent(name="worker", endpoint="http://127.0.0.1:1")
    _, port = make_server()

    status, body = _post(
        port,
        "/api/tasks",
        {"title": "deploy", "assignee": "worker"},
    )
    assert status == 201
    assert body["dispatched"] is True
    assert body["task"]["status"] == "failed"

    detail = store.get_task_detail(body["task"]["id"])
    assert len(detail["runs"]) == 1
    assert detail["runs"][0]["status"] == "failed"
    assert len(detail["events"]) == 1
    assert detail["events"][0]["kind"] == "dispatch_failed"
