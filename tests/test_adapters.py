"""Tests for phase 2: redaction, schema migration, and the three adapters."""

from __future__ import annotations

import json
import sqlite3

import pytest

from meshdispatch import models
from meshdispatch.adapters.a2a import A2AAdapter, infer_peer
from meshdispatch.adapters.hermes_cron import CronAdapter
from meshdispatch.adapters.hermes_subagent import SubagentAdapter
from meshdispatch.redact import REDACTED, redact
from meshdispatch.registry import Registry
from meshdispatch.store import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


@pytest.fixture
def registry(store):
    return Registry(store)


# ---------------------------------------------------------------------------
# 1. redaction
# ---------------------------------------------------------------------------


def test_redact_credential_shapes():
    sample = (
        "api key sk-abc123def456ghi789 and github token gho_ABCDEFGHIJKLMNOP. "
        "header: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123def. "
        "env TOKEN=superSecretValue123, API_KEY: my-api-key-12345, "
        "password= hunter2secret, slack " "xox" "b-123456789012-abcdefghijklmnop"
    )
    out = redact(sample)
    assert REDACTED in out
    for secret in (
        "abc123def456ghi789",
        "ABCDEFGHIJKLMNOP",
        "eyJhbGciOiJIUzI1NiJ9",
        "superSecretValue123",
        "my-api-key-12345",
        "hunter2secret",
        "123456789012",
    ):
        assert secret not in out, secret


def test_redact_preserves_non_secrets():
    # "task-<hex>" contains the substring "sk-" but must not be mangled.
    text = "task-000c5a82c77d4e3b completed; tokens are fine; plain prose stays."
    out = redact(text)
    assert "task-000c5a82c77d4e3b" in out
    assert "plain prose stays" in out


def test_redact_idempotent():
    text = "key sk-abc123def456"
    once = redact(text)
    twice = redact(once)
    assert once == twice


# ---------------------------------------------------------------------------
# 2. schema migration (old DB and new DB, repeatable)
# ---------------------------------------------------------------------------

_PHASE1_SCHEMA = """
CREATE TABLE tasks (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT, origin TEXT NOT NULL,
    origin_ref TEXT, assignee TEXT, coordination TEXT NOT NULL,
    participants TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_run_at TEXT, result TEXT
);
CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
    agent TEXT, status TEXT NOT NULL, started_at TEXT, ended_at TEXT,
    outcome TEXT, summary TEXT, error_type TEXT
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
    run_id INTEGER, author TEXT NOT NULL, author_kind TEXT NOT NULL,
    body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
    run_id INTEGER, kind TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
"""


def _columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def test_migration_upgrades_old_db(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(_PHASE1_SCHEMA)
    conn.commit()
    conn.close()

    store = Store(path)
    # Opening triggers the migration; re-open to prove idempotence.
    store.connect().close()
    store.connect().close()

    conn = sqlite3.connect(path)
    assert "visibility" in _columns(conn, "messages")
    assert "source_key" in _columns(conn, "runs")
    assert "source_key" in _columns(conn, "messages")
    assert "source_key" in _columns(conn, "events")
    conn.close()


def test_new_db_has_columns_and_repeatable(tmp_path):
    store = Store(tmp_path / "new.db")
    conn = store.connect()
    try:
        assert "visibility" in _columns(conn, "messages")
        assert "source_key" in _columns(conn, "runs")
        assert "source_key" in _columns(conn, "messages")
        assert "source_key" in _columns(conn, "events")
    finally:
        conn.close()
    # Re-opening must not error (idempotent migration).
    store.connect().close()
    store.connect().close()


def test_messages_default_visibility(store):
    tid = store.add_task(title="x")
    msg = store.add_message(tid, author="a", body="b")
    assert msg["visibility"] == "local"


def test_invalid_visibility_rejected(store):
    tid = store.add_task(title="x")
    with pytest.raises(ValueError):
        store.add_message(tid, author="a", body="b", visibility="public-oops")


# ---------------------------------------------------------------------------
# 3. cron adapter
# ---------------------------------------------------------------------------


def _make_executions_db(path, executions, incidents):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE executions (
            id TEXT PRIMARY KEY, job_id TEXT NOT NULL, source TEXT NOT NULL,
            process_id TEXT NOT NULL, pid INTEGER NOT NULL, process_started_at INTEGER,
            status TEXT NOT NULL, handoff_pending INTEGER NOT NULL DEFAULT 0,
            handoff_started_at REAL, claimed_at TEXT NOT NULL, started_at TEXT,
            finished_at TEXT, error TEXT, delivery_outcome TEXT, scheduled_instant TEXT
        );
        CREATE TABLE cron_incidents (
            id TEXT PRIMARY KEY, job_id TEXT NOT NULL, error_sig TEXT NOT NULL,
            state TEXT NOT NULL, failure_type TEXT NOT NULL DEFAULT 'unknown',
            first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, acked_at TEXT,
            alerted_at TEXT, closed_at TEXT, error TEXT NOT NULL, output_file TEXT
        );
        """
    )
    conn.executemany(
        "INSERT INTO executions (id, job_id, source, process_id, pid, status, "
        "claimed_at, started_at, finished_at, error, delivery_outcome) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        executions,
    )
    conn.executemany(
        "INSERT INTO cron_incidents (id, job_id, error_sig, state, failure_type, "
        "first_seen_at, last_seen_at, error) VALUES (?,?,?,?,?,?,?,?)",
        incidents,
    )
    conn.commit()
    conn.close()


def test_cron_adapter_sync_and_idempotent(tmp_path, registry):
    jobs_path = tmp_path / "jobs.json"
    jobs_path.write_text(
        json.dumps(
            {
                "jobs": [
                    {"id": "job1", "name": "Backup daily"},
                    {"id": "job2", "name": "Cleanup weekly"},
                ]
            }
        ),
        encoding="utf-8",
    )
    ex_path = tmp_path / "executions.db"
    _make_executions_db(
        ex_path,
        executions=[
            ("ex1", "job1", "builtin", "p1", 1, "completed",
             "2026-10-01T10:00:00+00:00", "2026-10-01T10:00:01+00:00",
             "2026-10-01T10:00:05+00:00", None, "delivered"),
            ("ex2", "job1", "builtin", "p2", 2, "failed",
             "2026-10-02T10:00:00+00:00", "2026-10-02T10:00:01+00:00",
             "2026-10-02T10:00:03+00:00", "SomeError: boom traceback", None),
            ("ex3", "job2", "direct", "p3", 3, "completed",
             "2026-10-03T10:00:00+00:00", "2026-10-03T10:00:01+00:00",
             "2026-10-03T10:00:02+00:00", None, "suppressed"),
            # orphaned execution (job no longer in definitions) -> skipped
            ("ex4", "job-gone", "direct", "p4", 4, "completed",
             "2026-10-04T10:00:00+00:00", "2026-10-04T10:00:01+00:00",
             "2026-10-04T10:00:02+00:00", None, None),
        ],
        incidents=[
            ("inc1", "job1", "sig", "open", "timeout",
             "2026-10-02T10:00:03+00:00", "2026-10-02T10:00:03+00:00", "boom"),
        ],
    )

    adapter = CronAdapter(jobs_path=jobs_path, executions_path=ex_path, assignee="host-a")
    stats = adapter.sync(registry)

    assert stats.tasks_new == 2
    assert stats.runs_new == 3
    assert stats.runs_skipped == 1  # orphan

    tasks = registry.store.list_tasks(origin="cron")
    assert len(tasks) == 2
    by_ref = {t["origin_ref"]: t for t in tasks}
    assert by_ref["job1"]["title"] == "Backup daily"
    assert by_ref["job1"]["assignee"] == "host-a"
    assert by_ref["job1"]["coordination"] == "single"

    detail = registry.store.get_task_detail(by_ref["job1"]["id"])
    runs = detail["runs"]
    assert len(runs) == 2
    failed = [r for r in runs if r["status"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["error_type"] == "timeout"
    # raw error text is never persisted anywhere
    assert all("SomeError" not in (r["summary"] or "") for r in runs)

    # Idempotent re-sync: nothing new.
    stats2 = adapter.sync(registry)
    assert stats2.tasks_new == 0
    assert stats2.runs_new == 0
    assert stats2.tasks_skipped == 2
    assert stats2.runs_skipped == 4


# ---------------------------------------------------------------------------
# 4. subagent adapter
# ---------------------------------------------------------------------------


def _make_delegation(tmp_path, deleg_id, goal, started, completed, trace_lines):
    live = tmp_path / "live" / deleg_id
    live.mkdir(parents=True)
    (live / "manifest.json").write_text(
        json.dumps(
            {
                "delegation_id": deleg_id,
                "started": started,
                "completed": completed,
                "tasks": [
                    {"index": 0, "goal": goal, "status": "completed",
                     "exit_reason": "completed"}
                ],
            }
        ),
        encoding="utf-8",
    )
    header = (
        f"=== Hermes subagent live transcript ===\n"
        f"delegation: {deleg_id}   task: 0\n"
        f"goal: {goal}\n"
        f"started: {started}\n"
        f"(append-only)\n"
        f"========================================\n"
    )
    (live / "task-0.log").write_text(header + "\n".join(trace_lines) + "\n", encoding="utf-8")
    return live


def test_subagent_adapter_sync_and_idempotent(tmp_path, registry):
    _make_delegation(
        tmp_path,
        "deleg_test1",
        goal="Implement the thing",
        started="2026-10-02 12:00:00",
        completed="2026-10-02 12:00:07",
        trace_lines=[
            "12:00:01 user     | kickoff: Implement the thing | context: go",
            "12:00:02 start    | Implement the thing",
            "12:00:03 tool     | -> terminal(ls -la)",
            "12:00:04 result   | terminal ok 0.1s: {\"output\": \"secret sk-abc123def456\"}",
            "12:00:05 assistant| Done. key sk-abc123def456 was used.",
            "12:00:06 think    | internal reasoning to drop",
            "12:00:07 final    | status=completed duration=5.00s summary: ok",
            "12:00:07 final    | end status=completed exit_reason=completed",
        ],
    )

    adapter = SubagentAdapter(delegation_dir=tmp_path, assignee="host-a")
    stats = adapter.sync(registry)

    assert stats.tasks_new == 1
    assert stats.runs_new == 1
    assert stats.messages_new == 4  # user + assistant + 2x final (think dropped)
    assert stats.events_new == 3  # start + tool_call + tool_result

    task = registry.store.list_tasks(origin="subagent")[0]
    assert task["origin_ref"] == "deleg_test1"
    assert task["title"] == "Implement the thing"
    assert task["coordination"] == "single"

    detail = registry.store.get_task_detail(task["id"])
    assert len(detail["runs"]) == 1
    assert detail["runs"][0]["status"] == "done"

    bodies = " ".join(m["body"] for m in detail["messages"])
    assert "sk-abc123def456" not in bodies  # redacted

    kinds = {e["kind"] for e in detail["events"]}
    assert kinds == {"start", "tool_call", "tool_result"}

    # Idempotent re-sync.
    stats2 = adapter.sync(registry)
    assert stats2.tasks_new == 0
    assert stats2.runs_new == 0
    assert stats2.messages_new == 0
    assert stats2.events_new == 0


# ---------------------------------------------------------------------------
# 5. a2a adapter
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path, ctx_id, lines):
    (tmp_path / f"ctx-{ctx_id}.jsonl").write_text(
        "\n".join(json.dumps(ln) for ln in lines) + "\n", encoding="utf-8"
    )


def test_a2a_adapter_sync_and_idempotent(tmp_path, registry):
    _make_ctx(
        tmp_path,
        "00d3e1ad4c474576",
        [
            {"ts": 1790767227.5, "role": "user",
             "text": "Please download the model", "task_id": "task-1"},
            {"ts": 1790767240.6, "role": "agent",
             "text": "[A2A inbound — 来自 aliyun] done, token ghp_ABC123XYZ987654",
             "task_id": "task-1"},
        ],
    )

    adapter = A2AAdapter(conversations_dir=tmp_path, local_name="daifamily")
    stats = adapter.sync(registry)

    assert stats.tasks_new == 1
    assert stats.messages_new == 2

    task = registry.store.list_tasks(origin="a2a")[0]
    assert task["origin_ref"] == "00d3e1ad4c474576"
    assert task["coordination"] == "multi"
    # peer inferred as aliyun; local always present.
    assert task["participants"] == ["daifamily", "aliyun"]

    detail = registry.store.get_task_detail(task["id"])
    bodies = " ".join(m["body"] for m in detail["messages"])
    assert "ABC123XYZ987654" not in bodies  # redacted
    assert all(m["author_kind"] == "agent" for m in detail["messages"])

    stats2 = adapter.sync(registry)
    assert stats2.tasks_new == 0
    assert stats2.messages_new == 0


def test_infer_peer_variants():
    assert infer_peer("A2A_TRUSTED_PEERS=aliyun-beijing", "daifamily") == "aliyun-beijing"
    assert infer_peer("来源 a2a / aliyun-beijing", "daifamily") == "aliyun-beijing"
    # "来自 daifamily" equals the local name -> filtered -> None.
    assert infer_peer("[A2A inbound — 来自 daifamily]", "daifamily") is None
    # Ambiguous (two distinct candidates) -> None.
    assert infer_peer("A2A_TRUSTED_PEERS=a,b", "daifamily") is None
    assert infer_peer("", "daifamily") is None
