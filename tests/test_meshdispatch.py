"""Tests for meshdispatch phase 1: model, store, registry."""

from __future__ import annotations

import datetime
import re
import sqlite3

import pytest

from meshdispatch import models
from meshdispatch.registry import Registry
from meshdispatch.store import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


# -- 1. task id format + uniqueness --------------------------------------


def test_task_id_format_and_uniqueness():
    ids = {models.generate_task_id() for _ in range(1000)}
    assert len(ids) == 1000
    pattern = re.compile(r"^md-\d{8}-[0-9a-f]{6}$")
    for tid in ids:
        assert pattern.match(tid), tid


def test_add_task_id_matches_format(store):
    tid = store.add_task(title="hello")
    assert re.match(r"^md-\d{8}-[0-9a-f]{6}$", tid)


# -- 2. origin + origin_ref idempotency -----------------------------------


def test_origin_ref_idempotent(store):
    reg = Registry(store)
    t1, created1 = reg.register(title="job", origin="cron", origin_ref="daily-backup")
    t2, created2 = reg.register(
        title="job again", origin="cron", origin_ref="daily-backup"
    )
    assert created1 is True
    assert created2 is False
    assert t1["id"] == t2["id"]
    assert len(store.list_tasks()) == 1


def test_no_origin_ref_is_not_idempotent(store):
    reg = Registry(store)
    t1, c1 = reg.register(title="a", origin="manual")
    t2, c2 = reg.register(title="b", origin="manual")
    assert c1 and c2
    assert t1["id"] != t2["id"]


# -- 3. timestamp normalization to UTC ISO 8601 ---------------------------


def test_normalize_ts_utc_z():
    assert models.normalize_ts("2026-10-02T12:00:00+08:00") == "2026-10-02T04:00:00Z"
    assert models.normalize_ts("2026-10-02T04:00:00Z") == "2026-10-02T04:00:00Z"
    assert models.normalize_ts("2026-10-02T04:00:00") == "2026-10-02T04:00:00Z"
    dt = datetime.datetime(2026, 10, 2, 4, 0, 0)
    assert models.normalize_ts(dt) == "2026-10-02T04:00:00Z"
    assert models.normalize_ts("") is None
    assert models.normalize_ts(None) is None


def test_store_timestamps_normalized(store):
    tid = store.add_task(title="ts")
    t = store.get_task(tid)
    assert t["created_at"].endswith("Z")
    assert t["updated_at"].endswith("Z")


# -- 4. invalid enum values rejected (four fields) ------------------------


@pytest.mark.parametrize("bad", ["", "bogus", "CRON", "Cron", 1])
def test_invalid_origin_rejected(store, bad):
    with pytest.raises(ValueError):
        store.add_task(title="x", origin=bad)


def test_null_origin_rejected(store):
    # origin is NOT NULL; a missing origin is rejected by the schema.
    with pytest.raises(sqlite3.IntegrityError):
        store.add_task(title="x", origin=None)


@pytest.mark.parametrize("bad", ["", "many", "MULTI", 2])
def test_invalid_coordination_rejected(store, bad):
    with pytest.raises(ValueError):
        store.add_task(title="x", coordination=bad)


@pytest.mark.parametrize("bad", ["", "unknown", "DONE", 3])
def test_invalid_status_rejected(store, bad):
    with pytest.raises(ValueError):
        store.add_task(title="x", status=bad)


def test_invalid_author_kind_rejected(store):
    tid = store.add_task(title="x")
    with pytest.raises(ValueError):
        store.add_message(tid, author="a", author_kind="robot")


# -- 5. foreign key constraints enforced ----------------------------------


def test_foreign_key_enforced(store):
    missing = "md-20261002-ffffff"
    with pytest.raises(sqlite3.IntegrityError):
        store.add_run_start(missing, agent="x")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_message(missing, author="a", body="b")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_event(missing, kind="k")


def test_wal_and_foreign_keys_pragma(store):
    conn = store.connect()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()


# -- 6. show returns associated runs/messages/events ----------------------


def test_show_returns_relations(store):
    tid = store.add_task(
        title="multi", coordination="multi", participants=["alice", "bob"]
    )
    r1 = store.add_run_start(tid, agent="alice")
    r2 = store.add_run_start(tid, agent="bob")
    store.add_message(tid, author="alice", body="hi bob", run_id=r1["id"])
    store.add_message(tid, author="bob", body="hi alice", run_id=r1["id"])
    store.add_message(tid, author="system", author_kind="system", body="synced")
    store.add_event(tid, kind="handoff", payload={"from": "alice", "to": "bob"}, run_id=r1["id"])
    store.add_event(tid, kind="milestone", payload={"done": True})

    detail = store.get_task_detail(tid)
    assert detail is not None
    assert len(detail["runs"]) == 2
    assert len(detail["messages"]) == 3
    assert len(detail["events"]) == 2
    assert detail["task"]["id"] == tid
    assert detail["task"]["participants"] == ["alice", "bob"]
    assert detail["events"][0]["payload"] == {"from": "alice", "to": "bob"}
    assert {r["agent"] for r in detail["runs"]} == {"alice", "bob"}


# -- 7. message append then read back -------------------------------------


def test_message_readback(store):
    tid = store.add_task(title="chat")
    store.add_message(tid, author="agent-a", author_kind="agent", body="ping")
    msgs = store.list_messages(tid)
    assert len(msgs) == 1
    assert msgs[0]["body"] == "ping"
    assert msgs[0]["author"] == "agent-a"
    assert msgs[0]["author_kind"] == "agent"
    assert msgs[0]["task_id"] == tid
    assert msgs[0]["created_at"].endswith("Z")


# -- list filters ---------------------------------------------------------


def test_list_filters(store):
    store.add_task(title="cron-a", origin="cron", status="pending", assignee="x")
    store.add_task(title="a2a-b", origin="a2a", status="done", assignee="y")
    store.add_task(title="manual-c", origin="manual", status="pending", assignee="x")

    assert len(store.list_tasks()) == 3
    assert len(store.list_tasks(status="pending")) == 2
    assert len(store.list_tasks(origin="a2a")) == 1
    assert len(store.list_tasks(assignee="x")) == 2
