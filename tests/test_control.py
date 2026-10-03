"""Tests for phase 4a: agent registry and manual task dispatch."""

from __future__ import annotations

import pytest

from meshdispatch.control.dispatch import A2ATransport, UnknownAgent, dispatch
from meshdispatch.store import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


class RecordingTransport:
    """Captures the outbound request and returns a canned response."""

    def __init__(self, response=None, error=None):
        self.response = response if response is not None else {"result": {"ok": True}}
        self.error = error
        self.calls = []

    def send(self, endpoint, request, timeout):
        self.calls.append((endpoint, request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


class TimeoutTransport:
    def send(self, endpoint, request, timeout):
        raise TimeoutError("slow peer")


# ---------------------------------------------------------------------------
# agent registry
# ---------------------------------------------------------------------------


def test_add_agent_round_trip(store):
    agent = store.add_agent(
        name="aliyun-beijing",
        description="bj worker",
        endpoint="http://host:9900",
        transport="a2a",
        enabled=True,
    )
    assert agent["name"] == "aliyun-beijing"
    assert agent["description"] == "bj worker"
    assert agent["endpoint"] == "http://host:9900"
    assert agent["transport"] == "a2a"
    assert agent["enabled"] is True

    got = store.get_agent("aliyun-beijing")
    assert got == agent


def test_add_agent_idempotent_by_name(store):
    store.add_agent(name="a", endpoint="http://one")
    store.add_agent(name="a", endpoint="http://two", enabled=False)

    agents = store.list_agents()
    assert len(agents) == 1
    assert agents[0]["name"] == "a"
    assert agents[0]["endpoint"] == "http://two"
    assert agents[0]["enabled"] is False


def test_list_agents_sorted_and_defaults(store):
    store.add_agent(name="zeta")
    store.add_agent(name="alpha", transport="a2a")
    names = [a["name"] for a in store.list_agents()]
    assert names == ["alpha", "zeta"]
    for agent in store.list_agents():
        assert agent["transport"] == "a2a"
        assert agent["enabled"] is True


def test_get_agent_missing_returns_none(store):
    assert store.get_agent("ghost") is None


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------


def test_unknown_assignee_raises_and_creates_nothing(store):
    with pytest.raises(UnknownAgent) as exc:
        dispatch(store, title="t", assignee="ghost")
    assert exc.value.name == "ghost"
    assert "ghost" in str(exc.value)
    assert store.list_tasks() == []


def test_unknown_participant_raises_and_creates_nothing(store):
    store.add_agent(name="lead", endpoint="http://lead")
    with pytest.raises(UnknownAgent) as exc:
        dispatch(
            store,
            title="t",
            assignee="lead",
            coordination="multi",
            participants=["lead", "missing"],
        )
    assert exc.value.name == "missing"
    assert store.list_tasks() == []


def test_missing_assignee_rejected(store):
    with pytest.raises(ValueError):
        dispatch(store, title="t", assignee="  ")


def test_dispatch_creates_task_and_records_success(store):
    store.add_agent(name="worker", endpoint="http://worker:9900")
    transport = RecordingTransport()

    result = dispatch(store, title="deploy", body="ship it", assignee="worker", transport=transport)

    assert result["dispatched"] is True
    task = result["task"]
    assert task["origin"] == "manual"
    assert task["assignee"] == "worker"
    assert task["coordination"] == "single"
    assert task["status"] == "done"
    assert task["result"] == "accepted"

    run = result["run"]
    assert run["status"] == "done"
    assert run["agent"] == "worker"
    assert run["outcome"] == "accepted"

    # the outbound request reached the transport with the agent's endpoint
    assert len(transport.calls) == 1
    endpoint, request, timeout = transport.calls[0]
    assert endpoint == "http://worker:9900"
    assert request["method"] == "tasks/send"
    assert request["params"]["task"]["id"] == task["id"]

    detail = store.get_task_detail(task["id"])
    assert len(detail["runs"]) == 1
    assert len(detail["events"]) == 1
    assert detail["events"][0]["kind"] == "dispatch"


def test_dispatch_multi_records_participants(store):
    store.add_agent(name="lead", endpoint="http://lead")
    store.add_agent(name="peer", endpoint="http://peer")
    transport = RecordingTransport()

    result = dispatch(
        store,
        title="pair",
        assignee="lead",
        coordination="multi",
        participants=["lead", "peer"],
        transport=transport,
    )

    assert result["task"]["coordination"] == "multi"
    assert result["task"]["participants"] == ["lead", "peer"]
    assert result["task"]["status"] == "done"


def test_dispatch_false_registers_without_sending(store):
    store.add_agent(name="worker", endpoint="http://worker")
    transport = RecordingTransport()

    result = dispatch(
        store, title="later", assignee="worker", send=False, transport=transport
    )

    assert result["dispatched"] is False
    assert result["run"] is None
    assert result["task"]["status"] == "pending"
    assert transport.calls == []

    detail = store.get_task_detail(result["task"]["id"])
    assert detail["runs"] == []


def test_dispatch_timeout_records_failed_run(store):
    store.add_agent(name="slow", endpoint="http://slow")

    result = dispatch(store, title="t", assignee="slow", transport=TimeoutTransport())

    assert result["dispatched"] is True
    assert result["task"]["status"] == "failed"
    assert result["run"]["status"] == "failed"
    assert result["run"]["error_type"] == "timeout"

    detail = store.get_task_detail(result["task"]["id"])
    assert detail["events"][0]["kind"] == "dispatch_failed"
    assert detail["events"][0]["payload"]["error_type"] == "timeout"


def test_dispatch_transport_error_records_failed_run(store):
    store.add_agent(name="bad", endpoint="http://bad")
    transport = RecordingTransport(error=RuntimeError("boom"))

    result = dispatch(store, title="t", assignee="bad", transport=transport)

    assert result["task"]["status"] == "failed"
    assert result["run"]["status"] == "failed"
    assert result["run"]["error_type"] == "transport"


def test_dispatch_remote_error_records_failed_run(store):
    store.add_agent(name="remote", endpoint="http://remote")
    transport = RecordingTransport(response={"error": {"code": -1, "message": "nope"}})

    result = dispatch(store, title="t", assignee="remote", transport=transport)

    assert result["task"]["status"] == "failed"
    assert result["run"]["error_type"] == "remote"


def test_a2a_transport_requires_endpoint():
    transport = A2ATransport()
    with pytest.raises(ValueError):
        transport.send("", {"jsonrpc": "2.0"}, 1.0)
