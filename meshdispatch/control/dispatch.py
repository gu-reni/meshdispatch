"""Manual task dispatch (phase 4a).

The owner creates a task from the dashboard and assigns it to an agent chosen
from the registry.  Dispatch is the first write path that can make an agent
*do something*, so it is deliberately conservative:

* every assignee/participant is resolved against the agent registry **before**
  any task is created, and an unregistered name aborts with
  :class:`UnknownAgent` -- a task is never created for an agent that does not
  exist;
* the outbound call travels over A2A JSON-RPC through an injectable
  :class:`Transport`, so the whole path is testable without a live peer;
* the transport is given a timeout and any transport failure (including a
  timeout) is recorded as a *failed* run + event and folded into the task
  status, never raised out to the HTTP handler.

Standard library only; no dependency on Hermes or any third-party package.
"""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from typing import Any, Iterable, Protocol

from .. import models
from ..store import Store

#: Default per-call timeout for the outbound A2A transport (seconds).
DEFAULT_TIMEOUT = 10.0


class UnknownAgent(ValueError):
    """Raised when an assignee or participant is not in the agent registry."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"unknown agent: {name}")


class Transport(Protocol):
    """An injectable outbound dispatch transport.

    ``send`` posts ``request`` to ``endpoint`` and returns the decoded JSON
    response, honouring ``timeout``.  It must raise (e.g. ``TimeoutError``)
    rather than block forever.
    """

    def send(
        self, endpoint: str, request: dict[str, Any], timeout: float
    ) -> dict[str, Any]: ...


class A2ATransport:
    """Default A2A JSON-RPC transport over HTTP (stdlib ``urllib``)."""

    def send(
        self, endpoint: str, request: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        if not endpoint:
            raise ValueError("no endpoint configured")
        payload = json.dumps(request, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
        except TimeoutError as exc:
            raise TimeoutError(f"timed out after {timeout}s") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise TimeoutError(f"timed out after {timeout}s") from exc
            raise
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))


def _as_list(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _build_request(
    task_id: str,
    title: str,
    body: str | None,
    assignee: str,
    coordination: str,
    participants: list[str],
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": secrets.token_hex(8),
        "method": "tasks/send",
        "params": {
            "task": {
                "id": task_id,
                "title": title,
                "body": body or "",
                "assignee": assignee,
                "coordination": coordination,
                "participants": participants,
            }
        },
    }


def _safe_result(response: Any) -> Any:
    if response is None or isinstance(response, (dict, list, str, int, float, bool)):
        return response
    return str(response)


def dispatch(
    store: Store,
    *,
    title: str,
    assignee: str,
    body: str | None = None,
    coordination: models.Coordination | str = models.Coordination.SINGLE,
    participants: Iterable[str] | None = None,
    send: bool = True,
    transport: Transport | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Create a manual task and (optionally) dispatch it to its assignee.

    Returns ``{"task": ..., "dispatched": bool, "run": run | None}``.

    Raises :class:`UnknownAgent` when the assignee or any participant is not in
    the registry (before anything is created).  Transport problems never
    propagate: they are recorded as a failed run and reflected in the task
    status.
    """
    coord_v = models.coerce_enum(coordination, models.Coordination, "coordination")
    assignee = (assignee or "").strip()
    if not assignee:
        raise ValueError("assignee is required")
    parts = _as_list(participants)

    # Resolve every named agent up-front so a task is never created for an
    # agent that does not exist.
    names: list[str] = []
    for raw in [assignee, *parts]:
        name = raw.strip()
        if name and name not in names:
            names.append(name)
    agents: dict[str, dict[str, Any]] = {}
    for name in names:
        agent = store.get_agent(name)
        if agent is None:
            raise UnknownAgent(name)
        agents[name] = agent

    task_id = store.add_task(
        title=title,
        body=body,
        origin=models.Origin.MANUAL,
        assignee=assignee,
        coordination=coord_v,
        participants=parts,
        status=models.Status.PENDING,
    )

    if not send:
        return {"task": store.get_task(task_id), "dispatched": False, "run": None}

    agent = agents[assignee]
    run = store.add_run_start(task_id, agent=assignee)
    request = _build_request(task_id, title, body, assignee, coord_v, parts)

    outcome: str
    error_type: str | None
    summary: str
    response: Any = None

    try:
        chosen = transport if transport is not None else A2ATransport()
        response = chosen.send(agent.get("endpoint"), request, timeout)
    except TimeoutError as exc:
        outcome, error_type, summary = "failed", "timeout", str(exc)
    except Exception as exc:  # noqa: BLE001 - surface as a failed run, never raise
        outcome, error_type, summary = "failed", "transport", str(exc)
    else:
        if isinstance(response, dict) and response.get("error"):
            outcome, error_type, summary = (
                "failed",
                "remote",
                json.dumps(response["error"], ensure_ascii=False),
            )
        else:
            outcome, error_type, summary = "accepted", None, "task dispatched"

    if error_type is None:
        store.add_event(
            task_id,
            kind="dispatch",
            payload={
                "assignee": assignee,
                "outcome": outcome,
                "response": _safe_result(response),
            },
            run_id=run["id"],
        )
        ended = store.add_run_end(
            run["id"], status=models.Status.DONE, outcome=outcome, summary=summary
        )
    else:
        store.add_event(
            task_id,
            kind="dispatch_failed",
            payload={"assignee": assignee, "error": summary, "error_type": error_type},
            run_id=run["id"],
        )
        ended = store.add_run_end(
            run["id"],
            status=models.Status.FAILED,
            outcome=outcome,
            summary=summary,
            error_type=error_type,
        )

    return {
        "task": store.get_task(task_id),
        "dispatched": True,
        "run": ended,
    }


__all__ = [
    "A2ATransport",
    "DEFAULT_TIMEOUT",
    "Transport",
    "UnknownAgent",
    "dispatch",
]
