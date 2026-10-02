"""Command-line interface for meshdispatch.

Human-readable tables/indented text by default; ``--json`` emits
machine-readable JSON.  No secrets ever appear in output.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import Any, Sequence

from . import models
from .registry import Registry
from .store import Store


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meshdispatch",
        description="Cross-server multi-agent task scheduling and observability (A2A).",
    )
    p.add_argument(
        "--db",
        default=None,
        help="SQLite path (default: $MESHDISPATCH_DB or ./meshdispatch.db)",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    add = sub.add_parser("add", help="Register a new task")
    add.add_argument("--title", required=True, help="task title (required)")
    add.add_argument("--body")
    add.add_argument(
        "--origin",
        choices=[o.value for o in models.Origin],
        default=models.Origin.MANUAL.value,
    )
    add.add_argument("--origin-ref", dest="origin_ref")
    add.add_argument("--assignee")
    add.add_argument(
        "--coordination",
        choices=[c.value for c in models.Coordination],
        default=models.Coordination.SINGLE.value,
    )
    add.add_argument("--participants", help="comma-separated list of agents")
    add.add_argument("--json", action="store_true")

    lst = sub.add_parser("list", help="List tasks")
    lst.add_argument("--status", choices=[s.value for s in models.Status])
    lst.add_argument("--origin", choices=[o.value for o in models.Origin])
    lst.add_argument("--assignee")
    lst.add_argument("--json", action="store_true")

    show = sub.add_parser("show", help="Show a task with its runs/messages/events")
    show.add_argument("id")
    show.add_argument("--json", action="store_true")

    rs = sub.add_parser("run-start", help="Record the start of a run")
    rs.add_argument("id", help="task id")
    rs.add_argument("--agent", required=True)
    rs.add_argument("--json", action="store_true")

    re_ = sub.add_parser("run-end", help="Record the end of a run")
    re_.add_argument("run_id", type=int, help="run id")
    re_.add_argument(
        "--status", choices=["done", "failed", "cancelled", "blocked"], default="done"
    )
    re_.add_argument("--outcome")
    re_.add_argument("--summary")
    re_.add_argument("--error-type", dest="error_type")
    re_.add_argument("--json", action="store_true")

    msg = sub.add_parser("message", help="Append a message to a task")
    msgsub = msg.add_subparsers(dest="message_command", required=True)
    madd = msgsub.add_parser("add", help="Append a message")
    madd.add_argument("id", help="task id")
    madd.add_argument("--author", required=True)
    madd.add_argument(
        "--author-kind",
        dest="author_kind",
        choices=[k.value for k in models.AuthorKind],
        default=models.AuthorKind.AGENT.value,
    )
    madd.add_argument("--body", required=True)
    madd.add_argument("--run-id", dest="run_id", type=int)
    madd.add_argument("--json", action="store_true")

    ev = sub.add_parser("event", help="Append an event to a task")
    evsub = ev.add_subparsers(dest="event_command", required=True)
    eadd = evsub.add_parser("add", help="Append an event")
    eadd.add_argument("id", help="task id")
    eadd.add_argument("--kind", required=True)
    eadd.add_argument("--payload", help="JSON object string")
    eadd.add_argument("--run-id", dest="run_id", type=int)
    eadd.add_argument("--json", action="store_true")

    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_participants(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_payload(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid --payload JSON: {exc}") from exc


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    rows = [[str(c) for c in row] for row in rows]
    widths = [
        max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)
    ]

    def fmt(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))


def _print_task_table(tasks: list[dict[str, Any]]) -> None:
    if not tasks:
        print("(no tasks)")
        return
    headers = ["ID", "TITLE", "ORIGIN", "ASSIGNEE", "COORD", "STATUS", "CREATED_AT"]
    rows: list[list[str]] = []
    for t in tasks:
        title = t["title"] if len(t["title"]) <= 30 else t["title"][:29] + "…"
        rows.append(
            [
                t["id"],
                title,
                t["origin"],
                t["assignee"] or "-",
                t["coordination"],
                t["status"],
                t["created_at"],
            ]
        )
    _print_table(headers, rows)


def _print_detail(detail: dict[str, Any]) -> None:
    t = detail["task"]
    print(f"Task: {t['id']}")
    for key in ("title", "body", "origin", "origin_ref", "assignee", "coordination", "status", "result"):
        val = t.get(key)
        if val not in (None, ""):
            print(f"  {key}: {val}")
    parts = t.get("participants") or []
    print(f"  participants: {', '.join(parts) if parts else '-'}")
    for key in ("created_at", "updated_at", "last_run_at"):
        print(f"  {key}: {t.get(key) or '-'}")
    print()
    print(f"Runs ({len(detail['runs'])}):")
    for r in detail["runs"]:
        print(
            f"  #{r['id']} agent={r['agent'] or '-'} status={r['status']} "
            f"started={r['started_at'] or '-'} ended={r['ended_at'] or '-'} "
            f"outcome={r['outcome'] or '-'}"
        )
    print()
    print(f"Messages ({len(detail['messages'])}):")
    for m in detail["messages"]:
        print(
            f"  #{m['id']} {m['author']}({m['author_kind']}) [{m['created_at']}]: "
            f"{m['body']}"
        )
    print()
    print(f"Events ({len(detail['events'])}):")
    for e in detail["events"]:
        print(
            f"  #{e['id']} {e['kind']} [{e['created_at']}]: "
            f"{json.dumps(e['payload'], ensure_ascii=False)}"
        )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def _dispatch(args: argparse.Namespace, store: Store) -> int:
    cmd = args.command

    if cmd == "add":
        registry = Registry(store)
        task, created = registry.register(
            title=args.title,
            body=args.body,
            origin=args.origin,
            origin_ref=args.origin_ref,
            assignee=args.assignee,
            coordination=args.coordination,
            participants=parse_participants(args.participants),
        )
        if args.json:
            _print_json(task)
        else:
            verb = "registered" if created else "already exists"
            print(
                f"{verb}: {task['id']}  ({task['origin']}/{task['coordination']})  "
                f"status={task['status']}"
            )
        return 0

    if cmd == "list":
        tasks = store.list_tasks(status=args.status, origin=args.origin, assignee=args.assignee)
        if args.json:
            _print_json(tasks)
        else:
            _print_task_table(tasks)
        return 0

    if cmd == "show":
        detail = store.get_task_detail(args.id)
        if detail is None:
            print(f"error: no task with id {args.id}", file=sys.stderr)
            return 1
        if args.json:
            _print_json(detail)
        else:
            _print_detail(detail)
        return 0

    if cmd == "run-start":
        run = store.add_run_start(args.id, args.agent)
        if args.json:
            _print_json(run)
        else:
            print(f"run {run['id']} started for task {run['task_id']} (agent={run['agent']})")
        return 0

    if cmd == "run-end":
        run = store.add_run_end(
            args.run_id,
            status=args.status,
            outcome=args.outcome,
            summary=args.summary,
            error_type=args.error_type,
        )
        if args.json:
            _print_json(run)
        else:
            print(f"run {run['id']} -> {run['status']}")
        return 0

    if cmd == "message":
        msg = store.add_message(
            args.id,
            author=args.author,
            author_kind=args.author_kind,
            body=args.body,
            run_id=args.run_id,
        )
        if args.json:
            _print_json(msg)
        else:
            print(
                f"message {msg['id']} appended to task {msg['task_id']} "
                f"by {msg['author']} ({msg['author_kind']})"
            )
        return 0

    if cmd == "event":
        ev = store.add_event(
            args.id,
            kind=args.kind,
            payload=parse_payload(args.payload),
            run_id=args.run_id,
        )
        if args.json:
            _print_json(ev)
        else:
            print(f"event {ev['id']} ({ev['kind']}) appended to task {ev['task_id']}")
        return 0

    print(f"error: unknown command {cmd}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    try:
        return _dispatch(args, store)
    except sqlite3.IntegrityError as exc:
        print(f"error: constraint violation: {exc}", file=sys.stderr)
        return 1
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
