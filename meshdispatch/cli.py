"""Command-line interface for meshdispatch.

Human-readable tables/indented text by default; ``--json`` emits
machine-readable JSON.  No secrets ever appear in output.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from typing import Any, Sequence

from . import models
from .registry import Registry
from .store import ApprovalConflict, ApprovalExpired, Store


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

    sync = sub.add_parser("sync", help="Pull tasks from origin adapters")
    sync.add_argument(
        "--adapter",
        choices=["cron", "a2a", "subagent", "all"],
        default="all",
        help="which adapter(s) to run (default: all)",
    )
    sync.add_argument("--since", help="only sync records at/after this ISO timestamp")
    sync.add_argument("--json", action="store_true")

    agent = sub.add_parser("agent", help="Manage the agent registry")
    agentsub = agent.add_subparsers(dest="agent_command", required=True)
    aadd = agentsub.add_parser("add", help="Register an agent")
    aadd.add_argument("--name", required=True, help="agent name (required)")
    aadd.add_argument("--description")
    aadd.add_argument("--endpoint", help="A2A endpoint URL")
    aadd.add_argument("--transport", default="a2a", help="transport (default: a2a)")
    aadd.add_argument("--disable", action="store_true", help="register as disabled")
    aadd.add_argument("--json", action="store_true")

    alist = agentsub.add_parser("list", help="List registered agents")
    alist.add_argument("--json", action="store_true")

    ashow = agentsub.add_parser("show", help="Show one registered agent")
    ashow.add_argument("name")
    ashow.add_argument("--json", action="store_true")

    approval = sub.add_parser("approval", help="Manage the approvals queue")
    approval_sub = approval.add_subparsers(dest="approval_command", required=True)
    aplist = approval_sub.add_parser("list", help="List approval requests")
    aplist.add_argument("--json", action="store_true")

    apshow = approval_sub.add_parser("show", help="Show one approval request")
    apshow.add_argument("id")
    apshow.add_argument("--json", action="store_true")

    apdecide = approval_sub.add_parser(
        "decide", help="Approve or reject an approval request"
    )
    apdecide.add_argument("id")
    decision_group = apdecide.add_mutually_exclusive_group(required=True)
    decision_group.add_argument("--approve", action="store_true")
    decision_group.add_argument("--reject", action="store_true")
    apdecide.add_argument("--totp", help="TOTP code (required for high-risk)")
    apdecide.add_argument(
        "--principal",
        help="name recorded as the decision maker "
        "(default: $MESHDISPATCH_PRINCIPAL or $USER)",
    )
    apdecide.add_argument("--json", action="store_true")

    push = sub.add_parser("push", help="Push the local store to a remote panel")
    push.add_argument("--to", required=True, dest="url", help="panel /api/ingest URL")
    push.add_argument("--token", required=True, help="ingest token (bound to --agent)")
    push.add_argument("--agent", help="agent this host is known as (default: local hostname)")
    push.add_argument("--since", help="only push tasks created at/after this ISO timestamp")
    push.add_argument(
        "--batch-size",
        dest="batch_size",
        type=int,
        default=50,
        help="tasks per batch (default: 50)",
    )
    push.add_argument("--json", action="store_true")

    token = sub.add_parser("token", help="Manage ingest tokens")
    tokensub = token.add_subparsers(dest="token_command", required=True)
    tcreate = tokensub.add_parser("create", help="Mint a token bound to an agent")
    tcreate.add_argument("--agent", required=True, help="agent name the token is bound to")
    tcreate.add_argument("--json", action="store_true")

    tlist = tokensub.add_parser("list", help="List ingest tokens")
    tlist.add_argument("--json", action="store_true")

    trevoke = tokensub.add_parser("revoke", help="Revoke an ingest token")
    trevoke.add_argument("id", help="token id")
    trevoke.add_argument("--json", action="store_true")

    device = sub.add_parser("device", help="Pair a machine with this panel")
    devicesub = device.add_subparsers(dest="device_command", required=True)

    dkeygen = devicesub.add_parser("keygen", help="Generate a local device keypair")
    dkeygen.add_argument("--out", default=".", help="directory to write keys into")
    dkeygen.add_argument("--bits", type=int, default=2048, help="RSA key size")
    dkeygen.add_argument("--json", action="store_true")

    drequest = devicesub.add_parser(
        "request", help="Post the public key to a panel and print the pairing code"
    )
    drequest.add_argument("--to", required=True, dest="url", help="panel /api/pairings URL")
    drequest.add_argument("--name", required=True, help="display name for this machine")
    drequest.add_argument("--key", dest="key_path", help="public key file (default: ./meshdispatch_key.pub)")
    drequest.add_argument("--json", action="store_true")

    dlist = devicesub.add_parser("list", help="List authorised devices")
    dlist.add_argument("--json", action="store_true")

    drevoke = devicesub.add_parser("revoke", help="Revoke a device")
    drevoke.add_argument("id", help="device id")
    drevoke.add_argument("--json", action="store_true")

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


def _print_agent_table(agents: list[dict[str, Any]]) -> None:
    if not agents:
        print("(no agents)")
        return
    headers = ["NAME", "DESCRIPTION", "ENDPOINT", "TRANSPORT", "ENABLED", "CREATED_AT"]
    rows: list[list[str]] = []
    for a in agents:
        desc = a.get("description") or ""
        desc = desc if len(desc) <= 30 else desc[:29] + "…"
        rows.append(
            [
                a["name"],
                desc or "-",
                a.get("endpoint") or "-",
                a["transport"],
                "yes" if a["enabled"] else "no",
                a["created_at"],
            ]
        )
    _print_table(headers, rows)


def _print_agent_detail(agent: dict[str, Any]) -> None:
    print(f"Agent: {agent['name']}")
    for key in ("description", "endpoint", "transport"):
        val = agent.get(key)
        print(f"  {key}: {val or '-'}")
    print(f"  enabled: {'yes' if agent['enabled'] else 'no'}")
    for key in ("created_at", "updated_at"):
        print(f"  {key}: {agent.get(key) or '-'}")


def _print_approval_table(approvals: list[dict[str, Any]]) -> None:
    if not approvals:
        print("(no approvals)")
        return
    headers = ["ID", "STATUS", "RISK", "AGENT", "TASK_ID", "COMMAND", "REQUESTED_AT"]
    rows: list[list[str]] = []
    for a in approvals:
        command = a["command"]
        command = command if len(command) <= 40 else command[:39] + "…"
        rows.append(
            [
                a["id"],
                a["status"],
                a["risk"],
                a["agent"],
                a["task_id"],
                command,
                a["requested_at"],
            ]
        )
    _print_table(headers, rows)


def _print_approval_detail(approval: dict[str, Any]) -> None:
    print(f"Approval: {approval['id']}")
    for key in ("status", "risk", "agent", "task_id", "nonce"):
        print(f"  {key}: {approval[key]}")
    print(f"  command: {approval['command']}")
    for key in ("purpose", "impact"):
        val = approval.get(key)
        print(f"  {key}: {val or '-'}")
    for key in ("requested_at", "expires_at", "decided_at", "decided_by"):
        print(f"  {key}: {approval.get(key) or '-'}")
    sig = approval.get("decision_signature")
    if sig:
        print(f"  decision_signature: {sig}")


def _print_token_table(tokens: list[dict[str, Any]]) -> None:
    if not tokens:
        print("(no ingest tokens)")
        return
    headers = ["ID", "AGENT", "STATUS", "CREATED_AT", "REVOKED_AT"]
    rows: list[list[str]] = []
    for t in tokens:
        rows.append(
            [
                t["id"],
                t["agent"],
                "revoked" if t["revoked"] else "active",
                t["created_at"],
                t.get("revoked_at") or "-",
            ]
        )
    _print_table(headers, rows)


def _print_push_summary(result: dict[str, Any]) -> None:
    acc = result["accepted"]
    print(
        f"accepted {acc['tasks']} tasks, {acc['runs']} runs, "
        f"{acc['messages']} messages, {acc['events']} events "
        f"(in {result['batches']} batches)"
    )
    for failure in result["failures"]:
        print(f"error: {failure}", file=sys.stderr)


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

    if cmd == "sync":
        from .adapters import ADAPTERS, SyncStats

        registry = Registry(store)
        names = (
            ["cron", "a2a", "subagent"]
            if args.adapter == "all"
            else [args.adapter]
        )
        results: dict[str, SyncStats] = {}
        for name in names:
            adapter = ADAPTERS[name]()
            results[name] = adapter.sync(registry, since=args.since)
        if args.json:
            _print_json({name: stats.to_dict() for name, stats in results.items()})
        else:
            for name, stats in results.items():
                d = stats.to_dict()
                print(
                    f"{name}: tasks_new={d['tasks_new']} tasks_updated={d['tasks_updated']} "
                    f"runs_new={d['runs_new']} messages_new={d['messages_new']} "
                    f"events_new={d['events_new']} skipped={d['skipped']}"
                )
        return 0

    if cmd == "agent":
        if args.agent_command == "add":
            agent = store.add_agent(
                name=args.name,
                description=args.description,
                endpoint=args.endpoint,
                transport=args.transport,
                enabled=not args.disable,
            )
            if args.json:
                _print_json(agent)
            else:
                state = "enabled" if agent["enabled"] else "disabled"
                print(
                    f"agent {agent['name']} registered ({agent['transport']}/{state})"
                )
            return 0
        if args.agent_command == "list":
            agents = store.list_agents()
            if args.json:
                _print_json(agents)
            else:
                _print_agent_table(agents)
            return 0
        if args.agent_command == "show":
            agent = store.get_agent(args.name)
            if agent is None:
                print(f"error: no agent named {args.name}", file=sys.stderr)
                return 1
            if args.json:
                _print_json(agent)
            else:
                _print_agent_detail(agent)
            return 0
        print(f"error: unknown agent command {args.agent_command}", file=sys.stderr)
        return 2

    if cmd == "approval":
        if args.approval_command == "list":
            approvals = store.list_approvals()
            if args.json:
                _print_json(approvals)
            else:
                _print_approval_table(approvals)
            return 0
        if args.approval_command == "show":
            approval = store.get_approval(args.id)
            if approval is None:
                print(f"error: no approval with id {args.id}", file=sys.stderr)
                return 1
            if args.json:
                _print_json(approval)
            else:
                _print_approval_detail(approval)
            return 0
        if args.approval_command == "decide":
            approval = store.get_approval(args.id)
            if approval is None:
                print(f"error: no approval with id {args.id}", file=sys.stderr)
                return 1
            decision = "approved" if args.approve else "rejected"
            if approval["risk"] == "high":
                secret = os.environ.get("MESHDISPATCH_TOTP_SECRET")
                if not secret or not _cli_totp_ok(secret, args.totp):
                    print(
                        "error: high-risk approval requires a valid --totp code "
                        "(set MESHDISPATCH_TOTP_SECRET to verify it)",
                        file=sys.stderr,
                    )
                    return 1
            principal = args.principal or os.environ.get(
                "MESHDISPATCH_PRINCIPAL"
            ) or os.environ.get("USER") or "owner"
            try:
                updated = store.decide_approval(
                    args.id, decision=decision, decided_by=principal
                )
            except (ApprovalConflict, ApprovalExpired) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if args.json:
                _print_json(updated)
            else:
                print(
                    f"approval {updated['id']} -> {updated['status']} "
                    f"(by {updated['decided_by']})"
                )
            return 0
        print(f"error: unknown approval command {args.approval_command}", file=sys.stderr)
        return 2

    if cmd == "push":
        from .control.push import push_to

        result = push_to(
            store,
            url=args.url,
            token=args.token,
            agent=args.agent,
            since=args.since,
            batch_size=args.batch_size,
        )
        if args.json:
            _print_json(result)
        else:
            _print_push_summary(result)
        return 1 if result["failures"] else 0

    if cmd == "token":
        if args.token_command == "create":
            record, plaintext = store.create_ingest_token(args.agent)
            if args.json:
                _print_json(
                    {
                        "id": record["id"],
                        "agent": record["agent"],
                        "token": plaintext,
                    }
                )
            else:
                print(f"token {record['id']} created for agent {record['agent']}:")
                print(plaintext)
            return 0
        if args.token_command == "list":
            tokens = store.list_ingest_tokens()
            if args.json:
                _print_json(tokens)
            else:
                _print_token_table(tokens)
            return 0
        if args.token_command == "revoke":
            if store.revoke_ingest_token(args.id):
                if args.json:
                    _print_json({"id": args.id, "revoked": True})
                else:
                    print(f"revoked token {args.id}")
                return 0
            print(f"error: no such active token {args.id}", file=sys.stderr)
            return 1
        print(f"error: unknown token command {args.token_command}", file=sys.stderr)
        return 2

    if cmd == "device":
        return _device_dispatch(args)

    print(f"error: unknown command {cmd}", file=sys.stderr)
    return 2


def _device_dispatch(args: argparse.Namespace) -> int:
    if args.device_command == "keygen":
        return _device_keygen(args)
    if args.device_command == "request":
        return _device_request(args)
    if args.device_command == "list":
        return _device_list(args)
    if args.device_command == "revoke":
        return _device_revoke(args)
    print(f"error: unknown device command {args.device_command}", file=sys.stderr)
    return 2


def _device_keygen(args: argparse.Namespace) -> int:
    from .auth.crypto import generate_rsa_keypair, serialize_ssh_public_key

    out_dir = os.path.abspath(args.out)
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        print(f"error: cannot create output directory: {exc}", file=sys.stderr)
        return 1

    keypair = generate_rsa_keypair(bits=args.bits)
    public = {"n": keypair["n"], "e": keypair["e"]}
    pub_line = serialize_ssh_public_key(public, comment="meshdispatch")

    priv_path = os.path.join(out_dir, "meshdispatch_key")
    pub_path = os.path.join(out_dir, "meshdispatch_key.pub")

    private_doc = {
        "n": keypair["n"],
        "e": keypair["e"],
        "d": keypair["d"],
        "p": keypair["p"],
        "q": keypair["q"],
    }
    try:
        with open(priv_path, "w", encoding="utf-8") as fh:
            json.dump(private_doc, fh)
        os.chmod(priv_path, 0o600)
        with open(pub_path, "w", encoding="utf-8") as fh:
            fh.write(pub_line + "\n")
    except OSError as exc:
        print(f"error: failed to write key files: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _print_json({"private": priv_path, "public": pub_path})
    else:
        print(f"private key: {priv_path}")
        print(f"public key:  {pub_path}")
    return 0


def _device_public_key(args: argparse.Namespace) -> str:
    path = args.key_path or os.path.join(os.getcwd(), "meshdispatch_key.pub")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            line = fh.read().strip()
    except OSError as exc:
        raise ValueError(f"cannot read public key file {path}: {exc}") from exc
    if not line:
        raise ValueError(f"public key file {path} is empty")
    return line


def _device_request(args: argparse.Namespace) -> int:
    import urllib.error
    import urllib.request

    try:
        public_key = _device_public_key(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(
        {"public_key": public_key, "display_name": args.name}, ensure_ascii=False
    ).encode("utf-8")
    req = urllib.request.Request(
        args.url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            body = {}
    except urllib.error.URLError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if status != 201:
        reason = body.get("error") if isinstance(body, dict) else ""
        print(f"error: pairing request failed (HTTP {status})"
              + (f": {reason}" if reason else ""), file=sys.stderr)
        return 1

    if args.json:
        _print_json(body)
    else:
        print("Pairing request created. Give this code to the panel owner:")
        print()
        print(f"  code:  {body['code']}")
        print(f"  id:    {body['id']}")
        print(f"  until: {body['expires_at']}")
    return 0


def _device_manager():
    from .auth import AuthConfig, AuthManager

    state_dir = os.environ.get("MESHDISPATCH_AUTH_STATE_DIR")
    return AuthManager(AuthConfig(), state_dir=state_dir or None)


def _device_list(args: argparse.Namespace) -> int:
    from .control.pairing import device_lister_from_manager

    devices = device_lister_from_manager(_device_manager())()
    if args.json:
        _print_json(devices)
        return 0
    if not devices:
        print("(no devices)")
        return 0
    headers = ["ID", "PRINCIPAL", "NAME", "CONFIRMED", "CREATED_AT"]
    rows = [
        [
            d.get("device_id") or "-",
            d.get("principal") or "-",
            d.get("device_name") or "-",
            "yes" if d.get("confirmed") else "no",
            d.get("created_at") or "-",
        ]
        for d in devices
    ]
    _print_table(headers, rows)
    return 0


def _device_revoke(args: argparse.Namespace) -> int:
    from .control.pairing import device_revoker_from_manager

    if device_revoker_from_manager(_device_manager())(args.id):
        if args.json:
            _print_json({"id": args.id, "revoked": True})
        else:
            print(f"revoked device {args.id}")
        return 0
    print(f"error: no such device {args.id}", file=sys.stderr)
    return 1


def _cli_totp_ok(secret: str, code: str | None) -> bool:
    if not code:
        return False
    from .auth.totp import totp_verify

    return totp_verify(secret, code)


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
