# meshdispatch

**Cross-server task scheduling and observability for teams of AI agents.**

meshdispatch connects heterogeneous agent runtimes running on **different machines**
over the [A2A protocol](https://github.com/a2aproject/A2A). One place to see what every
agent is doing right now, what it did before, and **what the agents said to each other
while doing it**.

<p>
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="status" src="https://img.shields.io/badge/status-early%20development-orange">
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-none-brightgreen">
</p>

---

## Why another agent orchestrator?

Because almost every existing one assumes a single runtime. Control planes today are
built around *one* CLI — Claude Code, Codex, OpenClaw — and a *single* machine. If your
agents are heterogeneous, or if they live on more than one server, you are on your own.

meshdispatch takes the opposite position:

| | Typical control plane | meshdispatch |
|---|---|---|
| Agent runtime | tied to one CLI | **any runtime** — speaks A2A, not a vendor API |
| Topology | one machine | **multiple servers, peer to peer** |
| Collaboration | parallel workers, no shared context | **first-class** — participants, handoffs, conversation log |
| Task identity | implicit | **every task has an id, a purpose, and a creation time** |

## What it does

- **Task registry.** Every task gets an id (`md-20261002-a3f19c`), a purpose, a creation
  time, an assignee, and a coordination mode — whether it is a **single-agent** or a
  **multi-agent** task.
- **Multi-agent collaboration as a first-class concept.** A task records its
  `participants`, every agent's run, and the **messages agents exchanged** while
  collaborating — so "what did they say to each other" is answerable after the fact.
- **Cross-server by design.** Tasks originating on a peer server are registered and
  tracked the same way as local ones, over the A2A protocol.
- **Run history, not just last status.** Each execution is stored separately with its
  own outcome, so you can see how a task has behaved over time.
- **Zero runtime dependencies.** The whole thing is Python standard library + SQLite.

## What is running today

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# collect what your agents already did, from their own logs
export MESHDISPATCH_DB=./meshdispatch.db
.venv/bin/meshdispatch sync --adapter all      # cron jobs, subagent traces, A2A conversations
.venv/bin/meshdispatch list

# serve the dashboard (task list, run history, inter-agent conversations,
# live updates over server-sent events). Auth is required: SSH-signed login,
# password + TOTP, or GitHub OAuth, with device binding and an audit log.
.venv/bin/python -m meshdispatch.web.server
```

The adapters read the logs Hermes already writes and are read-only with respect to
them — they never modify the sources. Registration is idempotent, so running `sync`
repeatedly does not create duplicates.

## Task model

| Table | What it holds |
|---|---|
| `tasks` | id, title, body, origin, assignee, coordination, participants, status, created_at, last_run_at, result |
| `runs` | one row per execution: agent, status, started_at, ended_at, outcome, summary |
| `messages` | the inter-agent conversation: author, author_kind, body, created_at |
| `events` | process events: kind, payload, created_at |

Enumerations are validated on write: `origin` in `cron | a2a | subagent | manual`,
`coordination` in `single | multi`, `status` in
`pending | running | done | failed | cancelled | blocked`.
All timestamps are normalized to ISO 8601 UTC.

## Quick start

```bash
git clone https://github.com/gu-reni/meshdispatch
cd meshdispatch
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# register a task
meshdispatch add --title "nightly DB backup" --origin cron --assignee backup-agent

# register a multi-agent, cross-server task
meshdispatch add --title "cross-server sync" --origin a2a --coordination multi \
  --participants "server-a,server-b"

meshdispatch list
meshdispatch show md-20261002-a3f19c
```

Also runnable as a module: `python -m meshdispatch list`.

## Status

**Working, but young.** Phases 1 to 3 are implemented and covered by 96 tests:
the task model and CLI, the collection adapters, and a dashboard with live push and
layered authentication. Not yet built: dispatching tasks from the dashboard and the
click-to-approve queue for guarded commands. See the roadmap below.

| Phase | Scope | State |
|---|---|---|
| 1 | Task model, store, registry, CLI | ✅ done |
| 2 | Adapters (cron / A2A / subagent) + conversation capture | ✅ done |
| 3 | Web dashboard with server-sent events + authentication | ✅ done |
| 4 | Dispatch tasks from the dashboard, click-to-approve command queue | 🚧 planned |
| 5 | Cross-server onboarding, packaging, docs | 🚧 planned |

## License

MIT — see [LICENSE](LICENSE).
