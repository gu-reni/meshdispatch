# Cross-server onboarding (push path)

One meshdispatch panel can accept tasks that were created on another panel. The
receiving side exposes a single ingest endpoint, `POST /api/ingest`, that a
pushing agent calls with a per-agent bearer token. No other route accepts an
ingest token: it cannot read tasks, create approvals, dispatch, or be used as a
session credential.

The sender half (`meshdispatch/control/push.py`) already flattens the local
store into exactly this payload, so a panel can be paired with another panel by
pointing `push_to` at its ingest URL.

## Authentication

Every request carries the token in the `Authorization` header:

```
Authorization: Bearer mdit-<id>.<secret>
```

The token is bound to one agent (`meshdispatch token create --agent <name>`),
and the batch's top-level `agent` field must match that binding. Requests with
a missing, revoked, or wrong-agent token get `401` / `403`.

## Endpoint

```
POST /api/ingest
Content-Type: application/json
Authorization: Bearer <token>
```

The body is a JSON object with five keys: `agent`, `tasks`, `runs`, `messages`,
`events`. The last four are arrays of objects and are all optional (an empty
batch is legal). Child records (`runs`, `messages`, `events`) reference their
parent task through **`task_id`** or **`origin_ref`** — either key is accepted,
and the receiver maps it to the local task id before inserting.

### Example request

```bash
curl -sS http://panel:8080/api/ingest \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer mdit-abcdef123456.0123456789abcdef' \
  --data '{
    "agent": "host-b",
    "tasks": [
      {
        "id": "md-20990101-000001",
        "title": "sync",
        "body": "reconcile state",
        "origin": "a2a",
        "origin_ref": "ctx-1",
        "assignee": "host-b",
        "coordination": "multi",
        "participants": ["host-a", "host-b"],
        "status": "done",
        "created_at": "2026-10-03T00:00:00Z",
        "updated_at": "2026-10-03T00:00:05Z",
        "last_run_at": "2026-10-03T00:00:05Z",
        "result": "accepted"
      }
    ],
    "runs": [
      {
        "task_id": "md-20990101-000001",
        "agent": "host-b",
        "status": "done",
        "started_at": "2026-10-03T00:00:00Z",
        "ended_at": "2026-10-03T00:00:05Z",
        "outcome": "accepted",
        "summary": "ok",
        "error_type": null,
        "source_key": "a2a:ctx-1:run:1"
      }
    ],
    "messages": [
      {
        "task_id": "md-20990101-000001",
        "author": "host-b",
        "author_kind": "agent",
        "body": "hello",
        "created_at": "2026-10-03T00:00:01Z",
        "visibility": "local",
        "source_key": "a2a:ctx-1:msg:1"
      }
    ],
    "events": [
      {
        "task_id": "md-20990101-000001",
        "kind": "handoff",
        "payload": {"to": "host-a"},
        "created_at": "2026-10-03T00:00:02Z",
        "source_key": "a2a:ctx-1:event:1"
      }
    ]
  }'
```

### Example response

```json
{
  "accepted": {"tasks": 1, "runs": 1, "messages": 1, "events": 1},
  "skipped": {"tasks": 0, "runs": 0, "messages": 0, "events": 0},
  "errors": []
}
```

`accepted` counts rows newly written; `skipped` counts rows that already
existed (idempotent no-op). A record that cannot be attributed to a task in the
batch is reported in `errors` rather than written.

## Accepted fields

### Top level

| Field      | Type   | Required | Meaning                                    |
|------------|--------|----------|--------------------------------------------|
| `agent`    | string | yes      | Agent the token is bound to (must match).  |
| `tasks`    | array  | no       | Task records.                              |
| `runs`     | array  | no       | Run records.                               |
| `messages` | array  | no       | Message records.                           |
| `events`   | array  | no       | Event records.                             |

### tasks

| Field           | Type        | Default       | Meaning                                        |
|-----------------|-------------|---------------|------------------------------------------------|
| `id`            | string      | generated     | Sender's task id; used verbatim when free.     |
| `title`         | string      | `"(untitled)"`| Task title.                                    |
| `body`          | string      | `null`        | Free-form description.                         |
| `origin`        | string      | `"manual"`    | One of `cron`, `a2a`, `subagent`, `manual`.    |
| `origin_ref`    | string      | `null`        | Sender-side unique key (dedup on `origin`+`origin_ref`). |
| `assignee`      | string      | `null`        | Responsible agent.                             |
| `coordination`  | string      | `"single"`    | `single` or `multi`.                           |
| `participants`  | array       | `[]`          | List of participant names.                     |
| `status`        | string      | `"pending"`   | One of `pending`, `running`, `done`, `failed`, `cancelled`, `blocked`. |
| `created_at`    | string      | now           | ISO 8601 UTC timestamp.                        |
| `updated_at`    | string      | `created_at`  | ISO 8601 UTC timestamp.                        |
| `last_run_at`   | string      | `null`        | ISO 8601 UTC timestamp.                        |
| `result`        | string      | `null`        | Final outcome text.                            |

### runs

Each run references its task via `task_id` **or** `origin_ref`.

| Field        | Type   | Default    | Meaning                                        |
|--------------|--------|------------|------------------------------------------------|
| `task_id`    | string | —          | Parent task's sender id (one reference form).  |
| `origin_ref` | string | —          | Parent task's origin_ref (alternative form).   |
| `agent`      | string | `null`     | Agent that performed the run.                  |
| `status`     | string | `"done"`   | One of `pending`, `running`, `done`, `failed`, `cancelled`, `blocked`. |
| `started_at` | string | `null`     | ISO 8601 UTC timestamp.                        |
| `ended_at`   | string | `null`     | ISO 8601 UTC timestamp.                        |
| `outcome`    | string | `null`     | Result label.                                  |
| `summary`    | string | `null`     | Human summary (redacted).                      |
| `error_type` | string | `null`     | Categorical failure type.                      |
| `source_key` | string | synthesized| Idempotency key; dedup on `(task_id, source_key)`. |

### messages

Each message references its task via `task_id` **or** `origin_ref`.

| Field         | Type   | Default     | Meaning                                       |
|---------------|--------|-------------|-----------------------------------------------|
| `task_id`     | string | —           | Parent task's sender id (one reference form). |
| `origin_ref`  | string | —           | Parent task's origin_ref (alternative form).  |
| `author`      | string | `"unknown"` | Who wrote the message.                        |
| `author_kind` | string | `"agent"`   | `agent`, `human`, or `system`.                |
| `body`        | string | —           | Message content (required).                   |
| `created_at`  | string | now         | ISO 8601 UTC timestamp.                       |
| `visibility`  | string | `"local"`   | `local` or `public`.                          |
| `source_key`  | string | synthesized | Idempotency key; dedup on `(task_id, source_key)`. |

### events

Each event references its task via `task_id` **or** `origin_ref`.

| Field        | Type   | Default     | Meaning                                       |
|--------------|--------|-------------|-----------------------------------------------|
| `task_id`    | string | —           | Parent task's sender id (one reference form). |
| `origin_ref` | string | —           | Parent task's origin_ref (alternative form).  |
| `kind`       | string | `"event"`   | Event category.                               |
| `payload`    | any    | `{}`        | Any JSON value (object, list, string, number, boolean). |
| `created_at` | string | now         | ISO 8601 UTC timestamp.                       |
| `source_key` | string | synthesized | Idempotency key; dedup on `(task_id, source_key)`. |

## Idempotency

- **tasks** deduplicate on `origin` + `origin_ref`, falling back to the
  sender's `id` when `origin_ref` is absent.
- **runs / messages / events** deduplicate on `(task_id, source_key)`. When the
  sender omits `source_key`, the receiver synthesises a stable one from the
  record's identity fields, so pushing the same batch twice writes nothing a
  second time and reports `accepted` all-zero.

## Security notes

An ingest token is only valid for `POST /api/ingest`. It cannot read any data,
create tasks or approvals, decide approvals, dispatch, or be accepted on any
session route.
