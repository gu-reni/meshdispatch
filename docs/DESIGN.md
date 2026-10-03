# Design notes

## Who this is for

meshdispatch is a dashboard for the **owner of the agents**. The person running it
must be able to see everything their agents are doing: activity state, what they
wrote, how they collaborated, and what they said to each other.

**Consequence for the security model:** we do **not** hide content from the
authenticated owner. Separation of concerns:

- **Access control is the security boundary.** The data is protected by keeping
  unauthorised people out, not by redacting what the owner sees.
- **Redaction is hygiene, not privacy.** The redactor exists so that credentials
  are not persisted into a database or carried off in logs. It is not there to
  hide things from the person who owns the machine.

## Authentication (phase 3)

Owners are authenticated in layers. All layers ship in the open-source build.

| Layer | Mechanism |
|---|---|
| Identity | SSH public-key signature (primary), account + TOTP, GitHub OAuth |
| Device | first login claims a device; later devices need confirmation from a claimed one |
| Session | short-lived session cookie, revocable, "sign out everywhere" |
| Transport | HTTPS (bring your own certificate) |
| Audit | every login, approval and outbound command is appended to an immutable log |

### On MAC-address binding

Binding a session to a client MAC address **cannot be done over HTTP**. A MAC
address is a layer-2 identifier: it is visible only inside the same broadcast
domain. Once a request crosses a router — which is always the case for public
access — the server sees an IP address and nothing below it.

What is actually achievable:

- **On the LAN** (client and server on the same segment): the server can read the
  client's MAC from the ARP table. This works, and is offered as an optional extra
  check for LAN access only.
- **Over the internet**: MAC binding is impossible. Use device binding plus SSH
  key signing plus TOTP instead — strictly stronger than a MAC address, and it
  works from anywhere.

## Task dispatch (phase 4)

Owners can create a task from the dashboard and assign it to a specific agent.

- The assignee is chosen from the **registry of known agents**, never typed as
  free text — otherwise a task can be dispatched to a non-existent agent and
  vanish silently.
- Multi-agent tasks record the participants and which one is the lead.
- Dispatch travels over A2A, so the target agent may be on another server.

## Approvals (phase 4)

When an agent needs permission to run something, the request is surfaced in the
dashboard as a clickable list.

**Scope:** only operations that are actually dangerous enter the approval list.
Sending every tool call through it would drown the queue and train the owner to
click through without reading.

```
agent wants to run a guarded command
        |  blocks, does not execute
   approval request recorded (command, purpose, impact, requesting agent, task id)
        |
   dashboard renders it as a clickable item
        |
   owner approves or rejects
        |
   agent unblocks and continues or aborts
```

**Security note.** A dashboard that can approve commands is a dashboard that can
execute commands. The blast radius of a broken authentication is therefore
arbitrary code execution. This is why the auth work is a prerequisite, not a
parallel task. Approval requests must be non-replayable (nonce, short expiry,
bound to the task id), signed by the server, and fully audited.

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 1 | Task model, store, registry, CLI | done |
| 2 | Adapters (cron / subagent / A2A) + conversation capture + redaction | done |
| 3 | Read-only dashboard, live push, layered authentication | planned |
| 4 | Control plane: dispatch tasks, click-to-approve | planned |
| 5 | Cross-server onboarding, packaging, docs | planned |

## Known issues

- `events.payload` records tool-call arguments verbatim, including command text.
  It is not yet passed through the redactor. Tracked for phase 3.
