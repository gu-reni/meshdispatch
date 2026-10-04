# Deploying meshdispatch

This document describes putting the dashboard behind a reverse proxy on a host
you control. It is written against what this project actually does; every
command below is one you can run as-is.

## What you are deploying

Two things run:

| Process | What it does | Talks to |
|---|---|---|
| `meshdispatch sync` (a scheduled job) | reads the agent logs on this host and writes them into the database | local files only, read-only |
| `meshdispatch.web.server` | serves the dashboard and the JSON API | the database, and the network |

The dashboard is the only thing that should ever face the network. `sync` is a
local batch job and needs no listening port.

**The dashboard is the security boundary.** It shows everything your agents have
done, and (from phase 4) it can dispatch tasks and record approvals. Treat it
like an admin console, not like a public site. It is not intended to be indexed,
linked, or reachable by people who are not you.

## 1. Install

```bash
python3 -m venv .venv
.venv/bin/pip install .            # or: pip install meshdispatch
```

Confirm it runs before configuring anything:

```bash
.venv/bin/meshdispatch --help
.venv/bin/meshdispatch agent list
```

## 2. Choose where state lives

Everything persistent is a file. Decide where, and back it up:

| Path | Contents | Sensitivity |
|---|---|---|
| `$MESHDISPATCH_DB` (default `./meshdispatch.db`) | tasks, runs, messages, events, agents, approvals, pairings, ingest tokens | high - it is the full activity record |
| the auth state directory | authorised devices, sessions, credentials, the audit log | high - it authorises access |

Set the database path explicitly so it does not depend on the working directory:

```bash
export MESHDISPATCH_DB=/var/lib/meshdispatch/meshdispatch.db
```

Back up by copying the database while nothing is writing to it, or use SQLite's
own backup:

```bash
sqlite3 "$MESHDISPATCH_DB" ".backup /var/backups/meshdispatch-$(date +%F).db"
```

The audit log is append-only and written on every login, approval decision and
pairing decision. Keep it; it is the record of who approved what.

## 3. Turn authentication on before it faces the network

The server fails closed: with nothing configured, every request is denied. That
is the correct default and you will have seen it as `401` on every route.

For anything reachable from outside your own network, enable all of:

1. **SSH public-key signature login** - the primary method. Verification goes
   through `ssh-keygen -Y verify`, so ed25519, ecdsa and rsa keys all work. Use
   the key type your own `ssh-keygen` produces by default.
2. **Device whitelist** - enrol each machine that may log in, and confirm it.
   An unconfirmed device is refused.
3. **TOTP, mandatory for public access** - a password or key alone is not enough
   from the public internet.
4. **GitHub OAuth** - optional, if you would rather log in that way.

Never expose the dashboard publicly with only a password. Never disable the
device whitelist "temporarily" on a public host.

Verify the gate before you expose anything: with the server running locally,
`curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/` must print
`401`.

## 4. Run it behind a reverse proxy

Terminate TLS at the proxy and let it forward to the loopback address. Bind the
server to loopback so it is never reachable directly:

```bash
MESHDISPATCH_HOST=127.0.0.1 MESHDISPATCH_PORT=8080 \
MESHDISPATCH_DB=/var/lib/meshdispatch/meshdispatch.db \
  .venv/bin/python -m meshdispatch.web.server
```

An nginx server block - the whole change is one file; do not add a second
listener for this:

```nginx
server {
    listen 8443 ssl;
    server_name panel.example.com;

    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    # The dashboard streams server-sent events. Buffering them defeats the point.
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

`proxy_buffering off` matters: without it the live update stream arrives in
bursts instead of immediately, and the dashboard's live behaviour looks broken
for reasons that have nothing to do with the application.

**Put the URL in the notes you keep, with its port.** A certificate covers a
name, so a URL that omits the port, or uses a bare IP address, will fail
certificate validation. Use the name.

## 5. Keep it running

Under systemd, so it restarts and so the logs have a home:

```ini
# /etc/systemd/system/meshdispatch.service
[Unit]
Description=meshdispatch dashboard
After=network-online.target

[Service]
User=meshdispatch
Environment=MESHDISPATCH_HOST=127.0.0.1
Environment=MESHDISPATCH_PORT=8080
Environment=MESHDISPATCH_DB=/var/lib/meshdispatch/meshdispatch.db
WorkingDirectory=/opt/meshdispatch
ExecStart=/opt/meshdispatch/.venv/bin/python -m meshdispatch.web.server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

And a job for collection. `sync` is idempotent, so a missed run costs nothing:

```bash
# every ten minutes
*/10 * * * * MESHDISPATCH_DB=/var/lib/meshdispatch/meshdispatch.db \
  /opt/meshdispatch/.venv/bin/meshdispatch sync --adapter all
```

## 6. Verification checklist

Run these after deploying, in this order. Each one has a definite answer.

```bash
# 1. unauthenticated access is refused
curl -s -o /dev/null -w '%{http_code}\n' https://panel.example.com:8443/api/tasks   # expect 401

# 2. the dashboard loads for you, and the static assets are present
#    (an installed copy with no static files returns 404 here, not 401)
curl -s -o /dev/null -w '%{http_code}\n' https://panel.example.com:8443/index.html  # expect 200 after login

# 3. collection actually wrote something
.venv/bin/meshdispatch list | head

# 4. the audit log recorded your login
tail -1 <auth state dir>/audit.jsonl
```

If step 2 returns `404` rather than `401`, the installed package is missing its
static files. That has happened before: the dashboard ships inside the wheel only
because `pyproject.toml` declares the package data. Check with:

```bash
python -c "import meshdispatch.web, pathlib; d=pathlib.Path(meshdispatch.web.__file__).parent/'static'; print(d.is_dir(), sorted(p.name for p in d.glob('*')))"
```

## 7. What this deployment must not become

The approvals queue authorises commands. This project deliberately stops short of
executing them: no approved command is run, shelled out to, or evaluated
anywhere in the codebase. The agent that asked for approval is the only thing
that can act on it.

Keep that property. If you ever add a component that acts on an approval, it is
no longer this project, and the panel has become a remote command execution
surface - in which case the access control above is the only thing standing
between the internet and your machines.

## See also

- [`CROSS-SERVER.md`](CROSS-SERVER.md) - adding a second machine, and device pairing
- [`DESIGN.md`](DESIGN.md) - why the authentication is shaped this way
- the top-level `README.md` - what the project does
