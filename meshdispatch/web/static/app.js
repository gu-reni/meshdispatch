"use strict";

/*
 * meshdispatch dashboard (read-only).  Plain vanilla JS, no dependencies.
 *
 * Everything that reaches the page from the API is rendered through
 * `textContent` / `createElement` only; dynamic data is never assigned to
 * `innerHTML`, so markup can not be injected through task/message content.
 *
 * Live updates arrive over an EventSource on /api/stream.  The server only
 * tells us *which table* grew (not which task), so on any change we cheaply
 * refetch the list + stats and, if a task is open, its detail too.  Refreshes
 * are debounced so a burst of inserts collapses into one pass.
 */

const REFRESH_DEBOUNCE_MS = 300;

const els = {
  stats: document.getElementById("stats"),
  taskList: document.getElementById("task-list"),
  taskCount: document.getElementById("task-count"),
  taskDetail: document.getElementById("task-detail"),
  backButton: document.getElementById("detail-back"),
  streamState: document.getElementById("stream-state"),
  taskForm: document.getElementById("task-form"),
  taskTitle: document.getElementById("task-title"),
  taskBody: document.getElementById("task-body"),
  taskAssignee: document.getElementById("task-assignee"),
  participantsField: document.getElementById("participants-field"),
  participantsList: document.getElementById("participants-list"),
  taskFormResult: document.getElementById("task-form-result"),
  approvalsList: document.getElementById("approvals-list"),
  approvalCount: document.getElementById("approval-count"),
  pairingsList: document.getElementById("pairings-list"),
  pairingCount: document.getElementById("pairing-count"),
  devicesList: document.getElementById("devices-list"),
  logoutButton: document.getElementById("logout-button"),
};

const state = {
  tasks: new Map(),
  agents: new Map(),
  selectedTaskId: null,
  approvals: new Map(),
  pairings: new Map(),
  devices: new Map(),
};

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

function api(path) {
  return fetch(path, { headers: { Accept: "application/json" } }).then((res) => {
    if (!res.ok) {
      const err = new Error("HTTP " + res.status);
      err.status = res.status;
      throw err;
    }
    return res.json();
  });
}

async function postTask(payload) {
  const res = await fetch("/api/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error((data && data.error) || "HTTP " + res.status);
    err.status = res.status;
    throw err;
  }
  return data;
}

function describeError(err) {
  if (err && err.status === 401) return "Authentication required.";
  return "Failed to load (" + (err && err.message ? err.message : "network error") + ").";
}

function describeApprovalError(err) {
  if (err && err.status === 403) {
    return "A valid TOTP code is required for high-risk approvals.";
  }
  if (err && err.status === 409) {
    return "This approval was already decided or has expired.";
  }
  if (err && err.status === 404) {
    return "This approval no longer exists.";
  }
  return "Failed to decide (" + (err && err.message ? err.message : "network error") + ").";
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function emptyNote(text) {
  return el("p", "note", text);
}

function errorNote(err) {
  return el("p", "note note--error", describeError(err));
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function fmtDuration(startIso, endIso) {
  if (!startIso) return "—";
  const start = new Date(startIso).getTime();
  if (Number.isNaN(start)) return "—";
  const end = endIso ? new Date(endIso).getTime() : Date.now();
  if (Number.isNaN(end)) return "—";
  let secs = Math.max(0, Math.round((end - start) / 1000));
  if (secs < 60) return secs + "s";
  const mins = Math.floor(secs / 60);
  secs = secs % 60;
  if (mins < 60) return mins + "m " + secs + "s";
  const hours = Math.floor(mins / 60);
  return hours + "h " + (mins % 60) + "m";
}

function remainingMs(expiresIso) {
  if (!expiresIso) return -1;
  const t = new Date(expiresIso).getTime();
  if (Number.isNaN(t)) return -1;
  return t - Date.now();
}

function fmtRemaining(expiresIso) {
  const ms = remainingMs(expiresIso);
  if (ms <= 0) return "expired";
  let secs = Math.floor(ms / 1000);
  if (secs < 60) return secs + "s";
  const mins = Math.floor(secs / 60);
  secs = secs % 60;
  if (mins < 60) return mins + "m " + secs + "s";
  const hours = Math.floor(mins / 60);
  return hours + "h " + (mins % 60) + "m";
}

function badge(status) {
  const node = el("span", "badge", status);
  node.dataset.status = status;
  return node;
}

function metaItem(label, value) {
  const wrap = el("span", "meta");
  wrap.append(el("span", "meta__label", label), el("span", "meta__value", value));
  return wrap;
}

function kvBlock(label, value) {
  const block = el("div", "kv");
  block.append(el("span", "kv__label", label), el("span", "kv__value", value));
  return block;
}

function field(dl, label, value) {
  dl.append(el("dt", null, label), el("dd", null, value));
}

function modeLabel(coordination) {
  return coordination === "multi" ? "multi-agent" : "single-agent";
}

function taskDuration(runs) {
  let earliest = null;
  let latest = null;
  let running = false;
  for (const run of runs) {
    if (run.started_at && (earliest === null || run.started_at < earliest)) {
      earliest = run.started_at;
    }
    if (run.ended_at && (latest === null || run.ended_at > latest)) {
      latest = run.ended_at;
    }
    if (run.status === "running") running = true;
  }
  if (!earliest) return "—";
  return fmtDuration(earliest, running ? null : latest);
}

// ---------------------------------------------------------------------------
// stats (header)
// ---------------------------------------------------------------------------

function renderStats(stats) {
  const nav = els.stats;
  nav.textContent = "";
  nav.append(statGroup("origin", stats.by_origin), statGroup("status", stats.by_status));
}

function statGroup(label, counts) {
  const group = el("div", "stats__group");
  group.append(el("span", "stats__label", label));
  const keys = Object.keys(counts || {}).sort();
  if (keys.length === 0) {
    group.append(el("span", "stats__empty", "none"));
  } else {
    for (const key of keys) {
      const chip = el("span", "stats__chip");
      chip.append(el("span", "stats__chip-name", key), el("span", "stats__chip-count", String(counts[key])));
      group.append(chip);
    }
  }
  return group;
}

// ---------------------------------------------------------------------------
// task list
// ---------------------------------------------------------------------------

function buildTaskRow(task) {
  const row = el("button", "task-row", null);
  row.type = "button";
  row.classList.toggle("is-selected", task.id === state.selectedTaskId);
  row.addEventListener("click", () => openTask(task.id));

  const head = el("div", "task-row__head");
  head.append(badge(task.status), el("span", "task-row__title", task.title));

  const meta = el("div", "task-row__meta");
  meta.append(
    metaItem("id", task.id),
    metaItem("created", fmtTime(task.created_at)),
    metaItem("last run", fmtTime(task.last_run_at)),
    metaItem("agent", task.assignee || "—"),
    metaItem("mode", modeLabel(task.coordination))
  );

  row.append(head, meta);
  return row;
}

function renderTaskList() {
  const list = els.taskList;
  list.textContent = "";
  const tasks = Array.from(state.tasks.values()).sort(
    (a, b) => activityTime(b) - activityTime(a) || a.id.localeCompare(b.id)
  );
  els.taskCount.textContent = String(tasks.length);
  if (tasks.length === 0) {
    list.append(emptyNote("No tasks recorded yet."));
    return;
  }
  for (const task of tasks) {
    list.append(buildTaskRow(task));
  }
}

function activityTime(task) {
  const iso = task.last_run_at || task.created_at || "";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
}

// ---------------------------------------------------------------------------
// task detail
// ---------------------------------------------------------------------------

function buildDetailHeader(task, runs) {
  const header = el("div", "detail__header");

  const titleRow = el("div", "detail__title-row");
  titleRow.append(badge(task.status), el("h2", "detail__title", task.title));

  const fields = el("dl", "detail__fields");
  field(fields, "ID", task.id);
  field(fields, "Mode", modeLabel(task.coordination));
  field(fields, "Status", task.status);
  field(fields, "Duration", taskDuration(runs));
  field(fields, "Result", task.result || "—");
  field(fields, "Origin", task.origin);
  field(fields, "Agent", task.assignee || "—");
  field(fields, "Created", fmtTime(task.created_at));
  field(fields, "Last run", fmtTime(task.last_run_at));

  header.append(titleRow, fields);
  return header;
}

function buildMessage(msg) {
  const item = el("li", "message");
  item.dataset.authorKind = msg.author_kind;

  const meta = el("div", "message__meta");
  const time = el("time", "message__time", fmtTime(msg.created_at));
  time.dateTime = msg.created_at || "";
  meta.append(
    el("span", "message__author", msg.author),
    el("span", "message__kind", msg.author_kind),
    time
  );

  const body = el("div", "message__body", msg.body);

  item.append(meta, body);
  return item;
}

function buildConversation(messages, coordination) {
  const section = el("section", "detail__section");
  section.append(el("h3", "detail__section-title", coordination === "multi" ? "Conversation" : "Messages"));

  const ordered = messages
    .slice()
    .sort((a, b) =>
      (a.created_at || "").localeCompare(b.created_at || "") || (a.id - b.id)
    );

  const list = el("ol", "conversation");
  for (const msg of ordered) list.append(buildMessage(msg));
  section.append(list);
  return section;
}

function buildRun(run) {
  const card = el("div", "run");

  const head = el("div", "run__head");
  head.append(badge(run.status), el("span", "run__agent", run.agent || "(no agent)"));

  const meta = el("div", "run__meta");
  meta.append(
    metaItem("started", fmtTime(run.started_at)),
    metaItem("ended", fmtTime(run.ended_at)),
    metaItem("duration", fmtDuration(run.started_at, run.ended_at))
  );

  card.append(head, meta);
  if (run.outcome) card.append(kvBlock("Outcome", run.outcome));
  if (run.summary) card.append(kvBlock("Summary", run.summary));
  if (run.error_type) card.append(kvBlock("Error", run.error_type));
  return card;
}

function buildRuns(runs) {
  const section = el("section", "detail__section");
  section.append(el("h3", "detail__section-title", "Runs"));
  if (runs.length === 0) {
    section.append(emptyNote("No runs recorded."));
    return section;
  }
  const list = el("div", "runs");
  for (const run of runs) list.append(buildRun(run));
  section.append(list);
  return section;
}

function renderDetail(detail) {
  const container = els.taskDetail;
  container.textContent = "";
  const task = detail.task;

  container.append(buildDetailHeader(task, detail.runs));

  if (detail.messages.length > 0) {
    container.append(buildConversation(detail.messages, task.coordination));
  }

  container.append(buildRuns(detail.runs));
}

// ---------------------------------------------------------------------------
// approvals panel
// ---------------------------------------------------------------------------

async function decideApproval(id, decision, totp) {
  const payload = { decision: decision };
  if (totp) payload.totp = totp;
  const res = await fetch(
    "/api/approvals/" + encodeURIComponent(id) + "/decide",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    }
  );
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error((data && data.error) || "HTTP " + res.status);
    err.status = res.status;
    throw err;
  }
  return data;
}

function buildApprovalCard(approval) {
  const card = el("div", "approval");
  card.dataset.risk = approval.risk;

  const head = el("div", "approval__head");
  head.append(
    badge(approval.risk),
    el("span", "approval__agent", approval.agent),
    el("span", "approval__id", approval.id)
  );

  const meta = el("div", "approval__meta");
  meta.append(
    metaItem("task", approval.task_id),
    metaItem("requested", fmtTime(approval.requested_at)),
    metaItem("time left", fmtRemaining(approval.expires_at))
  );

  const command = el("div", "approval__command");
  command.append(el("span", "approval__command-label", "command"));
  const commandValue = el("code", "approval__command-value", approval.command);
  command.append(commandValue);

  card.append(head, meta, command);

  if (approval.purpose) card.append(kvBlock("Purpose", approval.purpose));
  if (approval.impact) card.append(kvBlock("Impact", approval.impact));

  const highRisk = approval.risk === "high";
  const expired = remainingMs(approval.expires_at) <= 0;

  let totpInput = null;
  if (highRisk) {
    const totpField = el("label", "approval__totp-field");
    totpField.append(el("span", "approval__totp-label", "TOTP code (required)"));
    totpInput = document.createElement("input");
    totpInput.type = "text";
    totpInput.inputMode = "numeric";
    totpInput.autocomplete = "one-time-code";
    totpInput.className = "approval__totp";
    totpInput.placeholder = "6-digit code";
    totpField.append(totpInput);
    card.append(totpField);
  }

  const actions = el("div", "approval__actions");
  const approveBtn = el("button", "btn btn--approve", "Approve");
  approveBtn.type = "button";
  const rejectBtn = el("button", "btn btn--reject", "Reject");
  rejectBtn.type = "button";
  approveBtn.disabled = expired;
  rejectBtn.disabled = expired;
  actions.append(approveBtn, rejectBtn);

  const result = el("p", "note approval__result", "");
  result.hidden = true;

  function handleDecision(decision) {
    result.hidden = false;
    result.textContent = "Submitting…";
    result.classList.remove("note--error", "note--success");
    decideApproval(approval.id, decision, totpInput ? totpInput.value.trim() : "")
      .then((updated) => {
        result.textContent = "Decision recorded: " + updated.status + ".";
        result.classList.remove("note--error");
        result.classList.add("note--success");
        loadApprovals();
      })
      .catch((err) => {
        result.textContent = describeApprovalError(err);
        result.classList.remove("note--success");
        result.classList.add("note--error");
        loadApprovals();
      });
  }

  approveBtn.addEventListener("click", () => handleDecision("approve"));
  rejectBtn.addEventListener("click", () => handleDecision("reject"));

  if (expired) {
    card.append(el("p", "note note--error", "This request has expired."));
  }

  card.append(actions, result);
  return card;
}

function renderApprovals() {
  const list = els.approvalsList;
  list.textContent = "";
  const pending = Array.from(state.approvals.values()).filter(
    (a) => a.status === "pending"
  );
  els.approvalCount.textContent = String(pending.length);

  if (pending.length === 0) {
    list.append(emptyNote("No pending approvals."));
    return;
  }

  pending
    .slice()
    .sort((a, b) => (a.requested_at || "").localeCompare(b.requested_at || ""))
    .forEach((approval) => list.append(buildApprovalCard(approval)));
}

async function loadApprovals() {
  try {
    const approvals = await api("/api/approvals");
    state.approvals = new Map(approvals.map((a) => [a.id, a]));
    renderApprovals();
  } catch (err) {
    els.approvalsList.textContent = "";
    els.approvalCount.textContent = "";
    els.approvalsList.append(errorNote(err));
  }
}

// ---------------------------------------------------------------------------
// devices + pairing panel
// ---------------------------------------------------------------------------

function describePairingError(err) {
  if (err && err.status === 403) {
    return "A valid TOTP code is required to approve or reject a pairing.";
  }
  if (err && err.status === 409) {
    return "This pairing was already decided or has expired.";
  }
  if (err && err.status === 404) {
    return "This pairing no longer exists.";
  }
  return "Failed to decide (" + (err && err.message ? err.message : "network error") + ").";
}

async function decidePairing(id, decision, totp) {
  const payload = { decision: decision };
  if (totp) payload.totp = totp;
  const res = await fetch(
    "/api/pairings/" + encodeURIComponent(id) + "/decide",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    }
  );
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error((data && data.error) || "HTTP " + res.status);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function revokeDevice(id) {
  const res = await fetch(
    "/api/devices/" + encodeURIComponent(id) + "/revoke",
    { method: "POST", headers: { Accept: "application/json" } }
  );
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error((data && data.error) || "HTTP " + res.status);
    err.status = res.status;
    throw err;
  }
  return data;
}

function buildPairingCard(pairing) {
  const card = el("div", "pairing");

  const head = el("div", "pairing__head");
  head.append(
    el("span", "pairing__name", pairing.display_name),
    el("span", "pairing__id", pairing.id)
  );

  const meta = el("div", "pairing__meta");
  meta.append(
    metaItem("fingerprint", pairing.key_fingerprint),
    metaItem("time left", fmtRemaining(pairing.expires_at))
  );

  card.append(head, meta);

  const codeBlock = el("div", "pairing__code");
  codeBlock.append(el("span", "pairing__code-label", "pairing code"));
  codeBlock.append(
    el("span", "pairing__code-value", pairing.code || "—"),
    el("span", "pairing__code-hint", "compare with what the machine shows")
  );
  card.append(codeBlock);

  const expired = remainingMs(pairing.expires_at) <= 0;

  const totpField = el("label", "pairing__totp-field");
  totpField.append(el("span", "pairing__totp-label", "TOTP code (required)"));
  const totpInput = document.createElement("input");
  totpInput.type = "text";
  totpInput.inputMode = "numeric";
  totpInput.autocomplete = "one-time-code";
  totpInput.className = "pairing__totp";
  totpInput.placeholder = "6-digit code";
  totpField.append(totpInput);
  card.append(totpField);

  const actions = el("div", "pairing__actions");
  const approveBtn = el("button", "btn btn--approve", "Approve");
  approveBtn.type = "button";
  const rejectBtn = el("button", "btn btn--reject", "Reject");
  rejectBtn.type = "button";
  approveBtn.disabled = expired;
  rejectBtn.disabled = expired;
  actions.append(approveBtn, rejectBtn);

  const result = el("p", "note pairing__result", "");
  result.hidden = true;

  function handleDecision(decision) {
    result.hidden = false;
    result.textContent = "Submitting…";
    result.classList.remove("note--error", "note--success");
    decidePairing(pairing.id, decision, totpInput.value.trim())
      .then((updated) => {
        result.textContent = "Pairing " + updated.status + ".";
        result.classList.remove("note--error");
        result.classList.add("note--success");
        loadPairings();
        loadDevices();
      })
      .catch((err) => {
        result.textContent = describePairingError(err);
        result.classList.remove("note--success");
        result.classList.add("note--error");
        loadPairings();
      });
  }

  approveBtn.addEventListener("click", () => handleDecision("approve"));
  rejectBtn.addEventListener("click", () => handleDecision("reject"));

  if (expired) {
    card.append(el("p", "note note--error", "This request has expired."));
  }

  card.append(actions, result);
  return card;
}

function renderPairings() {
  const list = els.pairingsList;
  list.textContent = "";
  const pending = Array.from(state.pairings.values()).filter(
    (p) => p.status === "pending"
  );
  els.pairingCount.textContent = String(pending.length);

  if (pending.length === 0) {
    list.append(emptyNote("No pending pairing requests."));
    return;
  }

  pending
    .slice()
    .sort((a, b) => (a.created_at || "").localeCompare(b.created_at || ""))
    .forEach((p) => list.append(buildPairingCard(p)));
}

function buildDeviceRow(device) {
  const row = el("div", "device");

  const head = el("div", "device__head");
  head.append(
    el("span", "device__name", device.device_name || "(unnamed)"),
    badge(device.confirmed ? "approved" : "revoked")
  );

  const meta = el("div", "device__meta");
  meta.append(
    metaItem("id", device.device_id),
    metaItem("principal", device.principal || "—"),
    metaItem("created", fmtTime(device.created_at))
  );

  row.append(head, meta);

  const actions = el("div", "device__actions");
  const revokeBtn = el("button", "btn btn--reject", "Revoke");
  revokeBtn.type = "button";
  revokeBtn.disabled = !device.confirmed;
  actions.append(revokeBtn);
  row.append(actions);

  const result = el("p", "note device__result", "");
  result.hidden = true;

  revokeBtn.addEventListener("click", () => {
    result.hidden = false;
    result.textContent = "Revoking…";
    result.classList.remove("note--error", "note--success");
    revokeDevice(device.device_id)
      .then(() => {
        result.textContent = "Device revoked.";
        result.classList.remove("note--error");
        result.classList.add("note--success");
        loadDevices();
      })
      .catch((err) => {
        result.textContent = "Failed to revoke (" + err.message + ").";
        result.classList.remove("note--success");
        result.classList.add("note--error");
      });
  });

  row.append(result);
  return row;
}

function renderDevices() {
  const list = els.devicesList;
  list.textContent = "";
  const devices = Array.from(state.devices.values()).sort((a, b) =>
    (a.created_at || "").localeCompare(b.created_at || "")
  );
  if (devices.length === 0) {
    list.append(emptyNote("No authorised devices."));
    return;
  }
  for (const device of devices) {
    list.append(buildDeviceRow(device));
  }
}

async function loadPairings() {
  try {
    const pairings = await api("/api/pairings");
    state.pairings = new Map(pairings.map((p) => [p.id, p]));
    renderPairings();
  } catch (err) {
    els.pairingsList.textContent = "";
    els.pairingCount.textContent = "";
    els.pairingsList.append(errorNote(err));
  }
}

async function loadDevices() {
  try {
    const devices = await api("/api/devices");
    state.devices = new Map(devices.map((d) => [d.device_id, d]));
    renderDevices();
  } catch (err) {
    els.devicesList.textContent = "";
    els.devicesList.append(errorNote(err));
  }
}

// ---------------------------------------------------------------------------
// task creation form
// ---------------------------------------------------------------------------

function agentLabel(agent) {
  return agent.enabled ? agent.name : agent.name + " (disabled)";
}

function renderAgentOptions() {
  const assignee = els.taskAssignee;
  assignee.textContent = "";
  const placeholder = el("option", null, "Choose an agent…");
  placeholder.value = "";
  assignee.append(placeholder);

  const participants = els.participantsList;
  participants.textContent = "";

  const agents = Array.from(state.agents.values()).sort((a, b) =>
    a.name.localeCompare(b.name)
  );
  if (agents.length === 0) {
    participants.append(emptyNote("No agents registered yet."));
  }

  for (const agent of agents) {
    const option = el("option", null, agentLabel(agent));
    option.value = agent.name;
    assignee.append(option);

    const label = el("label", "participant");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.value = agent.name;
    label.append(box, el("span", "participant__name", agentLabel(agent)));
    participants.append(label);
  }
}

async function loadAgents() {
  try {
    const agents = await api("/api/agents");
    state.agents = new Map(agents.map((a) => [a.name, a]));
    renderAgentOptions();
  } catch (err) {
    state.agents = new Map();
    renderAgentOptions();
  }
}

function coordinationMode() {
  const selected = els.taskForm.querySelector('input[name="coordination"]:checked');
  return selected ? selected.value : "single";
}

function selectedParticipants() {
  const boxes = els.participantsList.querySelectorAll('input[type="checkbox"]');
  const names = [];
  for (const box of boxes) {
    if (box.checked) names.push(box.value);
  }
  return names;
}

function toggleParticipants() {
  els.participantsField.hidden = coordinationMode() !== "multi";
}

function showFormResult(message, isError) {
  const result = els.taskFormResult;
  result.hidden = false;
  result.textContent = message;
  result.classList.toggle("note--error", isError);
  result.classList.toggle("note--success", !isError);
}

async function handleFormSubmit(event) {
  event.preventDefault();
  const payload = {
    title: els.taskTitle.value.trim(),
    body: els.taskBody.value.trim(),
    assignee: els.taskAssignee.value,
    coordination: coordinationMode(),
  };
  if (payload.coordination === "multi") {
    payload.participants = selectedParticipants();
  }

  showFormResult("Dispatching…", false);
  try {
    const data = await postTask(payload);
    const task = data.task;
    showFormResult(
      "Created task " + task.id + " (status: " + task.status + ").",
      false
    );
    els.taskForm.reset();
    els.taskAssignee.value = "";
    toggleParticipants();
    await loadTasks();
    await loadStats();
  } catch (err) {
    showFormResult(
      err && err.message ? err.message : "Failed to dispatch task.",
      true
    );
  }
}

// ---------------------------------------------------------------------------
// data loading
// ---------------------------------------------------------------------------

async function loadStats() {
  try {
    renderStats(await api("/api/stats"));
  } catch (err) {
    els.stats.textContent = "";
    els.stats.append(errorNote(err));
  }
}

async function loadTasks() {
  try {
    const tasks = await api("/api/tasks");
    state.tasks = new Map(tasks.map((t) => [t.id, t]));
    if (state.selectedTaskId && !state.tasks.has(state.selectedTaskId)) {
      state.selectedTaskId = null;
      document.body.classList.remove("detail-open");
    }
    renderTaskList();
  } catch (err) {
    els.taskList.textContent = "";
    els.taskCount.textContent = "";
    els.taskList.append(errorNote(err));
  }
}

async function loadDetail(taskId) {
  try {
    const detail = await api("/api/tasks/" + encodeURIComponent(taskId));
    renderDetail(detail);
  } catch (err) {
    els.taskDetail.textContent = "";
    els.taskDetail.append(errorNote(err));
  }
}

function openTask(taskId) {
  state.selectedTaskId = taskId;
  document.body.classList.add("detail-open");
  renderTaskList();
  loadDetail(taskId);
}

function closeTask() {
  state.selectedTaskId = null;
  document.body.classList.remove("detail-open");
  renderTaskList();
}

// ---------------------------------------------------------------------------
// live updates (SSE)
// ---------------------------------------------------------------------------

let refreshTimer = null;

function scheduleRefresh() {
  if (refreshTimer !== null) return;
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    refresh();
  }, REFRESH_DEBOUNCE_MS);
}

async function refresh() {
  await loadStats();
  await loadTasks();
  await loadApprovals();
  await loadPairings();
  await loadDevices();
  if (state.selectedTaskId) await loadDetail(state.selectedTaskId);
}

function setStreamState(value) {
  els.streamState.dataset.state = value;
  els.streamState.textContent = value;
}

function connectStream() {
  const source = new EventSource("/api/stream");

  source.addEventListener("hello", () => setStreamState("live"));

  for (const table of ["tasks", "runs", "messages", "events", "approvals", "pairings"]) {
    source.addEventListener(table, () => scheduleRefresh());
  }

  // EventSource reconnects on its own (the server sends `retry: 1000`); we
  // just flip the header badge so the owner can see the connection dropped.
  source.onerror = () => setStreamState("reconnecting");
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

async function logout() {
  try {
    await fetch("/api/logout", {
      method: "POST",
      headers: { Accept: "application/json" },
    });
  } catch (err) {
    // Even if the revocation call fails, drop the user back at the login page.
  }
  window.location.assign("/login");
}

function init() {
  els.backButton.addEventListener("click", closeTask);
  if (els.logoutButton) {
    els.logoutButton.addEventListener("click", logout);
  }
  els.taskForm.addEventListener("submit", handleFormSubmit);
  for (const radio of els.taskForm.querySelectorAll('input[name="coordination"]')) {
    radio.addEventListener("change", toggleParticipants);
  }
  toggleParticipants();
  loadAgents();
  loadStats();
  loadTasks();
  loadApprovals();
  loadPairings();
  loadDevices();
  connectStream();
  // Re-render the approvals panel periodically so "time left" stays current
  // even when nothing else changes (approvals expire on a 30-minute budget).
  setInterval(() => {
    if (state.approvals.size > 0) renderApprovals();
  }, 15000);
}

init();
