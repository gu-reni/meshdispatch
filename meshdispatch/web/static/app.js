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
};

const state = {
  tasks: new Map(),
  selectedTaskId: null,
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

function describeError(err) {
  if (err && err.status === 401) return "Authentication required.";
  return "Failed to load (" + (err && err.message ? err.message : "network error") + ").";
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
  if (state.selectedTaskId) await loadDetail(state.selectedTaskId);
}

function setStreamState(value) {
  els.streamState.dataset.state = value;
  els.streamState.textContent = value;
}

function connectStream() {
  const source = new EventSource("/api/stream");

  source.addEventListener("hello", () => setStreamState("live"));

  for (const table of ["tasks", "runs", "messages", "events"]) {
    source.addEventListener(table, () => scheduleRefresh());
  }

  // EventSource reconnects on its own (the server sends `retry: 1000`); we
  // just flip the header badge so the owner can see the connection dropped.
  source.onerror = () => setStreamState("reconnecting");
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

function init() {
  els.backButton.addEventListener("click", closeTask);
  loadStats();
  loadTasks();
  connectStream();
}

init();
