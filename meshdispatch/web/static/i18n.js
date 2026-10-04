"use strict";

/*
 * meshdispatch i18n.  Plain vanilla JS, no dependencies, no network.
 *
 * The dictionary below is the single source of truth for every user-visible
 * string on both surfaces (the login page and the dashboard).  Look strings up
 * with MDI18N.t(key[, vars]); static markup carries data-i18n attributes that
 * MDI18N.apply() fills in; the chosen language is shared across pages through
 * one localStorage key.
 *
 * Nothing here touches innerHTML: DOM text is always written with textContent
 * (or .placeholder / setAttribute for attributes).
 */

(function (global) {
  const STORAGE_KEY = "meshdispatch.lang";
  const FALLBACK = "en";
  const SUPPORTED = ["en", "zh"];

  const MESSAGES = {
    en: {
      "lang.zh": "中文",
      "lang.en": "English",
      "common.language": "Language",
      "common.principal": "Principal",
      "common.password": "Password",
      "common.signIn": "Sign in",

      "status.pending": "pending",
      "status.running": "running",
      "status.done": "done",
      "status.failed": "failed",
      "status.cancelled": "cancelled",
      "status.blocked": "blocked",
      "status.approved": "approved",
      "status.rejected": "rejected",
      "status.revoked": "revoked",
      "status.expired": "expired",
      "status.high": "high",
      "status.medium": "medium",
      "status.low": "low",
      "origin.cron": "cron",
      "origin.a2a": "a2a",
      "origin.subagent": "subagent",
      "origin.manual": "manual",
      "mode.single": "single-agent",
      "mode.multi": "multi-agent",
      "unit.second": "s",
      "unit.minute": "m",
      "unit.hour": "h",

      "login.title": "meshdispatch — sign in",
      "login.lede": "Sign in to the dashboard.",
      "login.method": "Sign-in method",
      "login.tab.ssh": "SSH key",
      "login.tab.password": "Password",
      "login.ssh.getChallenge": "Get challenge",
      "login.ssh.step1": "1. Sign this nonce on the machine that holds your key",
      "login.ssh.step2": "2. SSH signature",
      "login.ssh.note": "Then paste the contents of the generated signature file below.",
      "login.ssh.signaturePlaceholder": "-----BEGIN SSH SIGNATURE-----",
      "login.ssh.submit": "Sign in with key",
      "login.password.totpLabel": "TOTP code (if required)",
      "login.password.totpPlaceholder": "6-digit code",
      "login.err.unauthorized": "Sign-in failed. Check your credentials and try again.",
      "login.err.totp": "A valid TOTP code is required.",
      "login.err.badRequest": "The request was rejected. Check the fields and try again.",
      "login.err.notConfigured": "Login is not configured on this server.",
      "login.err.http": "Sign-in failed (HTTP {status}).",
      "login.err.principalFirst": "Enter your principal first.",
      "login.ssh.requesting": "Requesting challenge…",
      "login.err.server": "Could not reach the server.",
      "login.err.freshChallenge": "Request a fresh challenge first.",
      "login.err.pasteSignature": "Paste the signature produced by ssh-keygen.",
      "login.ssh.verifying": "Verifying signature…",
      "login.err.credentials": "Enter your principal and password.",
      "login.password.signingIn": "Signing in…",

      "app.stream.connecting": "connecting",
      "app.stream.live": "live",
      "app.stream.reconnecting": "reconnecting",
      "app.stats.label": "Counts by origin and status",
      "app.stats.origin": "origin",
      "app.stats.status": "status",
      "app.stats.none": "none",
      "app.signOut": "Sign out",
      "app.pendingApprovals": "Pending approvals",
      "app.devicesPairing": "Devices & pairing",
      "app.pendingPairings": "Pending pairing requests",
      "app.authorisedDevices": "Authorised devices",
      "app.tasks": "Tasks",
      "app.form.title": "Title",
      "app.form.description": "Description",
      "app.form.assignee": "Assignee",
      "app.form.coordination": "Coordination",
      "app.form.single": "Single-agent",
      "app.form.multi": "Multi-agent",
      "app.form.participants": "Participants",
      "app.form.create": "Create task",
      "app.backToTasks": "← Back to tasks",
      "app.taskDetail": "Task detail",
      "app.meta.id": "id",
      "app.meta.created": "created",
      "app.meta.lastRun": "last run",
      "app.meta.agent": "agent",
      "app.meta.mode": "mode",
      "app.meta.fingerprint": "fingerprint",
      "app.meta.principal": "principal",
      "app.meta.started": "started",
      "app.meta.ended": "ended",
      "app.meta.duration": "duration",
      "app.meta.task": "task",
      "app.meta.requested": "requested",
      "app.meta.timeLeft": "time left",
      "app.field.id": "ID",
      "app.field.mode": "Mode",
      "app.field.status": "Status",
      "app.field.duration": "Duration",
      "app.field.result": "Result",
      "app.field.origin": "Origin",
      "app.field.agent": "Agent",
      "app.field.created": "Created",
      "app.field.lastRun": "Last run",
      "app.section.conversation": "Conversation",
      "app.section.messages": "Messages",
      "app.section.runs": "Runs",
      "app.run.noAgent": "(no agent)",
      "app.run.outcome": "Outcome",
      "app.run.summary": "Summary",
      "app.run.error": "Error",
      "app.tasks.empty": "No tasks recorded yet.",
      "app.runs.empty": "No runs recorded.",
      "app.approvals.empty": "No pending approvals.",
      "app.pairings.empty": "No pending pairing requests.",
      "app.devices.empty": "No authorised devices.",
      "app.approval.command": "command",
      "app.approval.purpose": "Purpose",
      "app.approval.impact": "Impact",
      "app.approval.totp": "TOTP code (required)",
      "app.approval.recorded": "Decision recorded: {status}.",
      "app.pairing.code": "pairing code",
      "app.pairing.codeHint": "compare with what the machine shows",
      "app.pairing.result": "Pairing {status}.",
      "app.request.expired": "This request has expired.",
      "app.approve": "Approve",
      "app.reject": "Reject",
      "app.submitting": "Submitting…",
      "app.totpPlaceholder": "6-digit code",
      "app.device.unnamed": "(unnamed)",
      "app.device.revoke": "Revoke",
      "app.device.revoking": "Revoking…",
      "app.device.revoked": "Device revoked.",
      "app.device.revokeFailed": "Failed to revoke ({message}).",
      "app.agent.disabled": "{name} (disabled)",
      "app.form.chooseAgent": "Choose an agent…",
      "app.form.noAgents": "No agents registered yet.",
      "app.form.dispatching": "Dispatching…",
      "app.form.created": "Created task {id} (status: {status}).",
      "app.form.failed": "Failed to dispatch task.",
      "app.err.authRequired": "Authentication required.",
      "app.err.loadFailed": "Failed to load ({message}).",
      "app.err.approvalTotp": "A valid TOTP code is required for high-risk approvals.",
      "app.err.approvalDecided": "This approval was already decided or has expired.",
      "app.err.approvalMissing": "This approval no longer exists.",
      "app.err.pairingTotp": "A valid TOTP code is required to approve or reject a pairing.",
      "app.err.pairingDecided": "This pairing was already decided or has expired.",
      "app.err.pairingMissing": "This pairing no longer exists.",
      "app.err.decideFailed": "Failed to decide ({message}).",
    },

    zh: {
      "lang.zh": "中文",
      "lang.en": "English",
      "common.language": "语言",
      "common.principal": "用户名",
      "common.password": "密码",
      "common.signIn": "登录",

      "status.pending": "待处理",
      "status.running": "执行中",
      "status.done": "已完成",
      "status.failed": "失败",
      "status.cancelled": "已取消",
      "status.blocked": "受阻",
      "status.approved": "已批准",
      "status.rejected": "已拒绝",
      "status.revoked": "已撤销",
      "status.expired": "已过期",
      "status.high": "高",
      "status.medium": "中",
      "status.low": "低",
      "origin.cron": "定时",
      "origin.a2a": "A2A",
      "origin.subagent": "子代理",
      "origin.manual": "手动",
      "mode.single": "单 Agent",
      "mode.multi": "多 Agent",
      "unit.second": "秒",
      "unit.minute": "分",
      "unit.hour": "时",

      "login.title": "meshdispatch — 登录",
      "login.lede": "登录以访问控制台。",
      "login.method": "登录方式",
      "login.tab.ssh": "SSH 密钥",
      "login.tab.password": "密码",
      "login.ssh.getChallenge": "获取挑战",
      "login.ssh.step1": "1. 在持有密钥的机器上对以下随机数签名",
      "login.ssh.step2": "2. SSH 签名",
      "login.ssh.note": "然后将生成的签名文件内容粘贴到下方。",
      "login.ssh.signaturePlaceholder": "-----BEGIN SSH SIGNATURE-----",
      "login.ssh.submit": "使用密钥登录",
      "login.password.totpLabel": "TOTP 验证码（如需要）",
      "login.password.totpPlaceholder": "6 位验证码",
      "login.err.unauthorized": "登录失败，请检查凭据后重试。",
      "login.err.totp": "需要有效的 TOTP 验证码。",
      "login.err.badRequest": "请求被拒绝，请检查填写内容后重试。",
      "login.err.notConfigured": "此服务器未配置登录功能。",
      "login.err.http": "登录失败（HTTP {status}）。",
      "login.err.principalFirst": "请先输入用户名。",
      "login.ssh.requesting": "正在获取挑战…",
      "login.err.server": "无法连接到服务器。",
      "login.err.freshChallenge": "请先重新获取挑战。",
      "login.err.pasteSignature": "请粘贴 ssh-keygen 生成的签名。",
      "login.ssh.verifying": "正在验证签名…",
      "login.err.credentials": "请输入用户名和密码。",
      "login.password.signingIn": "正在登录…",

      "app.stream.connecting": "连接中",
      "app.stream.live": "实时",
      "app.stream.reconnecting": "重连中",
      "app.stats.label": "按来源和状态统计",
      "app.stats.origin": "来源",
      "app.stats.status": "状态",
      "app.stats.none": "无",
      "app.signOut": "退出登录",
      "app.pendingApprovals": "待审批",
      "app.devicesPairing": "设备与配对",
      "app.pendingPairings": "待处理配对请求",
      "app.authorisedDevices": "已授权设备",
      "app.tasks": "任务",
      "app.form.title": "标题",
      "app.form.description": "描述",
      "app.form.assignee": "执行者",
      "app.form.coordination": "协作方式",
      "app.form.single": "单 Agent",
      "app.form.multi": "多 Agent",
      "app.form.participants": "参与者",
      "app.form.create": "创建任务",
      "app.backToTasks": "← 返回任务列表",
      "app.taskDetail": "任务详情",
      "app.meta.id": "编号",
      "app.meta.created": "创建",
      "app.meta.lastRun": "最近执行",
      "app.meta.agent": "Agent",
      "app.meta.mode": "模式",
      "app.meta.fingerprint": "指纹",
      "app.meta.principal": "用户名",
      "app.meta.started": "开始",
      "app.meta.ended": "结束",
      "app.meta.duration": "耗时",
      "app.meta.task": "任务",
      "app.meta.requested": "申请时间",
      "app.meta.timeLeft": "剩余时间",
      "app.field.id": "编号",
      "app.field.mode": "模式",
      "app.field.status": "状态",
      "app.field.duration": "耗时",
      "app.field.result": "结果",
      "app.field.origin": "来源",
      "app.field.agent": "Agent",
      "app.field.created": "创建时间",
      "app.field.lastRun": "最近执行",
      "app.section.conversation": "对话",
      "app.section.messages": "消息",
      "app.section.runs": "执行记录",
      "app.run.noAgent": "（无 Agent）",
      "app.run.outcome": "结果",
      "app.run.summary": "摘要",
      "app.run.error": "错误",
      "app.tasks.empty": "暂无任务记录。",
      "app.runs.empty": "暂无执行记录。",
      "app.approvals.empty": "暂无待审批项。",
      "app.pairings.empty": "暂无待处理配对请求。",
      "app.devices.empty": "暂无已授权设备。",
      "app.approval.command": "命令",
      "app.approval.purpose": "用途",
      "app.approval.impact": "影响",
      "app.approval.totp": "TOTP 验证码（必填）",
      "app.approval.recorded": "已记录决定：{status}。",
      "app.pairing.code": "配对码",
      "app.pairing.codeHint": "请与设备上显示的配对码核对",
      "app.pairing.result": "配对{status}。",
      "app.request.expired": "该请求已过期。",
      "app.approve": "批准",
      "app.reject": "拒绝",
      "app.submitting": "正在提交…",
      "app.totpPlaceholder": "6 位验证码",
      "app.device.unnamed": "（未命名）",
      "app.device.revoke": "撤销",
      "app.device.revoking": "正在撤销…",
      "app.device.revoked": "设备已撤销。",
      "app.device.revokeFailed": "撤销失败（{message}）。",
      "app.agent.disabled": "{name}（已禁用）",
      "app.form.chooseAgent": "选择 Agent…",
      "app.form.noAgents": "暂无已注册 Agent。",
      "app.form.dispatching": "正在下发…",
      "app.form.created": "已创建任务 {id}（状态：{status}）。",
      "app.form.failed": "任务下发失败。",
      "app.err.authRequired": "需要认证。",
      "app.err.loadFailed": "加载失败（{message}）。",
      "app.err.approvalTotp": "高风险审批需要有效的 TOTP 验证码。",
      "app.err.approvalDecided": "该审批已被处理或已过期。",
      "app.err.approvalMissing": "该审批已不存在。",
      "app.err.pairingTotp": "批准或拒绝配对需要有效的 TOTP 验证码。",
      "app.err.pairingDecided": "该配对已被处理或已过期。",
      "app.err.pairingMissing": "该配对已不存在。",
      "app.err.decideFailed": "操作失败（{message}）。",
    },
  };

  let current = null;
  const listeners = [];

  function normalizeLang(value) {
    if (!value) return null;
    const lower = String(value).toLowerCase();
    if (lower === "zh" || lower.indexOf("zh-") === 0 || lower.indexOf("zh_") === 0) {
      return "zh";
    }
    if (lower === "en" || lower.indexOf("en-") === 0 || lower.indexOf("en_") === 0) {
      return "en";
    }
    return null;
  }

  function storedLang() {
    try {
      return normalizeLang(global.localStorage.getItem(STORAGE_KEY));
    } catch (err) {
      return null;
    }
  }

  function detectLang() {
    const saved = storedLang();
    if (saved) return saved;
    const nav = global.navigator
      ? global.navigator.language ||
        (global.navigator.languages && global.navigator.languages[0])
      : null;
    return normalizeLang(nav) || FALLBACK;
  }

  function getLang() {
    if (!current) current = detectLang();
    return current;
  }

  function locale() {
    return getLang() === "zh" ? "zh-CN" : "en";
  }

  function t(key, vars) {
    const table = MESSAGES[getLang()] || MESSAGES[FALLBACK];
    let text = table[key];
    if (text === undefined) text = MESSAGES[FALLBACK][key];
    if (text === undefined) return key;
    if (vars) {
      text = text.replace(/\{(\w+)\}/g, function (match, name) {
        const value = vars[name];
        return value === undefined || value === null ? match : String(value);
      });
    }
    return text;
  }

  function applyNode(node) {
    const key = node.getAttribute("data-i18n");
    if (key) node.textContent = t(key);
    const placeholder = node.getAttribute("data-i18n-placeholder");
    if (placeholder) node.placeholder = t(placeholder);
    const aria = node.getAttribute("data-i18n-aria-label");
    if (aria) node.setAttribute("aria-label", t(aria));
    const title = node.getAttribute("data-i18n-title");
    if (title) node.setAttribute("title", t(title));
  }

  function apply(root) {
    const doc = global.document;
    if (!doc) return;
    const scope = root || doc;
    if (scope.hasAttribute && scope.hasAttribute("data-i18n")) applyNode(scope);
    if (!scope.querySelectorAll) return;
    const selector =
      "[data-i18n], [data-i18n-placeholder], [data-i18n-aria-label], [data-i18n-title]";
    const nodes = scope.querySelectorAll(selector);
    for (let i = 0; i < nodes.length; i += 1) applyNode(nodes[i]);
    doc.documentElement.setAttribute("lang", getLang() === "zh" ? "zh-CN" : "en");
  }

  function syncToggles() {
    const doc = global.document;
    if (!doc) return;
    const buttons = doc.querySelectorAll("[data-lang-value]");
    for (let i = 0; i < buttons.length; i += 1) {
      const active = buttons[i].getAttribute("data-lang-value") === getLang();
      buttons[i].classList.toggle("is-active", active);
      buttons[i].setAttribute("aria-pressed", active ? "true" : "false");
    }
  }

  function notify() {
    apply();
    syncToggles();
    for (let i = 0; i < listeners.length; i += 1) {
      try {
        listeners[i](getLang());
      } catch (err) {
        /* a misbehaving listener must not block the others */
      }
    }
  }

  function setLang(lang) {
    current = normalizeLang(lang) || FALLBACK;
    try {
      global.localStorage.setItem(STORAGE_KEY, current);
    } catch (err) {
      /* storage unavailable (private mode): the choice lasts this page only */
    }
    notify();
  }

  function onChange(callback) {
    if (typeof callback === "function") listeners.push(callback);
  }

  function boot() {
    notify();
  }

  const MDI18N = {
    STORAGE_KEY: STORAGE_KEY,
    SUPPORTED: SUPPORTED,
    t: t,
    getLang: getLang,
    setLang: setLang,
    locale: locale,
    onChange: onChange,
    apply: apply,
    syncToggles: syncToggles,
  };

  global.MDI18N = MDI18N;

  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", boot);
    } else {
      boot();
    }
    global.document.addEventListener("click", function (event) {
      const target = event.target;
      if (!target || !target.closest) return;
      const button = target.closest("[data-lang-value]");
      if (button) setLang(button.getAttribute("data-lang-value"));
    });
  }
})(typeof window !== "undefined" ? window : this);
