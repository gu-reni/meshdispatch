"use strict";

/*
 * meshdispatch login.  Plain vanilla JS, no dependencies.
 *
 * All dynamic values (the nonce, server error messages) reach the page through
 * `textContent` only; nothing is ever assigned to `innerHTML`.  Passwords and
 * signatures are sent in the request body and are never logged or rendered.
 *
 * Every user-visible string goes through the shared MDI18N table (i18n.js).
 */

const t = MDI18N.t;

const els = {
  tabSsh: document.getElementById("tab-ssh"),
  tabPassword: document.getElementById("tab-password"),
  panelSsh: document.getElementById("panel-ssh"),
  panelPassword: document.getElementById("panel-password"),
  sshPrincipal: document.getElementById("ssh-principal"),
  sshChallenge: document.getElementById("ssh-challenge"),
  sshSteps: document.getElementById("ssh-steps"),
  sshCommand: document.getElementById("ssh-command"),
  sshSignature: document.getElementById("ssh-signature"),
  sshSubmit: document.getElementById("ssh-submit"),
  sshResult: document.getElementById("ssh-result"),
  passwordPrincipal: document.getElementById("password-principal"),
  passwordValue: document.getElementById("password-value"),
  passwordTotp: document.getElementById("password-totp"),
  passwordSubmit: document.getElementById("password-submit"),
  passwordResult: document.getElementById("password-result"),
};

let currentNonce = null;

// Each result line remembers the *key* (not the rendered text) so it can be
// re-rendered in the new language the moment the toggle changes.
const resultStates = new Map();

function msg(key, vars) {
  return { key: key, vars: vars || null };
}

function renderResult(node) {
  const state = resultStates.get(node);
  if (!state) return;
  node.textContent = t(state.key, state.vars);
  node.className = state.isError
    ? "note note--error task-form__result"
    : "note note--success task-form__result";
  node.hidden = false;
}

function setResult(node, descriptor, isError) {
  resultStates.set(node, { key: descriptor.key, vars: descriptor.vars, isError: isError });
  renderResult(node);
}

function clearResult(node) {
  resultStates.delete(node);
  node.hidden = true;
}

function refreshMessages() {
  for (const node of resultStates.keys()) renderResult(node);
}

function selectTab(which) {
  const ssh = which === "ssh";
  els.tabSsh.classList.toggle("login__tab--active", ssh);
  els.tabPassword.classList.toggle("login__tab--active", !ssh);
  els.tabSsh.setAttribute("aria-selected", String(ssh));
  els.tabPassword.setAttribute("aria-selected", String(!ssh));
  els.panelSsh.hidden = !ssh;
  els.panelPassword.hidden = ssh;
}

async function postLogin(payload) {
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  let data = null;
  try {
    data = await res.json();
  } catch (err) {
    data = null;
  }
  return { status: res.status, data: data };
}

function loginError(result) {
  if (result.status === 401) return msg("login.err.unauthorized");
  if (result.status === 403) return msg("login.err.totp");
  if (result.status === 400) return msg("login.err.badRequest");
  if (result.status === 501) return msg("login.err.notConfigured");
  return msg("login.err.http", { status: result.status });
}

function succeed() {
  window.location.assign("/");
}

function commandFor(nonce, namespace) {
  return (
    "printf '%s' '" + nonce + "' | " +
    "ssh-keygen -Y sign -n " + namespace + " -f ~/.ssh/id_ed25519 - > meshdispatch.sig"
  );
}

async function requestChallenge() {
  const principal = els.sshPrincipal.value.trim();
  if (!principal) {
    setResult(els.sshResult, msg("login.err.principalFirst"), true);
    return;
  }
  els.sshChallenge.disabled = true;
  setResult(els.sshResult, msg("login.ssh.requesting"), false);
  try {
    const result = await postLogin({
      method: "ssh",
      action: "challenge",
      principal: principal,
    });
    if (result.status !== 200 || !result.data || !result.data.nonce) {
      setResult(els.sshResult, loginError(result), true);
      return;
    }
    currentNonce = result.data.nonce;
    const namespace = result.data.namespace || "meshdispatch";
    els.sshCommand.textContent = commandFor(currentNonce, namespace);
    els.sshSteps.hidden = false;
    clearResult(els.sshResult);
  } catch (err) {
    setResult(els.sshResult, msg("login.err.server"), true);
  } finally {
    els.sshChallenge.disabled = false;
  }
}

async function submitSsh() {
  const principal = els.sshPrincipal.value.trim();
  const signature = els.sshSignature.value.trim();
  if (!principal || !currentNonce) {
    setResult(els.sshResult, msg("login.err.freshChallenge"), true);
    return;
  }
  if (!signature) {
    setResult(els.sshResult, msg("login.err.pasteSignature"), true);
    return;
  }
  els.sshSubmit.disabled = true;
  setResult(els.sshResult, msg("login.ssh.verifying"), false);
  try {
    const result = await postLogin({
      method: "ssh",
      principal: principal,
      nonce: currentNonce,
      signature: signature,
    });
    if (result.status === 200) {
      succeed();
      return;
    }
    setResult(els.sshResult, loginError(result), true);
  } catch (err) {
    setResult(els.sshResult, msg("login.err.server"), true);
  } finally {
    els.sshSubmit.disabled = false;
  }
}

async function submitPassword() {
  const principal = els.passwordPrincipal.value.trim();
  const password = els.passwordValue.value;
  if (!principal || !password) {
    setResult(els.passwordResult, msg("login.err.credentials"), true);
    return;
  }
  els.passwordSubmit.disabled = true;
  setResult(els.passwordResult, msg("login.password.signingIn"), false);
  try {
    const result = await postLogin({
      method: "password",
      principal: principal,
      password: password,
      totp: els.passwordTotp.value.trim(),
    });
    if (result.status === 200) {
      succeed();
      return;
    }
    setResult(els.passwordResult, loginError(result), true);
  } catch (err) {
    setResult(els.passwordResult, msg("login.err.server"), true);
  } finally {
    els.passwordSubmit.disabled = false;
  }
}

function init() {
  MDI18N.apply();
  MDI18N.syncToggles();
  MDI18N.onChange(refreshMessages);
  els.tabSsh.addEventListener("click", () => selectTab("ssh"));
  els.tabPassword.addEventListener("click", () => selectTab("password"));
  els.sshChallenge.addEventListener("click", requestChallenge);
  els.sshSubmit.addEventListener("click", submitSsh);
  els.passwordSubmit.addEventListener("click", submitPassword);
  els.passwordValue.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitPassword();
  });
}

init();
