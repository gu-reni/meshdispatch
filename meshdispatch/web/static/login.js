"use strict";

/*
 * meshdispatch login.  Plain vanilla JS, no dependencies.
 *
 * Account-and-password only.  The SSH public-key signature path was removed:
 * it required every user to run ssh-keygen locally against a nonce, which is
 * more machinery than this deployment wants.  The auth layer still supports key
 * signatures - this page simply does not offer them.
 *
 * All dynamic values (server error messages) reach the page through
 * `textContent` only; nothing is ever assigned to `innerHTML`.  The password is
 * sent in the request body and is never logged or rendered.
 *
 * Every user-visible string goes through the shared MDI18N table (i18n.js).
 */

const t = MDI18N.t;

const els = {
  passwordPrincipal: document.getElementById("password-principal"),
  passwordValue: document.getElementById("password-value"),
  passwordTotp: document.getElementById("password-totp"),
  passwordSubmit: document.getElementById("password-submit"),
  passwordResult: document.getElementById("password-result"),
};

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
  els.passwordSubmit.addEventListener("click", submitPassword);
  els.passwordValue.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitPassword();
  });
  els.passwordPrincipal.addEventListener("keydown", (event) => {
    if (event.key === "Enter") els.passwordValue.focus();
  });
}

init();
