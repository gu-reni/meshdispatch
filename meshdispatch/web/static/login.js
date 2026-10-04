"use strict";

/*
 * meshdispatch login.  Plain vanilla JS, no dependencies.
 *
 * All dynamic values (the nonce, server error messages) reach the page through
 * `textContent` only; nothing is ever assigned to `innerHTML`.  Passwords and
 * signatures are sent in the request body and are never logged or rendered.
 */

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

function setResult(node, message, isError) {
  node.textContent = message;
  node.className = isError
    ? "note note--error task-form__result"
    : "note note--success task-form__result";
  node.hidden = false;
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
  if (result.status === 401) return "Sign-in failed. Check your credentials and try again.";
  if (result.status === 403) return "A valid TOTP code is required.";
  if (result.status === 400) return "The request was rejected. Check the fields and try again.";
  if (result.status === 501) return "Login is not configured on this server.";
  return "Sign-in failed (HTTP " + result.status + ").";
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
    setResult(els.sshResult, "Enter your principal first.", true);
    return;
  }
  els.sshChallenge.disabled = true;
  setResult(els.sshResult, "Requesting challenge…", false);
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
    els.sshResult.hidden = true;
  } catch (err) {
    setResult(els.sshResult, "Could not reach the server.", true);
  } finally {
    els.sshChallenge.disabled = false;
  }
}

async function submitSsh() {
  const principal = els.sshPrincipal.value.trim();
  const signature = els.sshSignature.value.trim();
  if (!principal || !currentNonce) {
    setResult(els.sshResult, "Request a fresh challenge first.", true);
    return;
  }
  if (!signature) {
    setResult(els.sshResult, "Paste the signature produced by ssh-keygen.", true);
    return;
  }
  els.sshSubmit.disabled = true;
  setResult(els.sshResult, "Verifying signature…", false);
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
    setResult(els.sshResult, "Could not reach the server.", true);
  } finally {
    els.sshSubmit.disabled = false;
  }
}

async function submitPassword() {
  const principal = els.passwordPrincipal.value.trim();
  const password = els.passwordValue.value;
  if (!principal || !password) {
    setResult(els.passwordResult, "Enter your principal and password.", true);
    return;
  }
  els.passwordSubmit.disabled = true;
  setResult(els.passwordResult, "Signing in…", false);
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
    setResult(els.passwordResult, "Could not reach the server.", true);
  } finally {
    els.passwordSubmit.disabled = false;
  }
}

function init() {
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
