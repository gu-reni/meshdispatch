"""Tests for meshdispatch phase 3: layered authentication.

Covers the frozen interface plus every authentication layer from DESIGN.md:
SSH public-key signature, account+TOTP, GitHub OAuth, device enrollment and
confirmation, signed/revocable sessions, the append-only audit log, and the
optional LAN MAC whitelist.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import time

import pytest

from meshdispatch.auth import (
    AuthConfig,
    AuthManager,
    Identity,
    PrincipalConfig,
    build_ssh_signature,
    configure,
    enroll_device as module_enroll_device,
    revoke_all_sessions as module_revoke_all,
    authenticate as module_authenticate,
    generate_rsa_keypair,
    hash_password,
    serialize_ssh_public_key,
    totp_at,
    totp_verify,
    verify_password,
)
from meshdispatch.auth.crypto import verify_ssh_signature
from meshdispatch.auth.ssh import SSH_SIGN_NAMESPACE, verify_signature_for_keys

TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # base32, well-known RFC test vector


class Req:
    """Minimal stand-in for the web layer's lightweight request object."""

    def __init__(
        self,
        headers=None,
        cookies=None,
        client_ip=None,
        path="",
        query=None,
    ):
        self.headers = dict(headers or {})
        self.cookies = dict(cookies or {})
        self.client_ip = client_ip
        self.path = path
        self.query = dict(query or {})


class Clock:
    """Deterministic injectable clock."""

    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture(scope="module")
def keypair():
    return generate_rsa_keypair(bits=1024)


@pytest.fixture(scope="module")
def other_keypair():
    return generate_rsa_keypair(bits=1024)


_MANAGER_KWARGS = {"now", "state_dir", "github_exchange", "github_user", "arp_reader"}


def make_manager(**kwargs):
    manager_kwargs = {}
    config_kwargs = {}
    for k, v in kwargs.items():
        if k in _MANAGER_KWARGS:
            manager_kwargs[k] = v
        else:
            config_kwargs[k] = v
    config_kwargs.setdefault("cookie_signing_key", "unit-test-signing-key")
    return AuthManager(AuthConfig(**config_kwargs), **manager_kwargs)


def ssh_headers(private, principal, nonce, **extra):
    sig = base64.b64encode(
        build_ssh_signature(private, nonce.encode("utf-8"))
    ).decode("ascii")
    headers = {
        "X-Mesh-Principal": principal,
        "X-Mesh-Nonce": nonce,
        "X-Mesh-Signature": sig,
    }
    headers.update(extra)
    return headers


def basic_auth(principal, password):
    token = base64.b64encode(f"{principal}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


# ---------------------------------------------------------------------------
# Identity layer: SSH public-key signature
# ---------------------------------------------------------------------------


def test_ssh_signature_success(keypair):
    m = make_manager()
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")

    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert isinstance(ident, Identity)
    assert ident.principal == "gu-reni"
    assert ident.method == "ssh"
    # First login auto-claims a device.
    assert ident.device_id is not None


def test_ssh_wrong_public_key(keypair, other_keypair):
    m = make_manager()
    # Register only *other* key; sign with *keypair*.
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(other_keypair, "other"))
    nonce = m.issue_nonce("gu-reni")

    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert ident is None


def test_ssh_wrong_signature(keypair):
    m = make_manager()
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")

    # Sign a *different* message than the nonce we send.
    bad_sig = base64.b64encode(
        build_ssh_signature(keypair, b"some-other-nonce")
    ).decode("ascii")
    ident = m.authenticate(
        Req(
            headers={
                "X-Mesh-Principal": "gu-reni",
                "X-Mesh-Nonce": nonce,
                "X-Mesh-Signature": bad_sig,
            },
            client_ip="192.168.1.5",
        )
    )
    assert ident is None


def test_ssh_nonce_single_use(keypair):
    m = make_manager()
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    req = Req(
        headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5"
    )

    assert m.authenticate(req) is not None
    # Replaying the exact same signed nonce must fail.
    assert m.authenticate(req) is None


def test_ssh_nonce_expired(keypair):
    clock = Clock()
    m = make_manager(now=clock)
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")  # ttl = config.nonce_ttl (120s)
    clock.t += 121  # advance past expiry

    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert ident is None


def test_ssh_unregistered_principal(keypair):
    m = make_manager()
    # No authorized keys registered for anyone.
    nonce = m.issue_nonce("gu-reni")
    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert ident is None


# ---------------------------------------------------------------------------
# Identity layer: TOTP (RFC 6238)
# ---------------------------------------------------------------------------


def test_totp_correct_code():
    code = totp_at(TOTP_SECRET, 0)
    assert code == "282760"
    assert totp_verify(TOTP_SECRET, code, now=0) is True


def test_totp_wrong_code():
    assert totp_verify(TOTP_SECRET, "000000", now=0) is False
    assert totp_verify(TOTP_SECRET, "123456", now=0) is False


def test_totp_window_boundaries():
    # Code generated for step 1 must verify at step 0 (window +1).
    code_next = totp_at(TOTP_SECRET, 30)
    assert totp_verify(TOTP_SECRET, code_next, now=0, window=1) is True
    # ...but not with a zero window.
    assert totp_verify(TOTP_SECRET, code_next, now=0, window=0) is False
    # A code two steps out is rejected even with window 1.
    code_two = totp_at(TOTP_SECRET, 60)
    assert totp_verify(TOTP_SECRET, code_two, now=0, window=1) is False


# ---------------------------------------------------------------------------
# Identity layer: password hashing
# ---------------------------------------------------------------------------


def test_password_hash_verify_correct_and_wrong():
    stored = hash_password("correct-horse-battery")
    assert verify_password("correct-horse-battery", stored) is True
    assert verify_password("wrong-password", stored) is False


def test_password_hash_salted_unique():
    assert hash_password("same") != hash_password("same")


# ---------------------------------------------------------------------------
# Identity layer: account password (+TOTP) end to end
# ---------------------------------------------------------------------------


def test_password_login_lan_no_totp():
    m = make_manager(device_enforcement=False)
    m.set_password("gu-reni", "s3cret-pw")
    ident = m.authenticate(
        Req(
            headers={"Authorization": basic_auth("gu-reni", "s3cret-pw")},
            client_ip="192.168.1.5",
        )
    )
    assert isinstance(ident, Identity)
    assert ident.method == "password"


def test_password_login_wrong_password():
    m = make_manager(device_enforcement=False)
    m.set_password("gu-reni", "s3cret-pw")
    assert (
        m.authenticate(
            Req(
                headers={"Authorization": basic_auth("gu-reni", "nope")},
                client_ip="192.168.1.5",
            )
        )
        is None
    )


def test_password_login_public_requires_totp():
    clock = Clock()
    m = make_manager(device_enforcement=False, now=clock)
    m.set_password("gu-reni", "s3cret-pw")
    m.set_totp_secret("gu-reni", TOTP_SECRET)
    auth = {"Authorization": basic_auth("gu-reni", "s3cret-pw")}

    # Public IP without TOTP -> denied.
    assert m.authenticate(Req(headers=auth, client_ip="8.8.8.8")) is None

    # Public IP with a valid TOTP -> allowed.
    code = totp_at(TOTP_SECRET, int(clock()))
    ident = m.authenticate(
        Req(headers={**auth, "X-Mesh-Totp": code}, client_ip="8.8.8.8")
    )
    assert isinstance(ident, Identity)
    assert ident.method == "password"


def test_password_login_public_wrong_totp():
    clock = Clock()
    m = make_manager(device_enforcement=False, now=clock)
    m.set_password("gu-reni", "s3cret-pw")
    m.set_totp_secret("gu-reni", TOTP_SECRET)
    ident = m.authenticate(
        Req(
            headers={
                "Authorization": basic_auth("gu-reni", "s3cret-pw"),
                "X-Mesh-Totp": "000000",
            },
            client_ip="8.8.8.8",
        )
    )
    assert ident is None


# ---------------------------------------------------------------------------
# Identity layer: GitHub OAuth
# ---------------------------------------------------------------------------


def _github_config(**kw):
    cfg = dict(
        github_enabled=True,
        github_client_id="client-id-123",
        github_client_secret="secret-from-config-not-code",
        github_redirect_uri="https://example.invalid/oauth/callback",
        device_enforcement=False,
    )
    cfg.update(kw)
    return cfg


def _github_manager(state=None):
    def exchange(code):
        assert code == "authcode-xyz"
        return {"access_token": "gho_testtoken123456"}

    def user(token):
        assert token == "gho_testtoken123456"
        return {"login": "gu-reni", "id": 42}

    return AuthManager(
        AuthConfig(**_github_config()),
        github_exchange=exchange,
        github_user=user,
    )


def test_github_oauth_success():
    m = _github_manager()
    state = m.issue_oauth_state()
    ident = m.authenticate(
        Req(
            path="/oauth/callback",
            query={"code": "authcode-xyz", "state": state},
            client_ip="8.8.8.8",
        )
    )
    assert isinstance(ident, Identity)
    assert ident.method == "github"
    assert ident.principal == "gu-reni"


def test_github_oauth_bad_state_csrf():
    m = _github_manager()
    m.issue_oauth_state()  # a valid state exists, but the request forges another
    ident = m.authenticate(
        Req(
            path="/oauth/callback",
            query={"code": "authcode-xyz", "state": "forged-state"},
            client_ip="8.8.8.8",
        )
    )
    assert ident is None


def test_github_oauth_state_single_use():
    m = _github_manager()
    state = m.issue_oauth_state()
    req = Req(
        path="/oauth/callback",
        query={"code": "authcode-xyz", "state": state},
        client_ip="8.8.8.8",
    )
    assert m.authenticate(req) is not None
    assert m.authenticate(req) is None  # state consumed


def test_github_client_secret_from_env(monkeypatch):
    monkeypatch.setenv("MESHDISPATCH_GITHUB_CLIENT_SECRET", "env-secret-abc")
    cfg = AuthConfig.from_env(github_client_id="cid")
    assert cfg.github_client_secret == "env-secret-abc"


# ---------------------------------------------------------------------------
# Device layer
# ---------------------------------------------------------------------------


def test_first_device_auto_confirmed():
    m = make_manager()
    device_id = m.enroll_device("gu-reni", device_name="laptop")
    assert device_id
    rec = m.store.get_device(device_id)
    assert rec["confirmed"] is True


def test_second_device_pending_confirmation():
    m = make_manager()
    first = m.enroll_device("gu-reni", device_name="laptop")
    second = m.enroll_device("gu-reni", device_name="phone")
    assert m.store.get_device(first)["confirmed"] is True
    assert m.store.get_device(second)["confirmed"] is False


def test_new_device_unconfirmed_rejected_until_confirmed(keypair):
    m = make_manager()
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))

    # First device is claimed during the first login.
    nonce1 = m.issue_nonce("gu-reni")
    m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce1), client_ip="192.168.1.5")
    )

    # Enroll a *second* device (created unconfirmed).
    second = m.enroll_device("gu-reni", device_name="phone")
    second_key = m.get_device_key(second)

    # Logging in from that unconfirmed device is rejected.
    nonce2 = m.issue_nonce("gu-reni")
    rejected = m.authenticate(
        Req(
            headers=ssh_headers(
                keypair,
                "gu-reni",
                nonce2,
                **{"X-Mesh-Device-Id": second, "X-Mesh-Device-Key": second_key},
            ),
            client_ip="192.168.1.5",
        )
    )
    assert rejected is None

    # After confirmation the same device is accepted.
    assert m.confirm_device(second, approver_principal="gu-reni") is True
    nonce3 = m.issue_nonce("gu-reni")
    accepted = m.authenticate(
        Req(
            headers=ssh_headers(
                keypair,
                "gu-reni",
                nonce3,
                **{"X-Mesh-Device-Id": second, "X-Mesh-Device-Key": second_key},
            ),
            client_ip="192.168.1.5",
        )
    )
    assert isinstance(accepted, Identity)
    assert accepted.device_id == second


def test_device_key_never_stored_in_plaintext(keypair):
    m = make_manager()
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    device_id = m.store.list_devices("gu-reni")[0]["device_id"]
    raw_key = m.get_device_key(device_id)
    assert raw_key  # handed out exactly once
    rec = m.store.get_device(device_id)
    assert "key" not in rec
    assert rec["key_hash"] != raw_key
    assert raw_key not in rec["key_hash"]


def test_device_bad_key_rejected(keypair):
    m = make_manager()
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    device_id = m.store.list_devices("gu-reni")[0]["device_id"]
    nonce2 = m.issue_nonce("gu-reni")
    ident = m.authenticate(
        Req(
            headers=ssh_headers(
                keypair,
                "gu-reni",
                nonce2,
                **{"X-Mesh-Device-Id": device_id, "X-Mesh-Device-Key": "not-the-key"},
            ),
            client_ip="192.168.1.5",
        )
    )
    assert ident is None


# ---------------------------------------------------------------------------
# Session layer
# ---------------------------------------------------------------------------


def _session_request(m, cookie):
    return Req(cookies={m.config.cookie_name: cookie}, client_ip="192.168.1.5")


def test_session_roundtrip():
    m = make_manager()
    cookie = m.issue_session("gu-reni", "ssh", device_id="dev-1", ip="192.168.1.5")
    ident = m.authenticate(_session_request(m, cookie))
    assert isinstance(ident, Identity)
    assert ident.principal == "gu-reni"
    assert ident.method == "ssh"
    assert ident.device_id == "dev-1"


def test_session_expired():
    clock = Clock()
    m = make_manager(now=clock)
    cookie = m.issue_session("gu-reni", "ssh")
    clock.t += m.config.session_ttl + 1
    assert m.authenticate(_session_request(m, cookie)) is None


def test_session_tampered_cookie_rejected():
    m = make_manager()
    cookie = m.issue_session("gu-reni", "ssh")
    # Tamper the *payload* (before the dot): flipping the first payload char
    # always changes the decoded bytes, so the HMAC must mismatch.  (The
    # original flipped the last char of the base64url signature, which only
    # changes ignored padding bits ~1/4 of the time and is flaky.)
    payload, sep, sig = cookie.partition(".")
    flipped_payload = ("A" if payload[0] != "A" else "B") + payload[1:]
    flipped = flipped_payload + sep + sig
    assert flipped != cookie
    assert m.authenticate(_session_request(m, flipped)) is None


def test_revoke_all_sessions_invalidates_old_cookie():
    m = make_manager()
    c1 = m.issue_session("gu-reni", "ssh")
    c2 = m.issue_session("gu-reni", "password")
    c3 = m.issue_session("other-user", "ssh")

    assert m.authenticate(_session_request(m, c1)) is not None

    revoked = m.revoke_all_sessions("gu-reni")
    assert revoked == 2

    assert m.authenticate(_session_request(m, c1)) is None
    assert m.authenticate(_session_request(m, c2)) is None
    # Other principals' sessions are untouched.
    assert m.authenticate(_session_request(m, c3)) is not None


def test_revoke_session_single():
    m = make_manager()
    m.issue_session("gu-reni", "ssh")
    m.issue_session("gu-reni", "ssh")
    sids = [sid for sid, _ in m.store.list_sessions("gu-reni")]
    assert len(sids) == 2
    assert m.revoke_session(sids[0]) is True
    assert len(m.store.list_sessions("gu-reni")) == 1
    # Revoking the already-revoked id is a no-op.
    assert m.revoke_session(sids[0]) is False


# ---------------------------------------------------------------------------
# Audit layer
# ---------------------------------------------------------------------------


def test_audit_records_login_approval_revocation(tmp_path, keypair):
    m = AuthManager(
        AuthConfig(cookie_signing_key="k"),
        state_dir=str(tmp_path),
    )
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))

    nonce = m.issue_nonce("gu-reni")
    m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    # Failed login is also audited (wrong signature).
    bad_nonce = m.issue_nonce("gu-reni")
    bad_sig = base64.b64encode(build_ssh_signature(keypair, b"wrong-message")).decode()
    m.authenticate(
        Req(
            headers={
                "X-Mesh-Principal": "gu-reni",
                "X-Mesh-Nonce": bad_nonce,
                "X-Mesh-Signature": bad_sig,
            },
            client_ip="192.168.1.5",
        )
    )

    second = m.enroll_device("gu-reni", device_name="phone")
    m.confirm_device(second, approver_principal="gu-reni")
    m.issue_session("gu-reni", "ssh")
    m.revoke_all_sessions("gu-reni")

    entries = m.store.audit.read_from_disk()
    events = [e["event"] for e in entries]
    assert "login" in events
    assert "device_claim" in events or "device_claimed" in events
    assert "device_enroll" in events
    assert "device_approve" in events
    assert "session_revoke_all" in events

    # Every entry carries a timestamp, identity where relevant, and result.
    for e in entries:
        assert e["ts"].endswith("Z")
        assert "result" in e


def test_audit_append_only(tmp_path, keypair):
    m = AuthManager(AuthConfig(cookie_signing_key="k"), state_dir=str(tmp_path))
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    path = tmp_path / "audit.jsonl"
    assert path.exists()
    lines = path.read_text().strip().splitlines()
    assert len(lines) >= 1
    for line in lines:
        json.loads(line)  # each line is valid JSON


# ---------------------------------------------------------------------------
# Optional LAN MAC whitelist
# ---------------------------------------------------------------------------


def test_mac_whitelist_lan_match(keypair):
    def arp():
        return "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"

    m = AuthManager(
        AuthConfig(
            cookie_signing_key="k",
            mac_whitelist_enabled=True,
            mac_whitelist={"gu-reni": ["aa:bb:cc:dd:ee:ff"]},
        ),
        arp_reader=arp,
    )
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert isinstance(ident, Identity)


def test_mac_whitelist_lan_mismatch(keypair):
    def arp():
        return "192.168.1.5 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"

    m = AuthManager(
        AuthConfig(
            cookie_signing_key="k",
            mac_whitelist_enabled=True,
            mac_whitelist={"gu-reni": ["aa:bb:cc:dd:ee:ff"]},
        ),
        arp_reader=arp,
    )
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert ident is None


def test_mac_whitelist_public_skipped(keypair):
    # Public traffic always skips the MAC check, even if the whitelist cannot
    # possibly match (DESIGN.md: MAC binding is impossible over the internet).
    def arp():
        return ""

    m = AuthManager(
        AuthConfig(
            cookie_signing_key="k",
            mac_whitelist_enabled=True,
            mac_whitelist={"gu-reni": ["aa:bb:cc:dd:ee:ff"]},
        ),
        arp_reader=arp,
    )
    m.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))
    nonce = m.issue_nonce("gu-reni")
    ident = m.authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="93.184.216.34")
    )
    assert isinstance(ident, Identity)


# ---------------------------------------------------------------------------
# Default deny + frozen interface
# ---------------------------------------------------------------------------


def test_unauthenticated_request_returns_none():
    m = make_manager()
    assert m.authenticate(Req()) is None
    assert m.authenticate(Req(headers={"Authorization": "Basic nonsense"})) is None
    assert m.authenticate(None) is None


def test_identity_dataclass_shape():
    ident = Identity(principal="gu-reni", method="ssh", device_id=None)
    assert ident.principal == "gu-reni"
    assert ident.method == "ssh"
    assert ident.device_id is None


def test_module_level_frozen_interface(keypair):
    mgr = configure(AuthConfig(cookie_signing_key="k"))
    mgr.add_authorized_key("gu-reni", serialize_ssh_public_key(keypair, "laptop"))

    nonce = mgr.issue_nonce("gu-reni")
    ident = module_authenticate(
        Req(headers=ssh_headers(keypair, "gu-reni", nonce), client_ip="192.168.1.5")
    )
    assert isinstance(ident, Identity)

    device_id = module_enroll_device("gu-reni", device_name="phone")
    assert device_id

    cookie = mgr.issue_session("gu-reni", "ssh")
    assert module_authenticate(
        Req(cookies={"meshdispatch_session": cookie}, client_ip="192.168.1.5")
    ) is not None
    assert module_revoke_all("gu-reni") >= 1


# ---------------------------------------------------------------------------
# ssh-keygen -Y verify path (ed25519 / ecdsa / rsa, armoured signatures)
# ---------------------------------------------------------------------------

_SSH_KEYGEN = shutil.which("ssh-keygen")
needs_ssh_keygen = pytest.mark.skipif(
    _SSH_KEYGEN is None, reason="ssh-keygen not available on this host"
)


def _run(*argv, **kw):
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=30, **kw
    )


def _gen_ssh_key(tmp_path, keytype: str, name: str) -> tuple[str, str, str]:
    """Generate a key with ``ssh-keygen``; return (priv_path, pub_path, pub_line)."""
    priv = str(tmp_path / name)
    pub = priv + ".pub"
    proc = _run(
        _SSH_KEYGEN, "-t", keytype, "-N", "", "-f", priv, "-C", f"{name}@test"
    )
    assert proc.returncode == 0, proc.stderr
    pub_line = open(pub, encoding="utf-8").read().strip()
    return priv, pub, pub_line


def _sign_with_ssh_keygen(priv_path: str, nonce: str, msg_path: str) -> str:
    """Sign ``nonce`` with ``ssh-keygen -Y sign``; return the armoured block."""
    with open(msg_path, "wb") as fh:
        fh.write(nonce.encode("utf-8"))
    proc = _run(
        _SSH_KEYGEN, "-Y", "sign", "-f", priv_path, "-n", SSH_SIGN_NAMESPACE, msg_path
    )
    assert proc.returncode == 0, proc.stderr
    return open(msg_path + ".sig", encoding="utf-8").read()


@needs_ssh_keygen
def test_ssh_keygen_ed25519_armored_verify(tmp_path):
    priv, _, pub_line = _gen_ssh_key(tmp_path, "ed25519", "ed")
    nonce = "ed25519-e2e-nonce"
    armored = _sign_with_ssh_keygen(priv, nonce, str(tmp_path / "msg.txt"))

    assert verify_signature_for_keys(
        nonce, armored, [pub_line], principal="alice"
    ) is True


@needs_ssh_keygen
def test_ssh_keygen_ed25519_base64_armored_verify(tmp_path):
    priv, _, pub_line = _gen_ssh_key(tmp_path, "ed25519", "ed")
    nonce = "ed25519-e2e-nonce"
    armored = _sign_with_ssh_keygen(priv, nonce, str(tmp_path / "msg.txt"))
    b64 = base64.b64encode(armored.encode("utf-8")).decode("ascii")

    assert verify_signature_for_keys(
        nonce, b64, [pub_line], principal="alice"
    ) is True


@needs_ssh_keygen
def test_ssh_keygen_ed25519_wrong_key_rejected(tmp_path):
    priv, _, _ = _gen_ssh_key(tmp_path, "ed25519", "ed")
    _, _, other_pub = _gen_ssh_key(tmp_path, "ed25519", "other")
    nonce = "ed25519-e2e-nonce"
    armored = _sign_with_ssh_keygen(priv, nonce, str(tmp_path / "msg.txt"))

    # Signature made by ``ed`` but only ``other`` is registered -> deny.
    assert verify_signature_for_keys(
        nonce, armored, [other_pub], principal="alice"
    ) is False


@needs_ssh_keygen
def test_ssh_keygen_ed25519_tampered_nonce_rejected(tmp_path):
    priv, _, pub_line = _gen_ssh_key(tmp_path, "ed25519", "ed")
    armored = _sign_with_ssh_keygen(priv, "real-nonce", str(tmp_path / "msg.txt"))

    # The signature is over "real-nonce"; verifying a different nonce fails.
    assert verify_signature_for_keys(
        "different-nonce", armored, [pub_line], principal="alice"
    ) is False


@needs_ssh_keygen
def test_ssh_keygen_supports_rsa_and_ecdsa(tmp_path):
    # ssh-keygen decides the key type; rsa + ecdsa must also verify.
    for keytype in ("rsa", "ecdsa"):
        priv, _, pub_line = _gen_ssh_key(tmp_path, keytype, keytype.replace("-", ""))
        nonce = f"{keytype}-nonce"
        armored = _sign_with_ssh_keygen(priv, nonce, str(tmp_path / f"msg-{keytype}.txt"))
        assert verify_signature_for_keys(
            nonce, armored, [pub_line], principal="alice"
        ) is True


@needs_ssh_keygen
def test_ssh_keygen_ed25519_end_to_end_authenticate(tmp_path):
    # Full manager flow: register the key, issue a nonce, sign, authenticate.
    priv, _, pub_line = _gen_ssh_key(tmp_path, "ed25519", "ed")
    m = make_manager()
    m.add_authorized_key("gu-reni", pub_line)
    nonce = m.issue_nonce("gu-reni")
    armored = _sign_with_ssh_keygen(priv, nonce, str(tmp_path / "msg.txt"))

    ident = m.authenticate(
        Req(
            headers={
                "X-Mesh-Principal": "gu-reni",
                "X-Mesh-Nonce": nonce,
                "X-Mesh-Signature": base64.b64encode(
                    armored.encode("utf-8")
                ).decode("ascii"),
            },
            client_ip="192.168.1.5",
        )
    )
    assert isinstance(ident, Identity)
    assert ident.method == "ssh"


def test_ssh_keygen_missing_fails_safe(tmp_path, monkeypatch):
    # No ssh-keygen on PATH: an armoured signature must be denied, not raise.
    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir -> which() finds nothing
    armored = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
    assert verify_signature_for_keys(
        "nonce", armored, ["ssh-ed25519 AAAA"], principal="alice"
    ) is False


def test_ssh_keygen_unsafe_principal_fails_safe(tmp_path):
    # Whitespace in the principal cannot be written to allowed_signers safely.
    armored = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
    assert verify_signature_for_keys(
        "nonce", armored, ["ssh-ed25519 AAAA"], principal="a b"
    ) is False
