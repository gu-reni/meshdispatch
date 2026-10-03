"""SSH public-key signature authentication.

The server issues a one-time, short-lived nonce; the client signs it with its
SSH private key and echoes the signature.  Only *registered* public keys
(``authorized_keys`` style) are accepted.  Nonces are single-use and expire.

Verification has two paths:

* **Primary -- ``ssh-keygen -Y verify``.**  The client signs the nonce with
  ``ssh-keygen -Y sign`` (namespace ``meshdispatch``) and sends back the
  armoured ``-----BEGIN SSH SIGNATURE-----`` block.  We hand the block to the
  system ``ssh-keygen`` along with an ``allowed_signers`` file built from the
  registered keys.  This supports ``ssh-rsa``, ``ssh-ed25519`` and
  ``ecdsa-sha2-*`` alike -- ``ssh-keygen`` decides the key type, we never parse
  it ourselves.

* **Fallback -- pure-Python RSA.**  If the signature is the legacy raw
  ``rsa-sha2-256`` blob (produced by :func:`meshdispatch.auth.crypto.build_ssh_signature`)
  rather than an armoured ``-Y`` block, it is verified with the stdlib-only
  RSA path in :mod:`.crypto`.  This also keeps RSA-only deployments working on
  hosts without ``ssh-keygen``.

Everything fails closed: missing ``ssh-keygen``, malformed input and any
subprocess error all collapse to ``False`` -- never an exception.

This module holds the pure logic; :class:`AuthManager` supplies the nonce
store and the registered-key lookup.
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import tempfile
import time

from .crypto import verify_ssh_signature

#: The namespace bound into every ``ssh-keygen -Y sign`` signature.  The
#: client must sign with the exact same value or verification fails (the
#: namespace is embedded in the signature and re-checked by ``-Y verify -n``).
SSH_SIGN_NAMESPACE = "meshdispatch"

_ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"


def generate_nonce() -> str:
    """Return a fresh high-entropy challenge nonce."""
    return secrets.token_urlsafe(24)


def nonce_is_fresh(nonce: str, record: dict, now: float | None = None) -> bool:
    """True iff the nonce record exists, is unexpired, and is unused."""
    if not record or record.get("used"):
        return False
    expires_at = record.get("expires_at", 0.0)
    return (now if now is not None else time.time()) < expires_at


def _find_ssh_keygen() -> str | None:
    """Return the path to ``ssh-keygen`` or ``None`` if it is absent."""
    return shutil.which("ssh-keygen")


def _principal_is_safe(principal: str) -> bool:
    """True iff ``principal`` is a single, whitespace-free token.

    The principal is written into an ``allowed_signers`` file and passed as a
    ``-I`` argument; anything containing whitespace could not be matched
    unambiguously (and would be a malformed signers entry), so we refuse it.
    """
    return (
        isinstance(principal, str)
        and bool(principal)
        and not any(c.isspace() for c in principal)
    )


def _as_armored_signature(signature: str) -> str | None:
    """Return the armoured ``-Y sign`` block if ``signature`` is one.

    Accepts the armoured text either verbatim or base64-encoded (the header
    transport convention used elsewhere in this module).  Returns ``None`` when
    ``signature`` is neither, so the caller can try the legacy RSA blob path.
    """
    if not isinstance(signature, str) or not signature.strip():
        return None
    text = signature.strip()
    if _ARMOR_BEGIN in text:
        return text
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    if _ARMOR_BEGIN in decoded:
        return decoded.strip()
    return None


def _build_allowed_signers(principal: str, authorized_keys: list[str]) -> str:
    """Build an ``allowed_signers`` file body from ``authorized_keys`` lines.

    Each registered key is bound to ``principal``.  ``ssh-keygen`` re-parses
    the key type itself, so ``ssh-rsa`` / ``ssh-ed25519`` / ``ecdsa-sha2-*``
    all pass through untouched.
    """
    lines: list[str] = []
    for line in authorized_keys or []:
        if not isinstance(line, str):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        lines.append(principal + " " + " ".join(fields))
    return "\n".join(lines) + "\n"


def _verify_with_ssh_keygen(
    nonce: str,
    armored_signature: str,
    authorized_keys: list[str],
    principal: str,
) -> bool:
    """Verify an armoured ``ssh-keygen -Y sign`` signature.  Never raises."""
    ssh_keygen = _find_ssh_keygen()
    if ssh_keygen is None:
        return False
    if not _principal_is_safe(principal):
        return False
    allowed = _build_allowed_signers(principal, authorized_keys)
    if not allowed.strip():
        return False

    try:
        with tempfile.TemporaryDirectory(prefix="meshdispatch-sshsig-") as tmp:
            signers_path = os.path.join(tmp, "allowed_signers")
            sig_path = os.path.join(tmp, "signature.sig")
            with open(signers_path, "w", encoding="utf-8") as fh:
                fh.write(allowed)
            with open(sig_path, "w", encoding="utf-8") as fh:
                fh.write(armored_signature)
                if not armored_signature.endswith("\n"):
                    fh.write("\n")

            # Argument list only -- the signature and nonce are never spliced
            # into a shell string, so a hostile nonce/key can't inject commands.
            cmd = [
                ssh_keygen,
                "-Y",
                "verify",
                "-f",
                signers_path,
                "-I",
                principal,
                "-n",
                SSH_SIGN_NAMESPACE,
                "-s",
                sig_path,
            ]
            proc = subprocess.run(
                cmd,
                input=nonce.encode("utf-8"),
                capture_output=True,
                timeout=10,
            )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return proc.returncode == 0


def verify_signature_for_keys(
    nonce: str,
    signature_b64: str,
    authorized_keys: list[str],
    principal: str | None = None,
) -> bool:
    """Verify an SSH signature over ``nonce`` against any registered key.

    Two encodings are accepted:

    * the armoured ``ssh-keygen -Y sign`` block (verbatim or base64-encoded),
      verified via ``ssh-keygen -Y verify`` -- this covers ed25519, ecdsa and
      rsa; and
    * the legacy raw ``rsa-sha2-256`` blob (base64), verified with the
      stdlib-only RSA path.

    ``principal`` is required for the armoured path (it selects the signer
    identity in the ``allowed_signers`` file); the manager supplies it.

    Returns ``False`` (never raises) for malformed input or any verification
    failure.  Candidate keys are tried in registration order.
    """
    if not isinstance(signature_b64, str) or not signature_b64:
        return False

    # Primary: armoured ssh-keygen -Y signature (any key type).
    armored = _as_armored_signature(signature_b64)
    if armored is not None:
        if principal is None:
            return False
        return _verify_with_ssh_keygen(nonce, armored, authorized_keys, principal)

    # Fallback: legacy raw RSA blob.
    try:
        sig_blob = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    data = nonce.encode("utf-8")
    for line in authorized_keys or []:
        if verify_ssh_signature(line, data, sig_blob):
            return True
    return False


__all__ = [
    "SSH_SIGN_NAMESPACE",
    "generate_nonce",
    "nonce_is_fresh",
    "verify_signature_for_keys",
]
