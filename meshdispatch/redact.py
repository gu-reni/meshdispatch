"""Privacy redaction for text that is about to be persisted.

The adapters feed every message body and every event payload through
:func:`redact` before it reaches the store, so that credential-shaped
strings never land in the database.  The function is a pure, deterministic
string transform: no file or network access, no timestamps, so it is
trivially unit-testable.
"""

from __future__ import annotations

import re

# The placeholder that replaces any redacted secret.  It deliberately carries
# no entropy and no prefix that could be mistaken for a real credential.
REDACTED = "[REDACTED]"

# ---------------------------------------------------------------------------
# Credential shapes (ordered so that the longest/prefix-specific forms win).
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS: list[re.Pattern[str]] = [
    # OpenAI / Anthropic-style API keys: sk-..., sk-proj-...
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    # GitHub personal / OAuth / installation tokens: gho_..., ghp_..., ghs_...
    re.compile(r"\bgh[oprs]_[A-Za-z0-9]{10,}"),
    # GitHub fine-grained PATs: github_pat_...
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{10,}"),
    # Slack tokens: xoxb-..., xoxp-..., xoxa-..., xoxr-..., xoxs-...
    re.compile(r"\bxox[bpars]-[A-Za-z0-9-]{10,}"),
    # AWS access key ids: AKIA + 16 base32-ish chars.
    re.compile(r"\bAKIA[0-9A-Z]{16}"),
    # Google API keys: AIza + 35 chars.
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}"),
    # JWT-ish tokens (three base64url segments).
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}"),
    # HTTP bearer tokens: "Bearer <opaque value>".
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*"),
]

# Common secret-bearing field names.  The value after ``=``/``:`` is what gets
# redacted; the field name and separator are preserved so the reader still
# knows *what kind* of secret was present.
_FIELD_NAMES = (
    r"api[_-]?key|apikey|api[_-]?token|secret|token|password|passwd|pwd"
    r"|auth[_-]?token|access[_-]?token|access[_-]?key|client[_-]?secret"
    r"|private[_-]?key"
)

# A value is a quoted string of any length, or an unquoted run of at least 6
# non-space characters.  This avoids redacting things like ``token=on`` while
# still catching real secrets and any quoted value.
_VALUE = r"""(?:"[^"]*"|'[^']*'|[^\s,;"')\]}]{6,})"""

_KEY_VALUE_PATTERN = re.compile(
    rf"\b({_FIELD_NAMES})\b(\s*[:=]\s*)({_VALUE})",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Return ``text`` with credential-shaped substrings replaced.

    Applies, in order: bearer/JWT/prefix-form credentials, then the
    ``KEY=value`` / ``KEY: value`` field forms.  The transform is idempotent
    (redacting already-redacted text changes nothing) and never raises on
    non-string input types of content embedded in the text.
    """
    if not isinstance(text, str):
        return text
    for pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _KEY_VALUE_PATTERN.sub(r"\1\2" + REDACTED, text)
    return text


__all__ = ["REDACTED", "redact"]
