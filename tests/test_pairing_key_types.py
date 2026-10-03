"""Regression tests for the key types the pairing bootstrap accepts.

These pin behaviour that was broken twice: the pairing endpoint originally
validated public keys with ``meshdispatch.auth.crypto.parse_ssh_public_key``,
which is an RSA-only parser.  ``ssh-keygen`` defaults to ed25519, so the
endpoint rejected the very keys most people have - and it rejected them with the
misleading message "public_key is not a valid RSA public key".

The keys below are real public keys, generated with ssh-keygen for this test.
A mock would not have caught the bug: the whole failure was in the parsing of a
genuine key blob.
"""
from __future__ import annotations

import pytest

from meshdispatch.control.pairing import (
    SUPPORTED_KEY_TYPES,
    compute_key_fingerprint,
    validate_public_key,
)

#: Real public keys, one per supported family.  Regenerate with:
#:   ssh-keygen -t ed25519 -N "" -C pairing-test -f /tmp/k
REAL_KEYS = {
    "ssh-ed25519": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOK7sCbmJqBb8opI93j8IxfiPyeeJey5iFxvjH2t/SQQ pairing-test",
    "ssh-rsa": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDK7sv7LYiEhkSaOFdxAYKwJmz3p41v239n9VDZULwGp8s1tB2MjOkur7JK3tQ2me5zSEYxh2ZbTfaQfVYsar7ewe8LuZsEdzk+cidtSJ7NWQsAmk1tBwEOJFjcbgCIFpTdVNCZPCHfuJkP1U+u8BV9QR4kTXhRnwtlh/2XtdTUyHl+fsoSDptyd/0YU0ABLIYVOOsMiUFJVnWg9GKtT9NmGF8NheeUOUH4JrEWnXZdmvuBzBSxasi4NNCwTS3fz5VWQzVN3jPByX5hDM7+YfL3pbpr5lVNvnAokdR2w63vAtXcgJUUk9xZoJXNKj+Qi333AQbmy/9TmS+kk7xJpdrP pairing-test",
    "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP61uF70XoPTD9hqq+9OPA5A7qvX99GSJquGVN+3deKsdtFJLeIzJ7de/DtBQ5Dba8BR2v1WnVxNnUKG8njJD1U= pairing-test",
}


def test_verifier_key_types_are_all_supported() -> None:
    """Every type here must be in SUPPORTED_KEY_TYPES, by construction."""
    for key_type in REAL_KEYS:
        assert key_type in SUPPORTED_KEY_TYPES, (
            "pairing must accept the same key types that auth/ssh.py verifies"
        )


@pytest.mark.parametrize("key_type", sorted(REAL_KEYS))
def test_every_key_type_is_accepted(key_type: str) -> None:
    """The bug: ed25519 and ecdsa were rejected while rsa was accepted."""
    assert validate_public_key(REAL_KEYS[key_type]) == REAL_KEYS[key_type]
    fingerprint = compute_key_fingerprint(REAL_KEYS[key_type])
    assert fingerprint.startswith("SHA256:")


def test_fingerprints_differ_between_keys() -> None:
    fingerprints = {compute_key_fingerprint(k) for k in REAL_KEYS.values()}
    assert len(fingerprints) == len(REAL_KEYS)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "这不是密钥",
        "ssh-ed25519",  # a type with no blob at all
        "ssh-ed25519 !!!not-base64!!!",  # blob is not base64
        "ssh-ed25519 c3NoLXJzYQAAAAMBAAEAAAEBA",  # blob whose type disagrees
        "ssh-magic AAAAC3NzaC1lZDI1NTE5AAAA test",  # unsupported type
    ],
)
def test_bad_keys_are_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_public_key(bad)


def test_structurally_valid_but_truncated_blob_is_not_our_call() -> None:
    """We check structure, not key material.

    A blob whose base64 decodes and whose embedded type agrees is accepted here;
    whether the key is actually usable is decided at verification time by
    ssh-keygen -Y verify, not by enrolment.  Documenting that boundary on purpose.
    """
    truncated = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA tr"
    assert validate_public_key(truncated) == truncated


def test_rejection_message_names_what_is_expected() -> None:
    """The message must not claim the key is RSA when it plainly is not."""
    with pytest.raises(ValueError) as excinfo:
        validate_public_key("这不是密钥")
    message = str(excinfo.value)
    assert "RSA" not in message
    assert "authorized_keys" in message
