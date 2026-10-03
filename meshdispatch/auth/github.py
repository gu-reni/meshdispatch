"""GitHub OAuth (authorization-code flow) for identity.

The client secret is *never* hard-coded: it comes from ``AuthConfig`` or the
environment.  A random ``state`` parameter is issued per authorization attempt
and validated (constant-time) on the callback to defeat CSRF.

Network calls are isolated behind injectable hooks so the rest of the flow is
testable offline; the default hooks use ``urllib`` against api.github.com.
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.parse
import urllib.request
from typing import Callable

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

# TokenExchangeFn(code) -> dict with "access_token" (or raises).
TokenExchangeFn = Callable[[str], dict]
# UserFetchFn(access_token) -> dict with "login" (or raises).
UserFetchFn = Callable[[str], dict]


def generate_state() -> str:
    return secrets.token_urlsafe(24)


def _default_exchange(
    client_id: str, client_secret: str, redirect_uri: str, code: str
) -> dict:
    payload = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("ascii")
    req = urllib.request.Request(
        GITHUB_TOKEN_URL,
        data=payload,
        headers={"Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if "access_token" not in data:
        raise ValueError("github token exchange failed")
    return data


def _default_user(access_token: str) -> dict:
    req = urllib.request.Request(
        GITHUB_USER_URL,
        headers={
            "Authorization": f"token {access_token}",
            "Accept": "application/json",
            "User-Agent": "meshdispatch",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


class GithubOAuth:
    """Encapsulates the GitHub authorization-code flow."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        exchange: TokenExchangeFn | None = None,
        user: UserFetchFn | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._exchange_fn = exchange or (
            lambda code: _default_exchange(
                client_id, client_secret, redirect_uri, code
            )
        )
        self._user_fn = user or _default_user

    def authorize_url(self, state: str, scope: str = "read:user") -> str:
        params = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": scope,
                "state": state,
            }
        )
        return f"{GITHUB_AUTHORIZE_URL}?{params}"

    def principal_for_code(self, code: str) -> str:
        """Exchange ``code`` for a token, then resolve the GitHub login."""
        token = self._exchange_fn(code)
        access_token = token["access_token"]
        profile = self._user_fn(access_token)
        login = profile.get("login")
        if not login:
            raise ValueError("github user profile missing login")
        return str(login)


def validate_state(presented: str, expected: str) -> bool:
    """Constant-time comparison of the CSRF ``state`` parameter."""
    if not isinstance(presented, str) or not isinstance(expected, str):
        return False
    import hmac

    return hmac.compare_digest(presented.encode(), expected.encode())


__all__ = [
    "GithubOAuth",
    "generate_state",
    "validate_state",
    "GITHUB_AUTHORIZE_URL",
    "GITHUB_TOKEN_URL",
    "GITHUB_USER_URL",
]
