"""OAuth 2.1 for MCP clients that cannot take a pasted token (Claude.ai,
ChatGPT and other hosted connectors).

The flow is the one the MCP specification asks for — protected-resource
metadata, authorization-server metadata, dynamic client registration and the
authorization code grant with PKCE (S256 only) — with one rule of governed's
on top: **a person consents in the panel**, choosing which agent the client
becomes and to which Odoo profile it is pinned. The access token it gets is
an ordinary registered agent token: listed in the agent's tree, revocable,
archived with the agent, audited.

What is kept: registered clients (name and redirect URIs, 0600 on disk) and,
in memory only, authorization codes — hashed, single use, ten minutes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from ..storage import read_json, write_private_json

CODE_TTL = 600
MAX_CLIENTS = 200
MAX_REDIRECTS = 5
CLIENT_NAME = re.compile(r"^[\w .@()\-]{1,80}$")
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class OAuthError(Exception):
    """An OAuth error, by its RFC 6749 code. The description is safe to show."""

    def __init__(self, code: str, description: str) -> None:
        super().__init__(description)
        self.code = code
        self.description = description


def valid_redirect(uri: Any) -> bool:
    """HTTPS anywhere, plain HTTP only to this machine; no fragment, no
    credentials in the URL."""
    if not isinstance(uri, str) or len(uri) > 500:
        return False
    parts = urlsplit(uri)
    if parts.fragment or parts.username or parts.password or not parts.hostname:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK)


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def with_query(uri: str, params: dict[str, str]) -> str:
    return uri + ("&" if urlsplit(uri).query else "?") + urlencode(params)


@dataclass(frozen=True)
class Grant:
    client_id: str
    redirect_uri: str
    challenge: str
    agent: str
    profile: str | None
    expires: float


class OAuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._codes: dict[str, Grant] = {}

    # -- clients (dynamic registration) --------------------------------------

    def clients(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return dict(read_json(self.path, default=None) or {})

    def register(self, name: Any, redirect_uris: Any) -> dict[str, Any]:
        name = str(name or "MCP client").strip()[:80]
        if not CLIENT_NAME.match(name):
            raise OAuthError("invalid_client_metadata", "client_name has unsupported characters")
        if (not isinstance(redirect_uris, list) or not redirect_uris
                or len(redirect_uris) > MAX_REDIRECTS
                or not all(valid_redirect(u) for u in redirect_uris)):
            raise OAuthError("invalid_redirect_uri", "redirect_uris must be 1 to 5 HTTPS URLs "
                                                     "(HTTP only for localhost)")
        with self._lock:
            data = dict(read_json(self.path, default=None) or {})
            if len(data) >= MAX_CLIENTS:
                raise OAuthError("invalid_client_metadata", "too many registered clients")
            client_id = "gov-" + secrets.token_urlsafe(18)
            data[client_id] = {"client_name": name, "redirect_uris": list(redirect_uris),
                               "created_at": int(time.time())}
            write_private_json(self.path, data)
        return {"client_id": client_id, "client_name": name, "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none", "grant_types": ["authorization_code"],
                "response_types": ["code"]}

    def forget(self, client_id: str) -> bool:
        with self._lock:
            data = dict(read_json(self.path, default=None) or {})
            gone = data.pop(client_id, None) is not None
            if gone:
                write_private_json(self.path, data)
            return gone

    def check_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """The client of a valid authorization request. Raises OAuthError."""
        client = self.clients().get(str(params.get("client_id") or ""))
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id")
        if params.get("redirect_uri") not in client["redirect_uris"]:
            raise OAuthError("invalid_request", "redirect_uri is not registered for this client")
        if params.get("response_type") != "code":
            raise OAuthError("unsupported_response_type", "only response_type=code")
        if params.get("code_challenge_method") != "S256" or not re.fullmatch(
                r"[A-Za-z0-9_-]{43,128}", str(params.get("code_challenge") or "")):
            raise OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required")
        return client

    # -- codes ------------------------------------------------------------------

    def issue_code(self, grant: Grant) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            now = time.time()
            self._codes = {k: g for k, g in self._codes.items() if g.expires > now}
            self._codes[hashlib.sha256(code.encode()).hexdigest()] = grant
        return code

    def redeem(self, code: str, client_id: str, redirect_uri: str, verifier: str) -> Grant:
        """The grant behind a code, once. Raises OAuthError("invalid_grant")."""
        key = hashlib.sha256(str(code).encode()).hexdigest()
        with self._lock:
            grant = self._codes.pop(key, None)  # single use, even when the checks below fail
        if grant is None or grant.expires < time.time():
            raise OAuthError("invalid_grant", "unknown, used or expired code")
        if grant.client_id != client_id or grant.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "code was issued to another client or redirect_uri")
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", str(verifier or "")) or \
                not hmac.compare_digest(s256(verifier), grant.challenge):
            raise OAuthError("invalid_grant", "code_verifier does not match code_challenge")
        return grant


def metadata(base: str) -> dict[str, Any]:
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "authorization_response_iss_parameter_supported": True,
    }


def resource_metadata(base: str) -> dict[str, Any]:
    return {"resource": f"{base}/mcp", "authorization_servers": [base],
            "bearer_methods_supported": ["header"]}
