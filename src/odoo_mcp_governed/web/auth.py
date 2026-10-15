"""Authentication for the HTTP transport.

Two separate mechanisms for two separate audiences:

**Agents** present a JWT bearer token on ``/mcp``. Validation is strict about
exactly the things that are easy to forget: the algorithm is pinned to HS256
(so a token claiming ``alg: none`` or an asymmetric algorithm is rejected
before any signature logic runs), and ``exp``, ``iat``, ``iss`` and ``sub``
are all required. The ``sub`` claim becomes the actor identity that the
governance layer tracks, so each agent should get its own token.

**Administrators** log into the panel with ``ADMIN_PASSWORD`` and receive a
session cookie. The cookie value is 256 random bits that live only in this
process's memory — not a hash of the password, which anyone who knew or
guessed the password could forge offline, and which would never expire.
Restarting the server logs every administrator out, which is acceptable.
Each session also carries its own CSRF token, required on every form post.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from ..config import Settings
from ..storage import read_json, write_private_json

ALGORITHM = "HS256"


class AuthError(Exception):
    """Authentication failed. The message is safe to return to the client."""


def issue_token(settings: Settings, actor: str, *, hours: int | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=hours or settings.token_expiry_hours)
    claims = {
        "sub": actor,
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": uuid.uuid4().hex,
        "scope": "mcp",
    }
    token = jwt.encode(claims, settings.jwt_secret, algorithm=ALGORITHM)
    return {"token": token, "actor": actor, "issued_at": now.isoformat(),
            "expires_at": expires.isoformat(), "jti": claims["jti"]}


def verify_token(settings: Settings, token: str) -> dict[str, Any]:
    """Return the claims of a valid token, or raise :class:`AuthError`."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AuthError("malformed token") from None
    if header.get("alg") != ALGORITHM:
        raise AuthError("unsupported token algorithm")
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "iss", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("token expired") from None
    except jwt.InvalidIssuerError:
        raise AuthError("token issuer mismatch") from None
    except jwt.PyJWTError:
        raise AuthError("invalid token") from None
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise AuthError("token has no subject")
    return claims


class TokenStore:
    """The long-lived token shown in the panel for wiring up Claude.

    Kept on disk (0600) so it survives restarts and can be re-displayed to an
    administrator without minting a new one each time.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = settings.token_file

    def current(self) -> dict[str, Any] | None:
        data = read_json(self.path, default=None)
        if not data or not data.get("token"):
            return None
        try:
            verify_token(self.settings, data["token"])
        except AuthError:
            return None  # secret rotated or token expired: it is dead, say so
        return data

    def regenerate(self, actor: str = "claude") -> dict[str, Any]:
        data = issue_token(self.settings, actor)
        write_private_json(self.path, data)
        return data


@dataclass
class AdminSession:
    expires_at: float
    csrf: str
    ip: str


class AdminSessions:
    def __init__(self, ttl: timedelta) -> None:
        self.ttl = ttl.total_seconds()
        self._sessions: dict[str, AdminSession] = {}
        self._lock = threading.Lock()

    def create(self, ip: str) -> tuple[str, AdminSession]:
        sid = secrets.token_urlsafe(32)  # 256 bits
        session = AdminSession(
            expires_at=time.monotonic() + self.ttl, csrf=secrets.token_urlsafe(32), ip=ip
        )
        with self._lock:
            self._prune()
            self._sessions[sid] = session
        return sid, session

    def get(self, sid: str | None) -> AdminSession | None:
        if not sid:
            return None
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            if session.expires_at < time.monotonic():
                del self._sessions[sid]
                return None
            return session

    def revoke(self, sid: str | None) -> None:
        if sid:
            with self._lock:
                self._sessions.pop(sid, None)

    def _prune(self) -> None:
        now = time.monotonic()
        for sid in [s for s, v in self._sessions.items() if v.expires_at < now]:
            del self._sessions[sid]


def password_matches(expected: str, supplied: str) -> bool:
    """Constant-time comparison, so response timing reveals nothing."""
    return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def csrf_matches(session: AdminSession, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(session.csrf, supplied)
