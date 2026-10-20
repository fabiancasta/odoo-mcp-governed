"""A second factor for the admin panel: time-based one-time codes (RFC 6238).

With ``ADMIN_TOTP_SECRET`` set, logging in needs the password *and* the
six-digit code from an authenticator app. A leaked or guessed password alone
then opens nothing. Standard library only: HMAC-SHA1, 30-second steps, one
step of clock drift either way, and a code that worked once never works
again.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import threading
import time
import urllib.parse

STEP = 30
DIGITS = 6


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    clean = secret.replace(" ", "").upper()
    return base64.b32decode(clean + "=" * (-len(clean) % 8))


def valid_secret(secret: str) -> bool:
    try:
        return len(_key(secret)) >= 10
    except (ValueError, base64.binascii.Error):
        return False


def code_at(secret: str, counter: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def provisioning_uri(secret: str, account: str = "admin",
                     issuer: str = "odoo-mcp-governed") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "digits": DIGITS,
                                    "period": STEP})
    return f"otpauth://totp/{label}?{query}"


class TotpVerifier:
    def __init__(self, secret: str, *, now_fn=time.time) -> None:
        self.secret = secret
        self._now = now_fn
        self._last_counter = -1
        self._lock = threading.Lock()

    def verify(self, code: str) -> bool:
        code = (code or "").strip().replace(" ", "")
        if len(code) != DIGITS or not code.isdigit():
            return False
        current = int(self._now() // STEP)
        with self._lock:
            for counter in (current - 1, current, current + 1):
                if counter <= self._last_counter:
                    continue  # already used: a replayed code is refused
                if hmac.compare_digest(code_at(self.secret, counter), code):
                    self._last_counter = counter
                    return True
        return False
