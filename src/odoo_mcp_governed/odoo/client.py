"""A small JSON-RPC client for Odoo's external API.

Written against the documented external API (the ``common`` and ``object``
services), deliberately minimal: authenticate, ``execute_kw``, version.
Everything an MCP tool does is one of those.

Why JSON-RPC rather than XML-RPC: Odoo's XML-RPC endpoint cannot return
``None``. Plenty of perfectly good model methods return nothing —
``action_archive`` among them — and over XML-RPC they *run*, change the
database, and then fail while encoding the response. The caller is told the
call failed when it succeeded; an agent that retries archives twice, and the
audit log records an error for a change that was applied. JSON has ``null``,
so the problem does not exist. JSON-RPC errors also arrive structured
(exception class and message as separate fields), which removes any need to
pick a traceback apart.

What it adds over a bare HTTP POST:

* **A real timeout** on every request — a hung Odoo worker must not hang the
  thread serving an agent.
* **TLS verification on by default**, with an explicit opt-out per profile for
  self-signed development instances.
* **Errors without tracebacks.** Odoo includes its server traceback in the
  ``debug`` field of an error. That belongs in Odoo's log, not in a reply to
  an agent that will happily repeat it to a user. Only the exception class
  and message are kept.
"""

from __future__ import annotations

import http.client
import itertools
import json
import socket
import ssl
import threading
import urllib.error
import urllib.request
from typing import Any

MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class OdooError(Exception):
    """Odoo rejected the call (validation, access rights, missing record...)."""

    def __init__(self, message: str, kind: str = "OdooError") -> None:
        super().__init__(message)
        self.kind = kind


class OdooConnectionError(OdooError):
    """Odoo could not be reached, or authentication failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, kind="OdooConnectionError")


def _error_from(payload: dict[str, Any]) -> OdooError:
    data = payload.get("data") or {}
    kind = str(data.get("name") or "OdooError").rsplit(".", 1)[-1]
    message = str(data.get("message") or payload.get("message") or "Odoo returned an error")
    message = " ".join(line.strip() for line in message.splitlines() if line.strip())
    return OdooError(message[:500], kind=kind)


class OdooClient:
    """One authenticated connection to one Odoo database. Thread-safe."""

    _ids = itertools.count(1)

    def __init__(
        self,
        url: str,
        database: str,
        username: str,
        secret: str,
        *,
        ssl_verify: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.database = database
        self.username = username
        self._secret = secret
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self._uid: int | None = None
        self._uid_lock = threading.Lock()
        self._version: dict[str, Any] | None = None
        self._ssl_context: ssl.SSLContext | None = None
        if self.url.startswith("https://"):
            self._ssl_context = ssl.create_default_context()
            if not ssl_verify:
                self._ssl_context.check_hostname = False
                self._ssl_context.verify_mode = ssl.CERT_NONE

    def _call(self, service: str, method: str, *args: Any) -> Any:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "call",
                "id": next(self._ids),
                "params": {"service": service, "method": method, "args": list(args)},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.url}/jsonrpc",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self._ssl_context
            ) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except TimeoutError:
            raise OdooConnectionError(f"Odoo did not answer within {self.timeout:g}s") from None
        except urllib.error.HTTPError as exc:
            raise OdooConnectionError(f"Odoo answered HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise OdooConnectionError(
                    f"Odoo did not answer within {self.timeout:g}s"
                ) from None
            # Deliberately vague: the precise socket error often names internal
            # hosts and ports, which do not belong in a reply to an agent.
            raise OdooConnectionError(
                f"Could not reach Odoo ({type(exc.reason).__name__})"
            ) from None
        except (OSError, http.client.HTTPException) as exc:
            raise OdooConnectionError(f"Could not reach Odoo ({type(exc).__name__})") from None

        if len(raw) > MAX_RESPONSE_BYTES:
            raise OdooError("Odoo response exceeds the 64 MB limit", kind="ResponseTooLarge")
        try:
            payload = json.loads(raw)
        except ValueError:
            raise OdooConnectionError("Odoo returned something that is not JSON-RPC") from None
        if payload.get("error"):
            raise _error_from(payload["error"])
        return payload.get("result")

    # -- public API --------------------------------------------------------

    def ping(self) -> bool:
        """Live reachability check, uncached. Used by the health endpoint."""
        try:
            self._call("common", "version")
            return True
        except OdooError:
            return False

    def version(self) -> dict[str, Any]:
        if self._version is None:
            self._version = self._call("common", "version")
        return self._version

    @property
    def uid(self) -> int:
        if self._uid is None:
            with self._uid_lock:
                if self._uid is None:
                    uid = self._call(
                        "common", "authenticate", self.database, self.username, self._secret, {}
                    )
                    if not uid:
                        raise OdooConnectionError(
                            "Authentication failed for this profile (check user and API key)"
                        )
                    self._uid = int(uid)
        return self._uid

    def execute(
        self,
        model: str,
        method: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> Any:
        return self._call(
            "object",
            "execute_kw",
            self.database,
            self.uid,
            self._secret,
            model,
            method,
            args or [],
            kwargs or {},
        )

    def describe(self) -> dict[str, Any]:
        """Connection facts safe to show anyone: no secret, no uid."""
        return {
            "url": self.url,
            "database": self.database,
            "username": self.username,
            "ssl_verify": self.ssl_verify,
            "timeout": self.timeout,
        }
