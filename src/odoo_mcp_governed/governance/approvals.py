"""Human approval for destructive or bulk operations.

The flow is deliberately stateless for the agent: its call is refused with a
request number, an operator approves the request, and the agent repeats the
*same* call — same actor, profile, tool and arguments, so the same digest —
within the approval window. That call goes through once. Nothing has to hold
the agent's arguments while it waits, and an approval cannot be stretched to
cover a different call.

Only metadata is stored: who, which tool, which model, how many records. No
argument values, for the same reason the audit log holds none.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .events import Operation, ToolCall, utcnow

KINDS = ("delete", "bulk", "execute")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id           INTEGER PRIMARY KEY,
    created_at   TEXT NOT NULL,
    actor        TEXT NOT NULL,
    profile      TEXT NOT NULL,
    tool         TEXT NOT NULL,
    model        TEXT,
    operation    TEXT NOT NULL,
    record_count INTEGER,
    arg_digest   TEXT NOT NULL,
    status       TEXT NOT NULL,
    decided_by   TEXT,
    decided_at   TEXT,
    used_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_key ON approvals (actor, profile, tool, arg_digest);
"""


# On configurator profiles: the changes that run code or cannot be taken back.
CODE_MODELS = frozenset({"ir.actions.server", "base.automation", "ir.cron"})
MODULE_MODELS = frozenset({"ir.module.module", "base.module.upgrade", "base.module.uninstall"})


def needs_configurator_approval(call: ToolCall) -> bool:
    if call.model in MODULE_MODELS and call.operation in (
        Operation.EXECUTE, Operation.CREATE, Operation.WRITE, Operation.DELETE
    ):
        return True
    return call.model in CODE_MODELS and call.operation in (
        Operation.CREATE, Operation.WRITE, Operation.EXECUTE
    )


def needs_approval(call: ToolCall, kinds: frozenset[str], bulk_threshold: int) -> bool:
    if "delete" in kinds and call.operation is Operation.DELETE:
        return True
    if "execute" in kinds and call.operation is Operation.EXECUTE:
        return True
    return bool(
        "bulk" in kinds
        and call.operation in (Operation.CREATE, Operation.WRITE, Operation.DELETE)
        and call.record_count is not None
        and call.record_count > bulk_threshold
    )


class ApprovalStore:
    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        ttl: timedelta = timedelta(minutes=30),
        now_fn: Callable[[], datetime] = utcnow,
    ) -> None:
        self.path = str(path)
        self.ttl = ttl
        self._now = now_fn
        if self.path != ":memory:":
            target = Path(self.path)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not target.exists():
                os.close(os.open(target, os.O_CREAT | os.O_WRONLY, 0o600))
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @staticmethod
    def _key(call: ToolCall) -> tuple:
        return (call.actor, call.profile, call.tool, call.arg_digest)

    def _recent(self, call: ToolCall) -> sqlite3.Row | None:
        cutoff = (self._now() - self.ttl).isoformat()
        return self._conn.execute(
            "SELECT * FROM approvals WHERE actor = ? AND profile = ? AND tool = ? "
            "AND arg_digest = ? AND created_at >= ? AND status != 'used' "
            "ORDER BY id DESC LIMIT 1",
            (*self._key(call), cutoff),
        ).fetchone()

    def consume(self, call: ToolCall) -> bool:
        """Use an approval for exactly this call, once. True if one existed."""
        with self._lock:
            row = self._recent(call)
            if row is None or row["status"] != "approved":
                return False
            decided = datetime.fromisoformat(row["decided_at"])
            if self._now() - decided > self.ttl:
                return False
            self._conn.execute(
                "UPDATE approvals SET status = 'used', used_at = ? WHERE id = ?",
                (self._now().isoformat(), row["id"]),
            )
            self._conn.commit()
            return True

    def request(self, call: ToolCall) -> tuple[dict[str, Any], bool]:
        """The open request for this call, creating one if needed.

        Returns ``(request, created)``. Repeating a call while its request is
        pending — or after it was denied — does not create another one.
        """
        with self._lock:
            row = self._recent(call)
            if row is not None and row["status"] in ("pending", "denied"):
                return dict(row), False
            cursor = self._conn.execute(
                "INSERT INTO approvals (created_at, actor, profile, tool, model, operation, "
                "record_count, arg_digest, status) VALUES (?,?,?,?,?,?,?,?, 'pending')",
                (self._now().isoformat(), call.actor, call.profile, call.tool, call.model,
                 call.operation.value, call.record_count, call.arg_digest),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return dict(row), True

    def decide(self, request_id: int, *, approve: bool, by: str) -> bool:
        """Approve or deny a pending request. False if it was not pending."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? "
                "WHERE id = ? AND status = 'pending'",
                ("approved" if approve else "denied", by, self._now().isoformat(), request_id),
            )
            self._conn.commit()
            return cursor.rowcount == 1

    def get(self, request_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE id = ?", (request_id,)).fetchone()
        return dict(row) if row else None

    def pending(self) -> list[dict[str, Any]]:
        cutoff = (self._now() - self.ttl).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM approvals WHERE status = 'pending' AND created_at >= ? "
                "ORDER BY id DESC", (cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM approvals WHERE status != 'pending' ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]
