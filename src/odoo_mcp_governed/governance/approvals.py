"""Human approval for destructive or bulk operations.

The flow is deliberately stateless for the agent: its call is refused with a
request number, an operator approves the request, and the agent repeats the
*same* call — same actor, profile, tool and arguments, so the same digest —
within the approval window. That call goes through once. Nothing has to hold
the agent's arguments while it waits, and an approval cannot be stretched to
cover a different call.

Only metadata is stored: who, which tool, which model, how many records. No
argument values, for the same reason the audit log holds none.

Approval fatigue is the failure mode of every approval system: an operator
asked forty times an hour approves the forty-first without reading it. Two
things keep the count down. An operator can approve a request *and similar
ones* for a while — same agent, profile, tool and model, up to a number of
uses — instead of one call at a time; and every pending request of the same
kind is decided with one click. A burst of similar requests also notifies
once, not once per call.
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
CREATE TABLE IF NOT EXISTS approval_grants (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    actor      TEXT NOT NULL,
    profile    TEXT NOT NULL,
    tool       TEXT NOT NULL,
    model      TEXT,
    until      TEXT NOT NULL,
    max_uses   INTEGER NOT NULL,
    uses       INTEGER NOT NULL DEFAULT 0,
    granted_by TEXT NOT NULL,
    request_id INTEGER
);
"""

GRANT_MINUTES = (30, 120, 480)
"""The choices offered for "approve similar calls for…"."""
GRANT_MAX_USES = 50


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

    def _grant(self, call: ToolCall) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM approval_grants WHERE actor = ? AND profile = ? AND tool = ? "
            "AND model IS ? AND until > ? AND uses < max_uses ORDER BY id DESC LIMIT 1",
            (call.actor, call.profile, call.tool, call.model, self._now().isoformat()),
        ).fetchone()

    def consume(self, call: ToolCall) -> bool:
        """Use an approval for this call. True if one existed: an approval of
        this exact call (once), or a standing grant for calls like it."""
        with self._lock:
            grant = self._grant(call)
            if grant is not None:
                self._conn.execute("UPDATE approval_grants SET uses = uses + 1 WHERE id = ?",
                                   (grant["id"],))
                self._conn.commit()
                return True
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

    def pending_like(self, call: ToolCall) -> bool:
        """Whether a request of the same kind is already waiting — then a new
        one does not need to notify the operator again."""
        cutoff = (self._now() - self.ttl).isoformat()
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM approvals WHERE actor = ? AND profile = ? AND tool = ? "
                "AND model IS ? AND status = 'pending' AND created_at >= ? LIMIT 1",
                (call.actor, call.profile, call.tool, call.model, cutoff),
            ).fetchone() is not None

    def decide(self, request_id: int, *, approve: bool, by: str, grant_minutes: int = 0,
               group: bool = False) -> bool:
        """Approve or deny a pending request. False if it was not pending.

        ``group`` decides every pending request of the same kind (agent,
        profile, tool, model) at once. ``grant_minutes`` (approve only) also
        lets calls of that kind through for that long, up to
        :data:`GRANT_MAX_USES` of them.
        """
        now = self._now().isoformat()
        status = "approved" if approve else "denied"
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE id = ? AND status = 'pending'", (request_id,)
            ).fetchone()
            if row is None:
                return False
            if group:
                cutoff = (self._now() - self.ttl).isoformat()
                self._conn.execute(
                    "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? "
                    "WHERE actor = ? AND profile = ? AND tool = ? AND model IS ? "
                    "AND status = 'pending' AND created_at >= ?",
                    (status, by, now, row["actor"], row["profile"], row["tool"], row["model"],
                     cutoff),
                )
            else:
                self._conn.execute(
                    "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? "
                    "WHERE id = ?", (status, by, now, request_id))
            # Never a standing grant for modules or code: each of those is read.
            if approve and grant_minutes > 0 and row["model"] not in CODE_MODELS | MODULE_MODELS:
                until = (self._now() + timedelta(minutes=min(grant_minutes, 24 * 60))).isoformat()
                self._conn.execute(
                    "INSERT INTO approval_grants (created_at, actor, profile, tool, model, until, "
                    "max_uses, granted_by, request_id) VALUES (?,?,?,?,?,?,?,?,?)",
                    (now, row["actor"], row["profile"], row["tool"], row["model"], until,
                     GRANT_MAX_USES, by, request_id),
                )
            self._conn.commit()
            return True

    def grants(self) -> list[dict[str, Any]]:
        """Standing grants still in force."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM approval_grants WHERE until > ? AND uses < max_uses "
                "ORDER BY id DESC", (self._now().isoformat(),)).fetchall()
        return [dict(r) for r in rows]

    def revoke_grant(self, grant_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE approval_grants SET until = ? WHERE id = ? AND until > ?",
                (self._now().isoformat(), grant_id, self._now().isoformat()))
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
