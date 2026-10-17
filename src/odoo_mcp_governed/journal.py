"""The change journal: what each governed change did, value by value.

The audit log is deliberately value-free — it is meant to be shared with
whoever investigates an incident, and it should not become a second copy of
the ERP. This journal is the opposite: it keeps the old and new values of every
create, write and delete, so a change can be understood and undone. It is a
separate file (0600) for exactly that reason, and it never holds credential
fields: those are stripped with the same patterns that keep them out of tool
results.

Each entry points at the audit event (``audit_seq``) that sealed the change,
so the tamper-evident record of *that* it happened and this record of *what*
happened can be joined without trusting either alone.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS changes (
    id         INTEGER PRIMARY KEY,
    audit_seq  INTEGER NOT NULL,
    ts         TEXT    NOT NULL,
    actor      TEXT    NOT NULL,
    profile    TEXT    NOT NULL,
    model      TEXT    NOT NULL,
    operation  TEXT    NOT NULL,
    record_id  INTEGER NOT NULL,
    before     TEXT,
    after      TEXT
);
CREATE INDEX IF NOT EXISTS idx_changes_seq ON changes (audit_seq);
CREATE INDEX IF NOT EXISTS idx_changes_record ON changes (model, record_id);
"""


class ChangeJournal:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            target = Path(self.path)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not target.exists():
                os.close(os.open(target, os.O_CREAT | os.O_WRONLY, 0o600))
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add(
        self,
        *,
        audit_seq: int,
        ts: datetime,
        actor: str,
        profile: str,
        model: str,
        operation: str,
        changes: dict[int, tuple[dict[str, Any] | None, dict[str, Any] | None]],
    ) -> None:
        """One row per record: ``changes`` maps record id to ``(before, after)``."""
        rows = [
            (audit_seq, ts.isoformat(), actor, profile, model, operation, record_id,
             _dump(before), _dump(after))
            for record_id, (before, after) in changes.items()
        ]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO changes (audit_seq, ts, actor, profile, model, operation, "
                "record_id, before, after) VALUES (?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self._conn.commit()

    def for_seq(self, audit_seq: int) -> list[dict[str, Any]]:
        return self._select("WHERE audit_seq = ? ORDER BY id", (audit_seq,))

    def tail(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._select("ORDER BY id DESC LIMIT ?", (max(1, min(limit, 5000)),))

    def search(
        self, *, model: str | None = None, record_id: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Newest first, optionally for one model or one record."""
        clauses, params = [], []
        if model:
            clauses.append("model = ?")
            params.append(model)
        if record_id is not None:
            clauses.append("record_id = ?")
            params.append(record_id)
        where = ("WHERE " + " AND ".join(clauses) + " ") if clauses else ""
        params.append(max(1, min(limit, 5000)))
        return self._select(where + "ORDER BY id DESC LIMIT ?", tuple(params))

    def _select(self, where: str, params: tuple) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(f"SELECT * FROM changes {where}", params).fetchall()
        return [
            {**dict(r), "before": _load(r["before"]), "after": _load(r["after"])} for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# Values longer than this — images, file contents passed as base64 — are noted
# by size rather than copied: the journal is for understanding a change, and
# one product photo should not cost more than ten thousand edits.
MAX_VALUE_CHARS = 10_000


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return f"<omitted: {len(value)} characters>"
    return value


def _dump(value: dict[str, Any] | None) -> str | None:
    if value is None:
        return None
    clipped = {k: _clip(v) for k, v in value.items()}
    return json.dumps(clipped, ensure_ascii=False, default=str)


def _load(value: str | None) -> Any:
    return None if value is None else json.loads(value)
