"""Idempotent creates: a retried call returns the first result.

An agent that loses an answer — a dropped connection, a timeout — retries,
and a create done twice is a duplicate invoice. With an ``idempotency_key``
the second call gets the first call's result back, marked ``replayed``.
A key reused for a different change is refused.

Only the result is kept (ids, names the agent already saw), for a day.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

TTL = timedelta(hours=24)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS idempotency (
    actor TEXT NOT NULL, profile TEXT NOT NULL, tool TEXT NOT NULL, key TEXT NOT NULL,
    intent TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (actor, profile, tool, key)
);
"""


class IdempotencyStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            target = Path(self.path)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not target.exists():
                os.close(os.open(target, os.O_CREAT | os.O_WRONLY, 0o600))
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def get(self, actor: str, profile: str, tool: str, key: str) -> tuple[str, dict] | None:
        cutoff = (datetime.now(timezone.utc) - TTL).isoformat()
        with self._lock:
            self._conn.execute("DELETE FROM idempotency WHERE created_at < ?", (cutoff,))
            row = self._conn.execute(
                "SELECT intent, result FROM idempotency WHERE actor = ? AND profile = ? "
                "AND tool = ? AND key = ?", (actor, profile, tool, key)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def put(self, actor: str, profile: str, tool: str, key: str, intent: str,
            result: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO idempotency VALUES (?,?,?,?,?,?,?)",
                (actor, profile, tool, key, intent, json.dumps(result, default=str),
                 datetime.now(timezone.utc).isoformat()))
            self._conn.commit()
