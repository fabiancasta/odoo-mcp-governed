"""SQLite persistence for audit events.

Why SQLite and not a flat log file: the detectors need to ask questions like
"how many deletes has this actor done in the last 60 seconds", on every single
call. That is a query, not a scan. A JSONL file would mean re-reading and
re-parsing the tail of the log thousands of times a day.

Why SQLite and not Postgres: the audit log must survive the thing it is
auditing. A local file has no network partition, no credentials to rotate, and
no second service that can be down while calls are still being served. If the
log cannot be written, the call does not happen — see :mod:`.engine`.

Tamper-evidence does not depend on the storage being unwritable. It depends on
the hash chain in :mod:`.audit`: anyone with the file can edit a row, and the
chain will show exactly which one.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from .events import AuditEvent, Decision, Operation, Outcome, Signal

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    seq            INTEGER PRIMARY KEY,
    ts             TEXT    NOT NULL,
    actor          TEXT    NOT NULL,
    profile        TEXT    NOT NULL,
    tool           TEXT    NOT NULL,
    operation      TEXT    NOT NULL,
    model          TEXT,
    method         TEXT,
    fields_touched TEXT    NOT NULL,
    arg_digest     TEXT    NOT NULL,
    decision       TEXT    NOT NULL,
    reasons        TEXT    NOT NULL,
    signals        TEXT    NOT NULL,
    risk_score     INTEGER NOT NULL,
    outcome        TEXT    NOT NULL,
    affected_count INTEGER,
    latency_ms     INTEGER NOT NULL,
    error_type     TEXT,
    prev_hash      TEXT    NOT NULL,
    hash           TEXT    NOT NULL,
    record_ids     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_actor_ts ON audit_events (actor, ts);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_events (ts);
"""


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        seq=row["seq"],
        ts=datetime.fromisoformat(row["ts"]),
        actor=row["actor"],
        profile=row["profile"],
        tool=row["tool"],
        operation=Operation(row["operation"]),
        model=row["model"],
        method=row["method"],
        fields_touched=tuple(json.loads(row["fields_touched"])),
        arg_digest=row["arg_digest"],
        decision=Decision(row["decision"]),
        reasons=tuple(json.loads(row["reasons"])),
        signals=tuple(Signal(**s) for s in json.loads(row["signals"])),
        risk_score=row["risk_score"],
        outcome=Outcome(row["outcome"]),
        affected_count=row["affected_count"],
        latency_ms=row["latency_ms"],
        error_type=row["error_type"],
        prev_hash=row["prev_hash"],
        hash=row["hash"],
        record_ids=tuple(json.loads(row["record_ids"] or "[]")),
    )


class AuditStore:
    """Thread-safe append-only store.

    Pass ``":memory:"`` for tests. One re-entrant lock guards every access to
    the connection, reads included: Python's ``sqlite3`` connections are not
    safe to use from several threads at once, and the HTTP transport runs
    calls on a thread pool. Writes additionally rely on it so that sequence
    numbers and the hash chain are assigned without a race — two concurrent
    calls that both read "last seq is 41" would write two events claiming
    seq 42 with the same ``prev_hash``, silently forking the chain.
    Correctness here is worth more than throughput.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            target = Path(self.path)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Create the file 0600 before SQLite touches it. SQLite gives the
            # -wal and -shm files the same permissions as the database, so
            # this one call keeps all three private. The log holds no values,
            # but who did what to which model and when is not public either.
            if not target.exists():
                os.close(os.open(target, os.O_CREAT | os.O_WRONLY, 0o600))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            # Durability over speed: an audit log that loses its last few
            # entries on a crash is not an audit log.
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)
        columns = {r["name"] for r in self._conn.execute("PRAGMA table_info(audit_events)")}
        if "record_ids" not in columns:
            # A log created before record ids existed. The column is nullable
            # and old rows hash without it, so they keep verifying.
            self._conn.execute("ALTER TABLE audit_events ADD COLUMN record_ids TEXT")
        self._conn.commit()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- writes ------------------------------------------------------------

    def head(self) -> tuple[int, str]:
        """``(last_seq, last_hash)``, or ``(0, GENESIS_HASH)`` when empty."""
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return 0, GENESIS_HASH
        return row["seq"], row["hash"]

    def insert(self, event: AuditEvent) -> None:
        """Insert an already-sealed event.

        Chaining is the caller's job (:class:`~.audit.AuditLog`), which holds
        :attr:`lock` across reading the head and calling this, so the two
        happen as one critical section.
        """
        signals = [{"name": s.name, "weight": s.weight, "detail": s.detail} for s in event.signals]
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    seq, ts, actor, profile, tool, operation, model, method,
                    fields_touched, arg_digest, decision, reasons, signals,
                    risk_score, outcome, affected_count, latency_ms, error_type,
                    prev_hash, hash, record_ids
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.seq,
                    event.ts.isoformat(),
                    event.actor,
                    event.profile,
                    event.tool,
                    event.operation.value,
                    event.model,
                    event.method,
                    json.dumps(list(event.fields_touched)),
                    event.arg_digest,
                    event.decision.value,
                    json.dumps(list(event.reasons)),
                    json.dumps(signals),
                    event.risk_score,
                    event.outcome.value,
                    event.affected_count,
                    event.latency_ms,
                    event.error_type,
                    event.prev_hash,
                    event.hash,
                    json.dumps(list(event.record_ids)) if event.record_ids else None,
                ),
            )
            self._conn.commit()

    # -- reads -------------------------------------------------------------

    def _query(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def since(self, moment: datetime, actor: str | None = None) -> list[AuditEvent]:
        """Events at or after ``moment``, oldest first. The detectors' workhorse."""
        sql = "SELECT * FROM audit_events WHERE ts >= ?"
        params: list[object] = [moment.isoformat()]
        if actor is not None:
            sql += " AND actor = ?"
            params.append(actor)
        sql += " ORDER BY seq ASC"
        return [_row_to_event(r) for r in self._query(sql, params)]

    def tail(self, limit: int = 100, actor: str | None = None) -> list[AuditEvent]:
        """Most recent events, newest first. For the dashboard."""
        sql = "SELECT * FROM audit_events"
        params: list[object] = []
        if actor is not None:
            sql += " WHERE actor = ?"
            params.append(actor)
        sql += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        return [_row_to_event(r) for r in self._query(sql, params)]

    def search(
        self,
        *,
        actor: str | None = None,
        tool_prefix: str | None = None,
        decision: str | None = None,
        outcome: str | None = None,
        text: str | None = None,
        limit: int = 200,
    ) -> list[AuditEvent]:
        """Filtered tail for the admin audit view, newest first."""
        clauses: list[str] = []
        params: list[object] = []
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if tool_prefix:
            clauses.append("tool LIKE ? ESCAPE '\\'")
            params.append(_like_escape(tool_prefix) + "%")
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        if text:
            needle = "%" + _like_escape(text) + "%"
            clauses.append(
                "(actor LIKE ? ESCAPE '\\' OR tool LIKE ? ESCAPE '\\' OR "
                "model LIKE ? ESCAPE '\\' OR reasons LIKE ? ESCAPE '\\' OR "
                "signals LIKE ? ESCAPE '\\' OR error_type LIKE ? ESCAPE '\\')"
            )
            params.extend([needle] * 6)
        sql = "SELECT * FROM audit_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        return [_row_to_event(r) for r in self._query(sql, params)]

    def iter_all(self, chunk: int = 1000) -> Iterator[AuditEvent]:
        """Every event in chain order, fetched in chunks.

        Each chunk is read under the lock and released before yielding, so a
        slow consumer — verification of a large log — never holds the lock
        while it works, and an abandoned iteration never leaves it held.
        """
        last = 0
        while True:
            rows = self._query(
                "SELECT * FROM audit_events WHERE seq > ? ORDER BY seq ASC LIMIT ?",
                (last, chunk),
            )
            if not rows:
                return
            for row in rows:
                yield _row_to_event(row)
            last = rows[-1]["seq"]

    def count(self) -> int:
        return self._query("SELECT COUNT(*) AS n FROM audit_events")[0]["n"]

    def count_since(self, actor: str, moment: datetime) -> int:
        return self._query(
            "SELECT COUNT(*) AS n FROM audit_events WHERE actor = ? AND ts >= ?",
            (actor, moment.isoformat()),
        )[0]["n"]

    def count_for_actor(self, actor: str) -> int:
        """Lifetime event count for one actor — the privilege-drift baseline size."""
        return self._query(
            "SELECT COUNT(*) AS n FROM audit_events WHERE actor = ?", (actor,)
        )[0]["n"]

    def models_seen(self, actor: str) -> set[str]:
        """Every model this actor has ever been allowed to touch.

        Baseline for :class:`~.detectors.PrivilegeDriftDetector`. Denied calls
        are excluded on purpose: being refused access to a model must never be
        what teaches the baseline that the model is normal for you.
        """
        rows = self._query(
            """
            SELECT DISTINCT model FROM audit_events
            WHERE actor = ? AND model IS NOT NULL AND decision != ?
            """,
            (actor, Decision.DENY.value),
        )
        return {r["model"] for r in rows}

    def actors(self) -> list[str]:
        rows = self._query("SELECT DISTINCT actor FROM audit_events ORDER BY actor")
        return [r["actor"] for r in rows]
