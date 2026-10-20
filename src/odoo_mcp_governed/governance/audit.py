"""The hash-chained audit log.

Each event stores the hash of the one before it, so every event's hash depends
on the entire history. Change one byte of event 40 and events 40..N no longer
verify, and :meth:`AuditLog.verify` names event 40 as the break.

Threat model, stated plainly — this is where most "tamper-proof log" claims
quietly overreach:

*Detected.* Editing a past event. Deleting a past event. Reordering events.
Splicing in a fabricated event. All of these break the chain at a known point.

*Detected only with an HMAC key.* An attacker who can read and write the
database file and knows the record format can, with a plain SHA-256 chain,
recompute every hash from the altered point forward and produce a chain that
verifies. Setting ``AUDIT_HMAC_KEY`` closes this off for anyone who has the
file but not the key.

*Not detected by this module alone.* An attacker who owns the running process
has the key and can rewrite the whole chain, including the head. Nothing a
single host can do fixes that. The answer is anchoring: periodically copy the
head hash somewhere the server cannot reach back into — another host, an
append-only object store, a chat channel, a signed commit. Then a rewritten
chain disagrees with an anchor you still trust. :meth:`AuditLog.anchor` exists
for exactly this, and it is a two-line cron job, not a product.

*Also not detected.* Anything that bypasses this server and talks to Odoo
directly. Governance here covers the MCP surface, and claiming more than that
would be dishonest.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .events import AuditEvent, Decision, Operation, Outcome, Signal, ToolCall, utcnow
from .store import GENESIS_HASH, AuditStore


@dataclass(frozen=True)
class ChainStatus:
    """Result of verifying the log end to end."""

    intact: bool
    events_checked: int
    head_hash: str
    broken_at: int | None = None
    reason: str | None = None

    def summary(self) -> str:
        if self.intact:
            return f"intact: {self.events_checked} events, head {self.head_hash[:12]}"
        return f"BROKEN at seq {self.broken_at}: {self.reason}"


@dataclass(frozen=True)
class Anchor:
    """A point in the log you can publish off-box and compare against later."""

    seq: int
    head_hash: str
    taken_at: datetime
    event_count: int


class AuditLog:
    """Append-only, hash-chained record of every governed call.

    Writes are serialised on the store's lock so that reading the chain head
    and appending the next event are a single atomic step.
    """

    def __init__(self, store: AuditStore, hmac_key: bytes | None = None) -> None:
        self._store = store
        self._key = hmac_key

    @property
    def store(self) -> AuditStore:
        return self._store

    @property
    def keyed(self) -> bool:
        """Whether this log is HMAC-sealed rather than plain-hashed."""
        return bool(self._key)

    def record(
        self,
        call: ToolCall,
        *,
        decision: Decision,
        reasons: tuple[str, ...] = (),
        signals: tuple[Signal, ...] = (),
        risk_score: int = 0,
        outcome: Outcome,
        affected_count: int | None = None,
        latency_ms: int = 0,
        error_type: str | None = None,
        record_ids: tuple[int, ...] = (),
    ) -> AuditEvent:
        """Seal and append one event. Returns the event, with its hash filled in."""
        with self._store.lock:
            last_seq, last_hash = self._store.head()
            event = AuditEvent(
                seq=last_seq + 1,
                ts=call.ts,
                actor=call.actor,
                profile=call.profile,
                tool=call.tool,
                operation=call.operation,
                model=call.model,
                method=call.method,
                fields_touched=call.fields_touched,
                arg_digest=call.arg_digest,
                decision=decision,
                reasons=reasons,
                signals=signals,
                risk_score=risk_score,
                outcome=outcome,
                affected_count=affected_count,
                latency_ms=latency_ms,
                error_type=error_type,
                prev_hash=last_hash,
                record_ids=tuple(record_ids),
            )
            event.hash = event.compute_hash(self._key)
            self._store.insert(event)
            return event

    def verify(self) -> ChainStatus:
        """Walk the whole chain and report the first inconsistency.

        Checks three things per event: the sequence has no gaps, the recorded
        ``prev_hash`` matches the previous event's hash, and the event's own
        hash is what its contents produce.
        """
        expected_prev = GENESIS_HASH
        expected_seq = 1
        checked = 0
        head = GENESIS_HASH

        for event in self._store.iter_all():
            if event.seq != expected_seq:
                return ChainStatus(
                    intact=False,
                    events_checked=checked,
                    head_hash=head,
                    broken_at=event.seq,
                    reason=f"sequence gap: expected seq {expected_seq}, found {event.seq}",
                )
            if event.prev_hash != expected_prev:
                return ChainStatus(
                    intact=False,
                    events_checked=checked,
                    head_hash=head,
                    broken_at=event.seq,
                    reason="prev_hash does not match the preceding event — "
                    "an event was altered, removed or inserted",
                )
            recomputed = event.compute_hash(self._key)
            if recomputed != event.hash:
                return ChainStatus(
                    intact=False,
                    events_checked=checked,
                    head_hash=head,
                    broken_at=event.seq,
                    reason="event contents do not match its hash — this event was altered",
                )
            expected_prev = event.hash
            head = event.hash
            expected_seq = event.seq + 1
            checked += 1

        return ChainStatus(intact=True, events_checked=checked, head_hash=head)

    def anchor(self) -> Anchor:
        """Snapshot the current head so it can be published off-box.

        Publish this somewhere the server has no write access to. Comparing a
        later :meth:`verify` against a trusted anchor is the only thing that
        detects a rewrite by an attacker who owns the process.
        """
        seq, head_hash = self._store.head()
        return Anchor(
            seq=seq, head_hash=head_hash, taken_at=utcnow(), event_count=self._store.count()
        )

    def write_anchor(self, path: str | Path) -> Anchor:
        """Append the current anchor to a file, one line per anchor."""
        anchor = self.anchor()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(
                f"{anchor.taken_at.isoformat()}\tseq={anchor.seq}\t"
                f"count={anchor.event_count}\thead={anchor.head_hash}\n"
            )
        return anchor

    # -- convenience reads -------------------------------------------------

    def tail(self, limit: int = 100, actor: str | None = None) -> list[AuditEvent]:
        return self._store.tail(limit=limit, actor=actor)

    def since(self, moment: datetime, actor: str | None = None) -> list[AuditEvent]:
        return self._store.since(moment, actor=actor)

    def count_since(self, actor: str, moment: datetime) -> int:
        return self._store.count_since(actor, moment)

    def denied_count(self, moment: datetime, actor: str | None = None) -> int:
        return sum(1 for e in self.since(moment, actor) if e.decision is Decision.DENY)

    def operation_count(
        self, moment: datetime, operation: Operation, actor: str | None = None
    ) -> int:
        return sum(1 for e in self.since(moment, actor) if e.operation is operation)
