"""The vocabulary of the governance layer.

Everything downstream — policy, detection, audit, the admin dashboard — speaks
in terms of these types. Two of them matter most:

``ToolCall``  what an agent is *asking* to do, before anything happens.
``AuditEvent`` what was decided and what actually happened, after the fact.

Deliberate omission: neither type carries raw argument values. Odoo records
hold personal and commercial data, and an audit log is exactly the wrong place
to accumulate a second copy of it. We keep field *names* (useful, not
sensitive) and a digest of the arguments (lets you prove two calls were
identical without being able to read either).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Operation(str, Enum):
    """What a tool does to Odoo, independent of which tool it is.

    Policy is written against operations rather than tool names so that adding
    a tool cannot silently widen permissions.
    """

    READ = "read"
    CREATE = "create"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"  # arbitrary model method — the widest surface
    META = "meta"        # schema introspection, no record data
    ADMIN = "admin"      # server/cache status, touches no Odoo data

    @property
    def mutates(self) -> bool:
        return self in (Operation.CREATE, Operation.WRITE, Operation.DELETE)


class Decision(str, Enum):
    ALLOW = "allow"
    ALLOW_FLAGGED = "allow_flagged"  # permitted, but something looks off
    THROTTLE = "throttle"            # permitted, slowed down
    DENY = "deny"

    @property
    def permits(self) -> bool:
        return self is not Decision.DENY


class Outcome(str, Enum):
    OK = "ok"
    ERROR = "error"        # Odoo or transport failed
    DENIED = "denied"      # governance refused before reaching Odoo


def digest_args(arguments: Any) -> str:
    """A stable fingerprint of call arguments that reveals nothing about them.

    Canonical JSON so that key order and whitespace cannot produce different
    digests for identical calls. Values that JSON cannot represent fall back to
    ``repr``, which keeps the digest stable for a given input without needing
    the value to round-trip.
    """
    try:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=repr)
    except (TypeError, ValueError):
        canonical = repr(arguments)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class Signal:
    """One behavioural observation, emitted by one detector.

    ``weight`` is the contribution to the actor's risk score. Detectors are
    deliberately not allowed to deny a call on their own — they describe, the
    engine decides. That separation is what keeps a single noisy heuristic from
    taking down a production integration.
    """

    name: str
    weight: int
    detail: str


@dataclass(frozen=True)
class ToolCall:
    """A request to do something, before policy has ruled on it."""

    actor: str
    """Who is asking. The JWT subject over HTTP, or a fixed local identity for
    stdio. Governance is per-actor, so this must not be shared between agents
    if you want the detectors to mean anything."""

    profile: str
    """Which Odoo instance this is aimed at."""

    tool: str
    operation: Operation
    model: str | None = None
    method: str | None = None
    fields_touched: tuple[str, ...] = ()
    record_count: int | None = None
    """How many records the call asks to read or affect, when knowable up
    front: ``len(ids)`` for a write, ``limit`` for a search. ``None`` means
    unbounded, which is itself worth knowing."""

    arg_digest: str = ""
    ts: datetime = field(default_factory=utcnow)

    def describe(self) -> str:
        target = self.model or "-"
        if self.method:
            target = f"{target}.{self.method}"
        return f"{self.tool}({target})"


@dataclass
class AuditEvent:
    """An immutable record of one governed call.

    ``prev_hash``/``hash`` chain these together. See :mod:`.audit` for why.
    """

    seq: int
    ts: datetime
    actor: str
    profile: str
    tool: str
    operation: Operation
    model: str | None
    method: str | None
    fields_touched: tuple[str, ...]
    arg_digest: str
    decision: Decision
    reasons: tuple[str, ...]
    signals: tuple[Signal, ...]
    risk_score: int
    outcome: Outcome
    affected_count: int | None
    latency_ms: int
    error_type: str | None
    prev_hash: str
    hash: str = ""
    record_ids: tuple[int, ...] = ()
    """Ids the call created, changed or deleted, when known. Ids, never values."""

    def payload(self) -> dict[str, Any]:
        """The canonical, hashed content of this event.

        ``hash`` itself is excluded — it is the output of hashing this. Anything
        added here changes every subsequent hash, so new fields must go at the
        end of the record format and old logs keep verifying under the version
        of the code that wrote them.
        """
        return {
            "seq": self.seq,
            "ts": self.ts.isoformat(),
            "actor": self.actor,
            "profile": self.profile,
            "tool": self.tool,
            "operation": self.operation.value,
            "model": self.model,
            "method": self.method,
            "fields_touched": list(self.fields_touched),
            "arg_digest": self.arg_digest,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "signals": [
                {"name": s.name, "weight": s.weight, "detail": s.detail} for s in self.signals
            ],
            "risk_score": self.risk_score,
            "outcome": self.outcome.value,
            "affected_count": self.affected_count,
            "latency_ms": self.latency_ms,
            "error_type": self.error_type,
            "prev_hash": self.prev_hash,
        } | (
            # Only present when there are ids, so every event written before
            # this field existed hashes exactly as it did then.
            {"record_ids": list(self.record_ids)} if self.record_ids else {}
        )

    def compute_hash(self, key: bytes | None = None) -> str:
        """Seal this event.

        With ``key``, the chain is an HMAC chain: someone who obtains the
        database file alone — a stolen backup, a compromised ops account — can
        still alter a row, but cannot recompute the hashes to hide it. Without
        a key it is a plain SHA-256 chain, which detects edits and deletions
        but not a wholesale rewrite of the tail by someone who can run the
        hashing themselves. See :class:`~.audit.AuditLog` for the full threat
        model and why you also want off-box anchoring.
        """
        canonical = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if key:
            return hmac.new(key, canonical, hashlib.sha256).hexdigest()
        return hashlib.sha256(canonical).hexdigest()
