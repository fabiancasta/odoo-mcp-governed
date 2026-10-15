"""Tests for the tamper-evidence claim.

These are the tests that matter most in the project, because the audit log is
the one component whose whole value is a claim about what an attacker cannot
do. Asserting that it records events would be nearly worthless; what has to be
proven is that altering, deleting and forging records are all *detected*, and
that the detection names the right event.

The tests reach into ``store._conn`` to tamper. That is the point: they are
simulating an attacker with direct database access, which is exactly the
adversary the hash chain exists to defeat. Going through the public API would
prove nothing, since the public API has no way to modify a past event.
"""

from __future__ import annotations

import json

import pytest

from odoo_mcp_governed.governance import AuditLog, AuditStore, Decision, Operation, Outcome
from odoo_mcp_governed.governance.store import GENESIS_HASH

from .conftest import FakeClock, make_call


def populate(audit: AuditLog, clock: FakeClock, count: int = 5) -> None:
    """Write ``count`` events, with a delete at every third position.

    The mix is deliberate: a log of identical events cannot detect a tampering
    test that rewrites one event to look like another, because the rewrite
    would be a no-op. Every third event being a delete gives the tamper tests
    something that actually changes when altered.
    """
    for i in range(count):
        clock.advance(seconds=10)
        is_delete = i % 3 == 2
        audit.record(
            make_call(
                clock,
                tool="delete_record" if is_delete else f"tool_{i}",
                operation=Operation.DELETE if is_delete else Operation.READ,
            ),
            decision=Decision.ALLOW,
            outcome=Outcome.OK,
            affected_count=i,
        )


def test_empty_log_is_intact(audit: AuditLog) -> None:
    status = audit.verify()
    assert status.intact
    assert status.events_checked == 0
    assert status.head_hash == GENESIS_HASH


def test_chain_verifies_after_normal_use(audit: AuditLog, clock: FakeClock) -> None:
    populate(audit, clock, 20)
    status = audit.verify()
    assert status.intact, status.summary()
    assert status.events_checked == 20
    assert status.broken_at is None


def test_events_are_sequential_and_linked(audit: AuditLog, clock: FakeClock) -> None:
    populate(audit, clock, 4)
    events = list(audit.store.iter_all())

    assert [e.seq for e in events] == [1, 2, 3, 4]
    assert events[0].prev_hash == GENESIS_HASH
    for earlier, later in zip(events, events[1:], strict=False):
        assert later.prev_hash == earlier.hash, "each event must commit to its predecessor"


def test_modifying_an_event_is_detected(
    audit: AuditLog, store: AuditStore, clock: FakeClock
) -> None:
    """The classic cover-up: quietly change what a past call did."""
    populate(audit, clock, 6)
    assert audit.verify().intact

    # An attacker rewrites event 3 to look like a read instead of a delete.
    store._conn.execute("UPDATE audit_events SET operation = ? WHERE seq = 3", ("read",))
    store._conn.commit()

    status = audit.verify()
    assert not status.intact
    assert status.broken_at == 3
    assert "do not match its hash" in status.reason


def test_deleting_an_event_is_detected(
    audit: AuditLog, store: AuditStore, clock: FakeClock
) -> None:
    """Removing the incriminating row leaves a hole the chain reports."""
    populate(audit, clock, 6)

    store._conn.execute("DELETE FROM audit_events WHERE seq = 4")
    store._conn.commit()

    status = audit.verify()
    assert not status.intact
    assert status.broken_at == 5
    assert "sequence gap" in status.reason
    # Verification still names how far the log was trustworthy.
    assert status.events_checked == 3


def test_altering_an_event_and_refixing_its_own_hash_still_breaks_the_chain(
    audit: AuditLog, store: AuditStore, clock: FakeClock
) -> None:
    """A half-competent attacker recomputes the hash of the row they edited.

    That is not enough: the *next* event committed to the old hash, so the
    break simply moves one event forward. Hiding the change means rewriting
    every event after it, which is precisely what the HMAC key prevents.
    """
    populate(audit, clock, 6)

    events = list(store.iter_all())
    target = events[2]
    target.affected_count = 9999
    repaired_hash = target.compute_hash()  # unkeyed log: attacker can do this
    store._conn.execute(
        "UPDATE audit_events SET affected_count = ?, hash = ? WHERE seq = ?",
        (9999, repaired_hash, target.seq),
    )
    store._conn.commit()

    status = audit.verify()
    assert not status.intact
    # Event 3 now hashes correctly, so the break surfaces at event 4, which
    # still points at the original hash of event 3.
    assert status.broken_at == 4
    assert "prev_hash" in status.reason


def test_hmac_chain_cannot_be_repaired_without_the_key(
    store: AuditStore, clock: FakeClock
) -> None:
    """With a key, recomputing hashes from the file alone no longer works."""
    keyed = AuditLog(store, hmac_key=b"a-secret-not-in-the-database")
    assert keyed.keyed
    populate(keyed, clock, 6)
    assert keyed.verify().intact

    events = list(store.iter_all())
    target = events[2]
    target.affected_count = 9999
    # The attacker has the file and the record format, but not the key, so the
    # best they can produce is a plain SHA-256 hash.
    store._conn.execute(
        "UPDATE audit_events SET affected_count = ?, hash = ? WHERE seq = ?",
        (9999, target.compute_hash(), target.seq),
    )
    store._conn.commit()

    status = keyed.verify()
    assert not status.intact
    assert status.broken_at == 3
    assert "do not match its hash" in status.reason


def test_keyed_and_unkeyed_hashes_differ(store: AuditStore, clock: FakeClock) -> None:
    """Sanity check that the key actually participates in the hash."""
    keyed = AuditLog(store, hmac_key=b"key")
    populate(keyed, clock, 1)
    event = next(store.iter_all())
    assert event.hash == event.compute_hash(b"key")
    assert event.hash != event.compute_hash()


def test_inserting_a_fabricated_event_is_detected(
    audit: AuditLog, store: AuditStore, clock: FakeClock
) -> None:
    """Appending an event that was never served, to manufacture an alibi."""
    populate(audit, clock, 3)
    last = list(store.iter_all())[-1]

    store._conn.execute(
        """
        INSERT INTO audit_events (
            seq, ts, actor, profile, tool, operation, model, method,
            fields_touched, arg_digest, decision, reasons, signals,
            risk_score, outcome, affected_count, latency_ms, error_type,
            prev_hash, hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            last.seq + 1,
            clock.now.isoformat(),
            "agent-a",
            "default",
            "search_records",
            "read",
            "res.partner",
            None,
            json.dumps([]),
            "forged",
            "allow",
            json.dumps([]),
            json.dumps([]),
            0,
            "ok",
            1,
            5,
            None,
            last.hash,  # correctly linked...
            "f" * 64,  # ...but the hash itself is made up
        ),
    )
    store._conn.commit()

    status = audit.verify()
    assert not status.intact
    assert status.broken_at == last.seq + 1


def test_denials_are_recorded_not_dropped(audit: AuditLog, clock: FakeClock) -> None:
    """Refusals must persist — the probing detector is built out of them."""
    audit.record(
        make_call(clock, model="res.users"),
        decision=Decision.DENY,
        reasons=("model_not_allowed: 'res.users' is not in ALLOWED_MODELS",),
        outcome=Outcome.DENIED,
    )
    events = audit.tail()
    assert len(events) == 1
    assert events[0].decision is Decision.DENY
    assert events[0].outcome is Outcome.DENIED
    assert audit.verify().intact


def test_anchor_tracks_the_head(audit: AuditLog, clock: FakeClock, tmp_path) -> None:
    populate(audit, clock, 3)
    anchor = audit.anchor()
    assert anchor.seq == 3
    assert anchor.event_count == 3
    assert anchor.head_hash == audit.verify().head_hash

    path = tmp_path / "anchors.log"
    audit.write_anchor(path)
    populate(audit, clock, 1)
    audit.write_anchor(path)

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert "seq=3" in lines[0]
    assert "seq=4" in lines[1]
    # Two anchors taken at different times must differ, or anchoring would be
    # useless for spotting a rewrite.
    assert lines[0] != lines[1]


def test_argument_values_are_never_stored(audit: AuditLog, clock: FakeClock) -> None:
    """A digest, not the data. The log must not become a second copy of the ERP."""
    from odoo_mcp_governed.governance import ToolCall, digest_args

    secret = {"vat": "ES12345678Z", "email": "someone@example.com"}
    call = ToolCall(
        actor="agent-a",
        profile="default",
        tool="create_record",
        operation=Operation.CREATE,
        model="res.partner",
        fields_touched=("vat", "email"),
        arg_digest=digest_args(secret),
        ts=clock.now,
    )
    audit.record(call, decision=Decision.ALLOW, outcome=Outcome.OK, affected_count=1)

    stored = json.dumps(audit.tail()[0].payload())
    assert "ES12345678Z" not in stored
    assert "someone@example.com" not in stored
    # Field names survive, because knowing *which* fields were touched is the
    # whole point of an audit trail.
    assert "vat" in stored and "email" in stored


def test_digest_is_stable_and_order_independent() -> None:
    from odoo_mcp_governed.governance import digest_args

    assert digest_args({"a": 1, "b": 2}) == digest_args({"b": 2, "a": 1})
    assert digest_args({"a": 1}) != digest_args({"a": 2})


def test_digest_handles_values_json_cannot_represent() -> None:
    """Odoo calls carry dates and Decimals; the digest must not raise."""
    from datetime import date
    from decimal import Decimal

    from odoo_mcp_governed.governance import digest_args

    value = {"when": date(2026, 10, 1), "amount": Decimal("12.34")}
    assert len(digest_args(value)) == 32
    assert digest_args(value) == digest_args(value)


@pytest.mark.parametrize("count", [1, 50, 200])
def test_chain_scales(audit: AuditLog, clock: FakeClock, count: int) -> None:
    populate(audit, clock, count)
    status = audit.verify()
    assert status.intact
    assert status.events_checked == count
