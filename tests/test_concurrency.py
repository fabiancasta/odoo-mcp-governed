"""Concurrency: the HTTP transport serves calls from a thread pool, so the
governance layer has to hold its guarantees under parallel load.

Two separate properties:

* The hash chain must not fork when many threads append at once.
* Parallelism must not be a way around detection. Ten deletes fired at once
  must be judged as ten deletes, not as ten first deletes each looking at an
  empty history.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from odoo_mcp_governed.governance import (
    AuditLog,
    AuditStore,
    Decision,
    DetectorConfig,
    GovernanceDenied,
    GovernanceEngine,
    Operation,
    PolicyConfig,
    PolicyEngine,
    RiskConfig,
)

from .conftest import FakeClock, make_call


def _engine(store: AuditStore, policy_config: PolicyConfig, clock: FakeClock) -> GovernanceEngine:
    return GovernanceEngine(
        audit=AuditLog(store),
        policy=PolicyEngine(policy_config),
        detector_config=DetectorConfig(business_timezone="UTC"),
        risk_config=RiskConfig(throttle_threshold=20, block_threshold=40, throttle_seconds=0),
        now_fn=clock,
    )


def test_parallel_deletes_cannot_evade_the_burst_detector(
    tmp_path, policy_config: PolicyConfig, clock: FakeClock
) -> None:
    """The attack: fire every delete at once so each review sees nothing.

    The body sleeps briefly to hold the race window open — without per-actor
    serialisation, all ten reviews would complete before the first record, and
    all ten deletes would be allowed.
    """
    engine = _engine(AuditStore(tmp_path / "audit.db"), policy_config, clock)
    decisions: list[Decision] = []
    lock = threading.Lock()

    def delete() -> None:
        call = make_call(
            clock, tool="delete_record", operation=Operation.DELETE, model="mail.activity"
        )
        try:
            with engine.guard(call) as guarded:
                time.sleep(0.02)
                guarded.affected(1)
            outcome = Decision.ALLOW
        except GovernanceDenied:
            outcome = Decision.DENY
        with lock:
            decisions.append(outcome)

    with ThreadPoolExecutor(max_workers=10) as pool:
        for _ in range(10):
            pool.submit(delete)

    assert len(decisions) == 10
    assert decisions.count(Decision.DENY) > 0, "parallel deletes slipped past detection"
    # And the ones that ran were the first few, as for a sequential burst.
    assert decisions.count(Decision.ALLOW) <= 3
    assert engine.audit.verify().intact


def test_different_actors_are_not_serialised_behind_each_other(
    tmp_path, policy_config: PolicyConfig, clock: FakeClock
) -> None:
    """Per-actor serialisation must stay per actor: one slow agent must not
    stall every other integration on the server."""
    engine = _engine(AuditStore(tmp_path / "audit.db"), policy_config, clock)

    # No stopwatch: a wall-clock bound failed on a slow CI runner with correct
    # code. Instead all five calls must be inside their guarded section at the
    # same moment. If actors were serialised behind one another, the barrier
    # could never fill and every wait would time out.
    barrier = threading.Barrier(5, timeout=10)

    def slow_read(actor: str) -> None:
        with engine.guard(make_call(clock, actor=actor)) as guarded:
            barrier.wait()
            guarded.affected(1)

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(slow_read, [f"agent-{i}" for i in range(5)]))
    assert not barrier.broken


def test_chain_does_not_fork_under_concurrent_appends(tmp_path, clock: FakeClock) -> None:
    store = AuditStore(tmp_path / "audit.db")
    audit = AuditLog(store)

    def append(i: int) -> None:
        from odoo_mcp_governed.governance import Outcome

        audit.record(make_call(clock, actor=f"agent-{i % 7}"), decision=Decision.ALLOW,
                     outcome=Outcome.OK)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(append, range(400)))

    status = audit.verify()
    assert status.intact, status.summary()
    assert status.events_checked == 400
    seqs = [e.seq for e in store.iter_all(chunk=37)]
    assert seqs == list(range(1, 401)), "sequence numbers must be gapless and unique"
