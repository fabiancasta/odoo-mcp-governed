"""End-to-end risk behaviour under realistic agent traffic.

The unit tests prove each detector fires on its pattern. These prove the
system as a whole stays usable: an ordinary assistant session must never be
throttled or blocked, while the patterns governance exists for still are.

They were written after a live session against a real Odoo was blocked within
a few minutes of normal use — the score climbed 31 -> 47 -> 76 -> 159 because
every call re-emitted the same "state" signals (relative rate, off-hours,
drift) and the scorer summed them, and calls that were already refused kept
feeding the score, so the actor could never cool off.
"""

from __future__ import annotations

from odoo_mcp_governed.governance import (
    Decision,
    DetectorConfig,
    GovernanceDenied,
    GovernanceEngine,
    Operation,
    PolicyConfig,
    PolicyEngine,
    RiskConfig,
)
from odoo_mcp_governed.governance.audit import AuditLog

from .conftest import FakeClock, make_call

MODELS = (
    "res.partner",
    "product.template",
    "product.product",
    "sale.order",
    "sale.order.line",
    "account.move",
    "account.move.line",
    "res.company",
    "res.currency",
    "res.country",
)


def permissive_engine(audit: AuditLog, clock: FakeClock, **detector) -> GovernanceEngine:
    """The owner's local setup: everything allowed, detectors at defaults."""
    return GovernanceEngine(
        audit=audit,
        policy=PolicyEngine(
            PolicyConfig(
                allowed_models=frozenset({"*"}),
                writable_models=frozenset({"*"}),
                deletable_models=frozenset({"*"}),
                max_records_per_call=500,
            )
        ),
        detector_config=DetectorConfig(business_timezone="UTC", **detector),
        risk_config=RiskConfig(throttle_seconds=0.0),
        now_fn=clock,
    )


def run(engine: GovernanceEngine, call, *, affected: int = 5, fail: bool = False) -> Decision:
    try:
        with engine.guard(call) as guarded:
            guarded.affected(affected)
            if fail:
                raise ValueError("Invalid field 'x' on model")
    except GovernanceDenied as denied:
        return denied.judgement.decision
    except ValueError:
        pass
    return engine.audit.tail(1)[0].decision


def assistant_session(
    engine: GovernanceEngine, clock: FakeClock, *, minutes: int, per_minute: int = 40
) -> list[Decision]:
    """An assistant exploring and editing: mostly reads across many models, a
    few writes, the occasional wrong field name."""
    decisions = []
    step = 60.0 / per_minute
    for i in range(minutes * per_minute):
        model = MODELS[i % len(MODELS)]
        if i % 15 == 7:
            call = make_call(
                clock, tool="update_record", operation=Operation.WRITE,
                model=model, record_count=1,
            )
            decisions.append(run(engine, call, affected=1))
        else:
            call = make_call(clock, model=model, record_count=20)
            decisions.append(run(engine, call, affected=8, fail=(i % 20 == 19)))
        clock.advance(seconds=step)
    return decisions


def worst(decisions: list[Decision]) -> set[Decision]:
    return {d for d in decisions if d in (Decision.THROTTLE, Decision.DENY)}


class TestOrdinaryUseIsNeverImpeded:
    def test_a_normal_assistant_session(self, audit: AuditLog, clock: FakeClock) -> None:
        engine = permissive_engine(audit, clock)
        decisions = assistant_session(engine, clock, minutes=10)
        assert not worst(decisions), f"normal session impeded: {worst(decisions)}"

    def test_a_second_session_after_a_break(self, audit: AuditLog, clock: FakeClock) -> None:
        """Agents are bursty: busy for ten minutes, idle for two hours, busy
        again. The second burst looks 'unusual' against an average that
        includes the idle time, and must still not be punished for it."""
        engine = permissive_engine(audit, clock)
        assistant_session(engine, clock, minutes=5)
        clock.advance(hours=2)
        decisions = assistant_session(engine, clock, minutes=10)
        assert not worst(decisions), f"second session impeded: {worst(decisions)}"

    def test_working_late_is_noted_not_punished(self, audit: AuditLog, clock: FakeClock) -> None:
        """Off-hours is context, weight 10. It used to be re-added on every
        call, so the fourth call at night was throttled."""
        clock.now = clock.now.replace(hour=23)
        engine = permissive_engine(audit, clock)
        decisions = assistant_session(engine, clock, minutes=5, per_minute=20)
        assert not worst(decisions), f"off-hours session impeded: {worst(decisions)}"
        assert Decision.ALLOW_FLAGGED in decisions


class TestRealThreatsAreStillStopped:
    def delete(self, engine: GovernanceEngine, clock: FakeClock) -> tuple[Decision, int]:
        call = make_call(
            clock, tool="delete_record", operation=Operation.DELETE,
            model="res.partner", record_count=1,
        )
        judgement = engine.review(call)
        return run(engine, call, affected=1), judgement.risk_score

    def test_a_delete_burst_escalates_to_a_block(self, audit: AuditLog, clock: FakeClock) -> None:
        """Every delete is new evidence, so this signal must keep adding up:
        0 -> 0 -> 25 -> 50 -> 75 (blocked)."""
        engine = permissive_engine(audit, clock)
        results = []
        for _ in range(5):
            results.append(self.delete(engine, clock))
            clock.advance(seconds=5)
        decisions = [d for d, _ in results]
        scores = [s for _, s in results]
        assert decisions[:2] == [Decision.ALLOW, Decision.ALLOW]
        assert decisions[2] is Decision.ALLOW_FLAGGED
        assert decisions[3] is Decision.THROTTLE
        assert decisions[4] is Decision.DENY
        assert scores[2:] == [25, 50, 75]

    def test_a_blocked_actor_cools_off_even_while_still_calling(
        self, audit: AuditLog, clock: FakeClock
    ) -> None:
        """Refused calls must not keep the score up. Otherwise an agent that
        keeps retrying after a block — which agents do — is locked out for as
        long as it keeps trying, and the operator disables governance."""
        engine = permissive_engine(audit, clock)
        for _ in range(5):
            self.delete(engine, clock)
            clock.advance(seconds=5)

        recovered_after = None
        for second in range(0, 45 * 60, 3):
            call = make_call(clock, model="res.partner", record_count=10)
            if run(engine, call) is not Decision.DENY:
                recovered_after = second
                break
            clock.advance(seconds=3)
        assert recovered_after is not None, "actor never recovered while retrying"
        assert recovered_after < 30 * 60

    def test_the_score_has_a_ceiling(self, audit: AuditLog, clock: FakeClock) -> None:
        engine = permissive_engine(audit, clock)
        scores = []
        for _ in range(40):
            scores.append(self.delete(engine, clock)[1])
            clock.advance(seconds=1)
        assert max(scores) <= engine.risk.config.max_score


class TestRelativeRateBaseline:
    def test_a_fresh_actor_is_not_compared_against_its_own_burst(
        self, audit: AuditLog, clock: FakeClock
    ) -> None:
        """The baseline must come from before the current window and be
        averaged over the time the actor actually existed, not over six
        hours it was never around for."""
        engine = permissive_engine(audit, clock)
        decisions = assistant_session(engine, clock, minutes=3)
        names = {s.name for e in engine.audit.tail(500) for s in e.signals}
        assert "rate_anomaly_relative" not in names
        assert not worst(decisions)
