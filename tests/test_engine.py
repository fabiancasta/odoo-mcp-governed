"""Tests for the engine that combines policy, detection, risk and audit.

The central property under test is the one-way relationship between policy and
risk: risk can narrow what policy permits, never widen it. If that inverted,
tuning a threshold would become a way to grant permissions, and the allowlist
would stop being the authority on what is allowed.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from odoo_mcp_governed.governance import (
    Decision,
    DetectorConfig,
    GovernanceDenied,
    GovernanceEngine,
    Operation,
    Outcome,
    PolicyConfig,
    PolicyEngine,
    RiskConfig,
    RiskScorer,
    Signal,
)
from odoo_mcp_governed.governance.audit import AuditLog

from .conftest import FakeClock, make_call


class TestReview:
    def test_ordinary_call_is_allowed_cleanly(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        judgement = engine.review(make_call(clock, record_count=10))
        assert judgement.decision is Decision.ALLOW
        assert judgement.signals == ()
        assert judgement.risk_score == 0
        assert judgement.permitted

    def test_policy_violation_is_denied(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        judgement = engine.review(make_call(clock, model="res.users"))
        assert judgement.decision is Decision.DENY
        assert not judgement.permitted
        assert "model_not_allowed" in judgement.policy.codes

    def test_flagged_but_allowed_when_only_signals_fire(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        """A single off-hours call is noted, not punished."""
        clock.now = clock.now.replace(hour=3)
        judgement = engine.review(make_call(clock, record_count=5))
        assert judgement.decision is Decision.ALLOW_FLAGGED
        assert judgement.permitted
        assert any(s.name == "off_hours" for s in judgement.signals)

    def test_review_writes_nothing(self, engine: GovernanceEngine, clock: FakeClock) -> None:
        """Reviewing must be free of side effects, or the detectors would see
        their own evaluations as traffic."""
        before = engine.audit.store.count()
        engine.review(make_call(clock))
        assert engine.audit.store.count() == before


class TestRiskCannotWidenPolicy:
    """The invariant that keeps the allowlist authoritative."""

    def test_zero_risk_does_not_rescue_a_forbidden_call(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        judgement = engine.review(make_call(clock, model="ir.config_parameter"))
        assert judgement.risk_score == 0, "a first-ever call carries no risk history"
        assert judgement.decision is Decision.DENY, "and yet it must still be refused"

    def test_denial_survives_any_threshold_setting(
        self, audit: AuditLog, policy_config: PolicyConfig, clock: FakeClock
    ) -> None:
        """Even with thresholds set so high nothing could ever trip them,
        policy denials stand."""
        engine = GovernanceEngine(
            audit=audit,
            policy=PolicyEngine(policy_config),
            detector_config=DetectorConfig(business_timezone="UTC"),
            risk_config=RiskConfig(throttle_threshold=10**6, block_threshold=10**6),
            now_fn=clock,
        )
        judgement = engine.review(make_call(clock, model="res.users"))
        assert judgement.decision is Decision.DENY

    def test_high_risk_blocks_an_otherwise_permitted_call(
        self, audit: AuditLog, policy_config: PolicyConfig, clock: FakeClock
    ) -> None:
        """And the relationship works in the direction it is supposed to."""
        engine = GovernanceEngine(
            audit=audit,
            policy=PolicyEngine(policy_config),
            detector_config=DetectorConfig(business_timezone="UTC"),
            risk_config=RiskConfig(throttle_threshold=5, block_threshold=10),
            now_fn=clock,
        )
        clock.now = clock.now.replace(hour=3)  # off_hours: weight 10
        judgement = engine.review(make_call(clock, model="res.partner"))
        assert judgement.decision is Decision.DENY
        assert any("risk_block" in r for r in judgement.reasons)


class TestRiskScoring:
    def test_current_signals_sum(self, clock: FakeClock) -> None:
        scorer = RiskScorer(RiskConfig())
        signals = [Signal("a", 10, ""), Signal("b", 25, "")]
        assert scorer.score(signals, [], clock.now) == 35

    def test_history_decays_with_the_half_life(self, clock: FakeClock) -> None:
        """A signal one half-life old counts half as much."""
        from .test_detectors import event

        scorer = RiskScorer(RiskConfig(half_life=timedelta(minutes=15)))
        old = event(clock.now - timedelta(minutes=15), signals=(Signal("x", 40, ""),))
        assert scorer.score([], [old], clock.now) == 20

        older = event(clock.now - timedelta(minutes=30), signals=(Signal("x", 40, ""),))
        assert scorer.score([], [older], clock.now) == 10

    def test_history_outside_the_window_is_ignored(self, clock: FakeClock) -> None:
        from .test_detectors import event

        scorer = RiskScorer(RiskConfig(window=timedelta(hours=1)))
        ancient = event(clock.now - timedelta(hours=5), signals=(Signal("x", 100, ""),))
        assert scorer.score([], [ancient], clock.now) == 0

    def test_an_actor_can_cool_off(self, clock: FakeClock) -> None:
        """Risk must be recoverable, or one bad afternoon disables an
        integration permanently and the operator turns governance off."""
        from .test_detectors import event

        scorer = RiskScorer(RiskConfig(half_life=timedelta(minutes=15)))
        spike = event(clock.now, signals=(Signal("x", 60, ""),))
        assert scorer.score([], [spike], clock.now) == 60

        later = clock.now + timedelta(hours=2)
        assert scorer.score([], [spike], later) == 0


class TestGuard:
    def test_successful_call_is_recorded(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        with engine.guard(make_call(clock, record_count=3)) as guarded:
            guarded.affected(3)

        events = engine.audit.tail()
        assert len(events) == 1
        assert events[0].decision is Decision.ALLOW
        assert events[0].outcome is Outcome.OK
        assert events[0].affected_count == 3
        assert engine.audit.verify().intact

    def test_denied_call_raises_and_is_recorded(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        """A refusal is evidence. Dropping it would blind the probing detector,
        which is built entirely out of refusals."""
        with pytest.raises(GovernanceDenied) as excinfo, engine.guard(
            make_call(clock, model="res.users")
        ):
            pytest.fail("the body must never run for a denied call")

        assert "res.users" in str(excinfo.value)
        events = engine.audit.tail()
        assert len(events) == 1
        assert events[0].outcome is Outcome.DENIED
        assert events[0].decision is Decision.DENY

    def test_failing_call_is_recorded_and_the_error_propagates(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        class OdooBoom(Exception):
            pass

        with pytest.raises(OdooBoom), engine.guard(make_call(clock)):
            raise OdooBoom("xmlrpc exploded")

        events = engine.audit.tail()
        assert len(events) == 1
        assert events[0].outcome is Outcome.ERROR
        assert events[0].error_type == "OdooBoom"

    def test_latency_is_measured(self, engine: GovernanceEngine, clock: FakeClock) -> None:
        with engine.guard(make_call(clock)) as guarded:
            guarded.affected(1)
        assert engine.audit.tail()[0].latency_ms >= 0

    def test_throttling_actually_delays_the_call(
        self, audit: AuditLog, policy_config: PolicyConfig, clock: FakeClock
    ) -> None:
        """Throttle has to cost real wall-clock time or it does nothing.

        Its purpose is to turn a runaway loop into a slow trickle so a human
        has time to notice. A throttle decision that returns immediately is
        just a log line.
        """
        import time as wallclock

        engine = GovernanceEngine(
            audit=audit,
            policy=PolicyEngine(policy_config),
            detector_config=DetectorConfig(business_timezone="UTC"),
            risk_config=RiskConfig(
                throttle_threshold=5, block_threshold=10**6, throttle_seconds=0.25
            ),
            now_fn=clock,
        )
        clock.now = clock.now.replace(hour=3)  # off_hours puts the score over 5

        started = wallclock.perf_counter()
        with engine.guard(make_call(clock)) as guarded:
            guarded.affected(1)
        elapsed = wallclock.perf_counter() - started

        assert elapsed >= 0.25
        assert engine.audit.tail()[0].decision is Decision.THROTTLE

    def test_a_delete_burst_eventually_gets_refused(
        self, audit: AuditLog, policy_config: PolicyConfig, clock: FakeClock
    ) -> None:
        """The end-to-end behaviour the governance layer exists for.

        Each delete is individually permitted — mail.activity is deletable.
        The pattern is what gets stopped, and only after the detector has
        something to detect.
        """
        engine = GovernanceEngine(
            audit=audit,
            policy=PolicyEngine(policy_config),
            detector_config=DetectorConfig(business_timezone="UTC"),
            risk_config=RiskConfig(throttle_threshold=20, block_threshold=40, throttle_seconds=0),
            now_fn=clock,
        )

        def attempt_delete() -> Decision:
            call = make_call(
                clock, tool="delete_record", operation=Operation.DELETE, model="mail.activity"
            )
            try:
                with engine.guard(call) as guarded:
                    guarded.affected(1)
                return engine.audit.tail()[0].decision
            except GovernanceDenied as denied:
                return denied.judgement.decision

        decisions = []
        for _ in range(6):
            decisions.append(attempt_delete())
            clock.advance(seconds=5)

        assert decisions[0] is Decision.ALLOW, "the first delete must not be impeded"
        assert decisions[1] is Decision.ALLOW, "nor the second — two is not a burst"
        assert Decision.DENY in decisions, f"the burst must end in refusal, got {decisions}"
        assert engine.audit.verify().intact


class TestResilience:
    def test_a_broken_detector_does_not_break_the_server(
        self, audit: AuditLog, policy_config: PolicyConfig, clock: FakeClock
    ) -> None:
        """A bug in one heuristic must not become an outage.

        Failing closed on a detector crash would mean any exception in
        statistical code takes down every Odoo integration. Failing open
        silently would be a blind spot. So: drop the detector, record that it
        was dropped, carry on.
        """

        class Exploding:
            name = "exploding"

            def window(self, config):
                return timedelta(0)

            def evaluate(self, ctx):
                raise RuntimeError("detector bug")

        engine = GovernanceEngine(
            audit=audit,
            policy=PolicyEngine(policy_config),
            detectors=[Exploding()],
            detector_config=DetectorConfig(business_timezone="UTC"),
            now_fn=clock,
        )
        judgement = engine.review(make_call(clock))
        assert judgement.permitted
        assert any(s.name == "detector_error" for s in judgement.signals)
        # The failure must not inflate the score, or a crashing detector would
        # throttle every actor on the server.
        assert judgement.risk_score == 0
        assert "detector bug" in judgement.signals[0].detail

    def test_actors_are_scored_independently(
        self, engine: GovernanceEngine, clock: FakeClock
    ) -> None:
        """One misbehaving agent must not raise another's risk."""
        for _ in range(4):
            call = make_call(
                clock,
                actor="noisy",
                tool="delete_record",
                operation=Operation.DELETE,
                model="mail.activity",
            )
            try:
                with engine.guard(call) as guarded:
                    guarded.affected(1)
            except GovernanceDenied:
                pass
            clock.advance(seconds=2)

        quiet = engine.review(make_call(clock, actor="quiet"))
        assert quiet.decision is Decision.ALLOW
        assert quiet.risk_score == 0


class TestSelfCheck:
    def test_passes_and_reports_config_warnings(
        self, engine: GovernanceEngine
    ) -> None:
        warnings = engine.self_check()
        assert engine.audit.verify().intact
        assert any("unkeyed" in w for w in warnings)

    def test_warns_about_a_permissive_config(
        self, audit: AuditLog, clock: FakeClock
    ) -> None:
        engine = GovernanceEngine(
            audit=audit,
            policy=PolicyEngine(PolicyConfig()),
            detector_config=DetectorConfig(business_timezone="UTC"),
            now_fn=clock,
        )
        warnings = engine.self_check()
        assert any("ALLOWED_MODELS is empty" in w for w in warnings)

    def test_no_unkeyed_warning_when_a_key_is_set(
        self, store, policy_config: PolicyConfig, clock: FakeClock
    ) -> None:
        engine = GovernanceEngine(
            audit=AuditLog(store, hmac_key=b"k"),
            policy=PolicyEngine(policy_config),
            detector_config=DetectorConfig(business_timezone="UTC"),
            now_fn=clock,
        )
        assert not any("unkeyed" in w for w in engine.self_check())
