"""Tests for the behavioural detectors.

Every detector gets two tests at minimum: it fires on the pattern it claims to
catch, and it stays silent on ordinary traffic. The second half is the one
that keeps the system usable — a detector that fires on everything gets its
threshold raised to infinity by the first on-call engineer it wakes, and then
it may as well not exist.
"""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

import pytest

from odoo_mcp_governed.governance import (
    AuditEvent,
    Decision,
    DetectionContext,
    DetectorConfig,
    Operation,
    Outcome,
    Signal,
)
from odoo_mcp_governed.governance.detectors import (
    AllowlistProbingDetector,
    DeleteBurstDetector,
    MassReadDetector,
    OffHoursDetector,
    PrivilegeDriftDetector,
    RateAnomalyDetector,
    RepeatedErrorDetector,
    WriteAmplificationDetector,
    default_detectors,
    parse_days,
    parse_hours,
)

from .conftest import BASE_TIME, FakeClock, make_call


def event(
    ts: datetime,
    *,
    seq: int = 1,
    actor: str = "agent-a",
    operation: Operation = Operation.READ,
    model: str | None = "res.partner",
    decision: Decision = Decision.ALLOW,
    outcome: Outcome = Outcome.OK,
    reasons: tuple[str, ...] = (),
    affected_count: int | None = None,
    signals: tuple[Signal, ...] = (),
    error_type: str | None = None,
) -> AuditEvent:
    """A minimal audit event for feeding detector history."""
    return AuditEvent(
        seq=seq,
        ts=ts,
        actor=actor,
        profile="default",
        tool="t",
        operation=operation,
        model=model,
        method=None,
        fields_touched=(),
        arg_digest="d",
        decision=decision,
        reasons=reasons,
        signals=signals,
        risk_score=0,
        outcome=outcome,
        affected_count=affected_count,
        latency_ms=1,
        error_type=error_type,
        prev_hash="x",
        hash="y",
    )


def context(
    clock: FakeClock,
    config: DetectorConfig,
    history: list[AuditEvent] | None = None,
    **call_kwargs,
) -> DetectionContext:
    """Context for detectors that only need a call and history.

    Tests that also need ``models_seen`` or ``actor_event_count`` build
    :class:`DetectionContext` directly — keeping those out of here means every
    keyword this helper accepts belongs to the call, with no ambiguity about
    where an argument lands.
    """
    return DetectionContext(
        call=make_call(clock, **call_kwargs),
        now=clock.now,
        config=config,
        history=history or [],
    )


# --- parsing helpers -------------------------------------------------------


def test_parse_hours() -> None:
    assert parse_hours("07:00-20:00") == (time(7, 0), time(20, 0))
    assert parse_hours("9-17") == (time(9, 0), time(17, 0))


def test_parse_hours_rejects_nonsense() -> None:
    with pytest.raises(ValueError, match="07:00-20:00"):
        parse_hours("always")


def test_parse_days() -> None:
    assert parse_days("mon,tue,fri") == frozenset({0, 1, 4})
    assert parse_days("monday, Tuesday") == frozenset({0, 1})


def test_parse_days_rejects_unknown_weekday() -> None:
    with pytest.raises(ValueError, match="unknown weekday"):
        parse_days("mon,funday")


# --- DeleteBurstDetector ---------------------------------------------------


class TestDeleteBurst:
    detector = DeleteBurstDetector()

    def test_fires_on_rapid_deletes(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(clock.now - timedelta(seconds=s), operation=Operation.DELETE, seq=i)
            for i, s in enumerate((30, 20, 10), start=1)
        ]
        signals = self.detector.evaluate(
            context(
                clock, detector_config, history, operation=Operation.DELETE, model="mail.activity"
            )
        )
        assert len(signals) == 1
        assert signals[0].name == "delete_burst"
        assert "4 delete operations" in signals[0].detail

    def test_counts_the_pending_call(self, clock: FakeClock, detector_config) -> None:
        """Two past deletes plus the one being judged reaches the threshold of 3.

        The call under review has not been recorded yet, so a detector that
        only looked at history would always be one behind — it would catch the
        burst after the third delete had already happened.
        """
        history = [
            event(clock.now - timedelta(seconds=s), operation=Operation.DELETE, seq=i)
            for i, s in enumerate((20, 10), start=1)
        ]
        signals = self.detector.evaluate(
            context(clock, detector_config, history, operation=Operation.DELETE)
        )
        assert len(signals) == 1

    def test_silent_on_a_single_delete(self, clock: FakeClock, detector_config) -> None:
        assert self.detector.evaluate(
            context(clock, detector_config, [], operation=Operation.DELETE)
        ) == []

    def test_silent_on_reads(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(clock.now - timedelta(seconds=s), operation=Operation.READ, seq=i)
            for i, s in enumerate((30, 20, 10), start=1)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []

    def test_deletes_outside_the_window_do_not_count(
        self, clock: FakeClock, detector_config
    ) -> None:
        """Three deletes spread over an hour is maintenance, not a burst."""
        history = [
            event(clock.now - timedelta(minutes=m), operation=Operation.DELETE, seq=i)
            for i, m in enumerate((50, 30, 10), start=1)
        ]
        assert self.detector.evaluate(
            context(clock, detector_config, history, operation=Operation.DELETE)
        ) == []

    def test_denied_deletes_do_not_count(self, clock: FakeClock, detector_config) -> None:
        """A delete that was refused never happened, so it is not a delete.

        It still raises risk, but through the probing detector — counting it
        here too would double-penalise the same event.
        """
        history = [
            event(
                clock.now - timedelta(seconds=s),
                operation=Operation.DELETE,
                decision=Decision.DENY,
                outcome=Outcome.DENIED,
                seq=i,
            )
            for i, s in enumerate((30, 20, 10), start=1)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []


# --- AllowlistProbingDetector ---------------------------------------------


class TestAllowlistProbing:
    detector = AllowlistProbingDetector()

    def _denial(self, ts: datetime, model: str, seq: int = 1) -> AuditEvent:
        return event(
            ts,
            seq=seq,
            model=model,
            decision=Decision.DENY,
            outcome=Outcome.DENIED,
            reasons=(f"model_not_allowed: {model!r} is not in ALLOWED_MODELS",),
        )

    def test_fires_on_repeated_denials(self, clock: FakeClock, detector_config) -> None:
        history = [
            self._denial(clock.now - timedelta(seconds=s), m, seq=i)
            for i, (s, m) in enumerate(
                ((60, "res.users"), (40, "account.move"), (20, "ir.config_parameter")), start=1
            )
        ]
        signals = self.detector.evaluate(context(clock, detector_config, history))
        assert len(signals) == 1
        assert signals[0].name == "allowlist_probing"
        assert "3 denied access attempts" in signals[0].detail
        assert "3 model(s)" in signals[0].detail

    def test_weighs_breadth_more_than_repetition(
        self, clock: FakeClock, detector_config
    ) -> None:
        """Scanning many models is a map; retrying one is a bug.

        Both reach the threshold, but they do not mean the same thing, and the
        score has to reflect that or enumeration hides behind noise.
        """
        spread = [
            self._denial(clock.now - timedelta(seconds=s), m, seq=i)
            for i, (s, m) in enumerate(
                ((60, "res.users"), (40, "account.move"), (20, "ir.cron")), start=1
            )
        ]
        same = [
            self._denial(clock.now - timedelta(seconds=s), "res.users", seq=i)
            for i, s in enumerate((60, 40, 20), start=1)
        ]
        spread_weight = self.detector.evaluate(context(clock, detector_config, spread))[0].weight
        same_weight = self.detector.evaluate(context(clock, detector_config, same))[0].weight
        assert spread_weight > same_weight

    def test_silent_below_the_threshold(self, clock: FakeClock, detector_config) -> None:
        history = [self._denial(clock.now - timedelta(seconds=10), "res.users")]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []

    def test_ignores_denials_for_unrelated_reasons(
        self, clock: FakeClock, detector_config
    ) -> None:
        """Hitting the volume cap repeatedly is clumsiness, not reconnaissance."""
        history = [
            event(
                clock.now - timedelta(seconds=s),
                seq=i,
                decision=Decision.DENY,
                outcome=Outcome.DENIED,
                reasons=("volume_exceeded: 900 records requested, limit is 500",),
            )
            for i, s in enumerate((60, 40, 20), start=1)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []

    def test_ignores_successful_calls(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(clock.now - timedelta(seconds=s), seq=i) for i, s in enumerate((60, 40, 20), 1)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []


# --- OffHoursDetector ------------------------------------------------------


class TestOffHours:
    detector = OffHoursDetector()

    def test_silent_during_business_hours(self, detector_config) -> None:
        clock = FakeClock(BASE_TIME)  # Tuesday 10:00 UTC
        assert self.detector.evaluate(context(clock, detector_config)) == []

    def test_fires_at_night(self, detector_config) -> None:
        clock = FakeClock(datetime(2026, 10, 6, 3, 30, tzinfo=timezone.utc))
        signals = self.detector.evaluate(context(clock, detector_config))
        assert len(signals) == 1
        assert "03:30" in signals[0].detail

    def test_fires_on_a_non_business_day(self, detector_config) -> None:
        clock = FakeClock(datetime(2026, 10, 4, 10, 0, tzinfo=timezone.utc))  # Sunday
        signals = self.detector.evaluate(context(clock, detector_config))
        assert len(signals) == 1
        assert "sun" in signals[0].detail

    def test_weight_is_low_by_design(self, detector_config) -> None:
        """On its own, off-hours activity must not approach any threshold.

        Its job is to add context to another signal, not to raise an alert by
        itself — plenty of legitimate automation runs at 04:00.
        """
        clock = FakeClock(datetime(2026, 10, 6, 3, 30, tzinfo=timezone.utc))
        signal = self.detector.evaluate(context(clock, detector_config))[0]
        assert signal.weight < 20

    def test_window_that_wraps_midnight(self) -> None:
        """A night-shift operation configured as 22:00-06:00."""
        config = DetectorConfig(
            business_hours=(time(22, 0), time(6, 0)),
            business_days=frozenset(range(7)),
            business_timezone="UTC",
        )
        inside = FakeClock(datetime(2026, 10, 6, 23, 30, tzinfo=timezone.utc))
        also_inside = FakeClock(datetime(2026, 10, 6, 2, 0, tzinfo=timezone.utc))
        outside = FakeClock(datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc))

        assert self.detector.evaluate(context(inside, config)) == []
        assert self.detector.evaluate(context(also_inside, config)) == []
        assert len(self.detector.evaluate(context(outside, config))) == 1

    def test_respects_the_configured_timezone(self) -> None:
        """14:00 UTC is 09:00 in Bogota: inside the window there, and the
        detector must judge by the configured zone, not UTC."""
        clock = FakeClock(datetime(2026, 10, 6, 14, 0, tzinfo=timezone.utc))
        bogota = DetectorConfig(business_timezone="America/Bogota")
        utc = DetectorConfig(
            business_hours=(time(7, 0), time(13, 0)), business_timezone="UTC"
        )
        assert self.detector.evaluate(context(clock, bogota)) == []
        assert len(self.detector.evaluate(context(clock, utc))) == 1


# --- RateAnomalyDetector ---------------------------------------------------


class TestRateAnomaly:
    detector = RateAnomalyDetector()

    def test_silent_on_normal_traffic(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(clock.now - timedelta(seconds=s), seq=i) for i, s in enumerate(range(0, 50, 5), 1)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []

    def test_fires_on_an_absolute_spike(self, clock: FakeClock, detector_config) -> None:
        history = [event(clock.now - timedelta(seconds=1), seq=i) for i in range(100)]
        signals = self.detector.evaluate(context(clock, detector_config, history))
        assert any(s.name == "rate_anomaly" for s in signals)

    def test_fires_when_a_quiet_actor_suddenly_gets_busy(self, detector_config) -> None:
        """The stolen-token shape: well under any absolute threshold, but far
        above what this particular actor has ever done."""
        clock = FakeClock(BASE_TIME)
        # A light baseline: 60 calls spread over six hours.
        history = [
            event(clock.now - timedelta(hours=6) + timedelta(minutes=6 * i), seq=i)
            for i in range(60)
        ]
        # Then 30 calls in the last minute.
        history += [
            event(clock.now - timedelta(seconds=i), seq=1000 + i) for i in range(30)
        ]
        signals = self.detector.evaluate(context(clock, detector_config, history))
        names = {s.name for s in signals}
        assert "rate_anomaly_relative" in names
        assert "rate_anomaly" not in names, "30 calls/min is below the absolute threshold of 90"

    def test_relative_check_needs_a_baseline(self, clock: FakeClock, detector_config) -> None:
        """With almost no history there is no 'normal' to deviate from, so the
        relative check must stay quiet rather than flag every new actor."""
        history = [event(clock.now - timedelta(seconds=i), seq=i) for i in range(5)]
        signals = self.detector.evaluate(context(clock, detector_config, history))
        assert not any(s.name == "rate_anomaly_relative" for s in signals)


# --- MassReadDetector ------------------------------------------------------


class TestMassRead:
    detector = MassReadDetector()

    def test_fires_on_cumulative_volume(self, clock: FakeClock, detector_config) -> None:
        """Each call is individually legal and under the per-call cap; only the
        sum reveals the problem."""
        history = [
            event(
                clock.now - timedelta(seconds=30 * i),
                seq=i,
                operation=Operation.READ,
                affected_count=500,
            )
            for i in range(1, 12)
        ]
        signals = self.detector.evaluate(context(clock, detector_config, history))
        assert len(signals) == 1
        assert "5500 records read" in signals[0].detail

    def test_silent_on_routine_reads(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(
                clock.now - timedelta(seconds=30 * i),
                seq=i,
                operation=Operation.READ,
                affected_count=20,
            )
            for i in range(1, 12)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []

    def test_ignores_writes(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(
                clock.now - timedelta(seconds=30),
                seq=i,
                operation=Operation.WRITE,
                affected_count=5000,
            )
            for i in range(1, 3)
        ]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []


# --- PrivilegeDriftDetector ------------------------------------------------


class TestPrivilegeDrift:
    detector = PrivilegeDriftDetector()

    def test_fires_on_a_new_model_for_an_established_actor(
        self, clock: FakeClock, detector_config
    ) -> None:
        ctx = DetectionContext(
            call=make_call(clock, model="account.move"),
            now=clock.now,
            config=detector_config,
            history=[],
            models_seen=frozenset({"res.partner", "product.template"}),
            actor_event_count=200,
        )
        signals = self.detector.evaluate(ctx)
        assert len(signals) == 1
        assert "account.move" in signals[0].detail

    def test_silent_on_a_familiar_model(self, clock: FakeClock, detector_config) -> None:
        ctx = DetectionContext(
            call=make_call(clock, model="res.partner"),
            now=clock.now,
            config=detector_config,
            models_seen=frozenset({"res.partner"}),
            actor_event_count=200,
        )
        assert self.detector.evaluate(ctx) == []

    def test_silent_during_warm_up(self, clock: FakeClock, detector_config) -> None:
        """A brand-new actor has no baseline, so everything would be 'drift'.

        Without this guard the detector would fire on every call of an
        integration's first day and teach everyone to ignore it.
        """
        ctx = DetectionContext(
            call=make_call(clock, model="account.move"),
            now=clock.now,
            config=detector_config,
            models_seen=frozenset({"res.partner"}),
            actor_event_count=3,
        )
        assert self.detector.evaluate(ctx) == []

    def test_silent_when_no_model_is_involved(self, clock: FakeClock, detector_config) -> None:
        ctx = DetectionContext(
            call=make_call(clock, tool="server_status", operation=Operation.ADMIN, model=None),
            now=clock.now,
            config=detector_config,
            actor_event_count=200,
        )
        assert self.detector.evaluate(ctx) == []


# --- WriteAmplificationDetector -------------------------------------------


class TestWriteAmplification:
    detector = WriteAmplificationDetector()

    def test_fires_on_a_large_batch_write(self, clock: FakeClock, detector_config) -> None:
        signals = self.detector.evaluate(
            context(
                clock,
                detector_config,
                operation=Operation.WRITE,
                model="res.partner",
                record_count=250,
            )
        )
        assert len(signals) == 1
        assert "250 records" in signals[0].detail

    def test_silent_on_a_small_write(self, clock: FakeClock, detector_config) -> None:
        assert self.detector.evaluate(
            context(clock, detector_config, operation=Operation.WRITE, record_count=3)
        ) == []

    def test_ignores_large_reads(self, clock: FakeClock, detector_config) -> None:
        """Reads are MassReadDetector's business; double-counting would make a
        normal paginated search look like two problems."""
        assert self.detector.evaluate(
            context(clock, detector_config, operation=Operation.READ, record_count=400)
        ) == []


# --- RepeatedErrorDetector -------------------------------------------------


class TestRepeatedErrors:
    detector = RepeatedErrorDetector()

    def test_fires_on_a_run_of_failures(self, clock: FakeClock, detector_config) -> None:
        history = [
            event(
                clock.now - timedelta(seconds=10 * i),
                seq=i,
                outcome=Outcome.ERROR,
                error_type="ValidationError",
            )
            for i in range(1, 12)
        ]
        signals = self.detector.evaluate(context(clock, detector_config, history))
        assert len(signals) == 1
        assert "11 failed calls" in signals[0].detail
        assert "ValidationError" in signals[0].detail

    def test_silent_on_occasional_failures(self, clock: FakeClock, detector_config) -> None:
        history = [event(clock.now - timedelta(seconds=10), outcome=Outcome.ERROR, seq=1)]
        assert self.detector.evaluate(context(clock, detector_config, history)) == []


# --- the default set as a whole --------------------------------------------


def test_default_set_is_silent_on_ordinary_traffic(clock: FakeClock, detector_config) -> None:
    """The most important test in the file.

    A realistic workload — steady reads, a couple of small writes, during
    business hours — must produce zero signals. If this fails, every alert the
    system raises is noise and nobody will read any of them.
    """
    history = [
        event(
            clock.now - timedelta(minutes=i),
            seq=i,
            operation=Operation.WRITE if i % 10 == 0 else Operation.READ,
            affected_count=1 if i % 10 == 0 else 15,
        )
        for i in range(1, 40)
    ]
    ctx = DetectionContext(
        call=make_call(clock, model="res.partner", record_count=20),
        now=clock.now,
        config=detector_config,
        history=history,
        models_seen=frozenset({"res.partner"}),
        actor_event_count=len(history),
    )
    signals = [s for d in default_detectors() for s in d.evaluate(ctx)]
    assert signals == [], f"unexpected signals on normal traffic: {signals}"


def test_every_default_detector_declares_a_window(detector_config) -> None:
    for detector in default_detectors():
        assert detector.window(detector_config) >= timedelta(0)
        assert detector.name
