"""Behavioural detection — is this call, in context, a sign something is wrong?

Policy asks whether a call is permitted. These detectors ask a different
question: this call is permitted, but does the *pattern* it belongs to look
like a misconfigured agent, a prompt-injected one, or someone using stolen
credentials? Every pattern below is something a legitimate integration can do
once and almost never does repeatedly.

Two rules the whole module obeys:

**Detectors describe, they never decide.** Each returns :class:`Signal` objects
with a weight. :class:`~.engine.GovernanceEngine` adds the weights up and
applies the thresholds. A heuristic that can refuse a call on its own is a
heuristic that can take down production by itself.

**Detectors are pure functions of a context.** No I/O, no clock access, no
shared state — the engine hands them history and the current time. That is why
they are straightforward to test: build a context, assert on the signals.

Each detector documents what it is actually looking for and, just as
importantly, how it produces false positives. A detector whose failure mode
you cannot describe is one you will end up ignoring in practice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from typing import Protocol, runtime_checkable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .events import AuditEvent, Decision, Operation, Outcome, Signal, ToolCall
from .policy import reason_code

_DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def parse_hours(spec: str) -> tuple[time, time]:
    """Parse ``"07:00-20:00"`` into a start and end time."""
    start_raw, _, end_raw = spec.partition("-")
    if not end_raw:
        raise ValueError(f"business hours must look like '07:00-20:00', got {spec!r}")

    def one(raw: str) -> time:
        hh, _, mm = raw.strip().partition(":")
        return time(hour=int(hh), minute=int(mm or 0))

    return one(start_raw), one(end_raw)


def parse_days(spec: str) -> frozenset[int]:
    """Parse ``"mon,tue,wed"`` into weekday numbers (Monday = 0)."""
    days = set()
    for token in spec.split(","):
        token = token.strip().lower()[:3]
        if not token:
            continue
        if token not in _DAY_NAMES:
            raise ValueError(f"unknown weekday {token!r}; use mon..sun")
        days.add(_DAY_NAMES.index(token))
    return frozenset(days)


@dataclass(frozen=True)
class DetectorConfig:
    """Thresholds for every detector.

    The defaults are set for a business-hours integration doing hundreds of
    reads and a handful of writes per day. An agent driving a nightly batch
    job will trip several of these until they are raised — which is the
    intended workflow: start noisy, tune down with real traffic, rather than
    start silent and hope.
    """

    # DeleteBurstDetector
    delete_burst_window: timedelta = timedelta(seconds=60)
    delete_burst_threshold: int = 3
    delete_burst_weight: int = 25

    # AllowlistProbingDetector
    probe_window: timedelta = timedelta(minutes=5)
    probe_threshold: int = 3
    probe_weight: int = 30

    # OffHoursDetector
    business_hours: tuple[time, time] = (time(7, 0), time(20, 0))
    business_days: frozenset[int] = frozenset({0, 1, 2, 3, 4, 5})
    business_timezone: str | None = None
    off_hours_weight: int = 10

    # RateAnomalyDetector
    rate_window: timedelta = timedelta(seconds=60)
    rate_threshold: int = 90
    rate_baseline_window: timedelta = timedelta(hours=6)
    rate_baseline_multiplier: float = 5.0
    rate_baseline_min_events: int = 50
    rate_weight: int = 15

    # MassReadDetector
    mass_read_window: timedelta = timedelta(minutes=10)
    mass_read_threshold: int = 5_000
    mass_read_weight: int = 20

    # PrivilegeDriftDetector
    drift_min_history: int = 25
    drift_weight: int = 8

    # WriteAmplificationDetector
    write_amplification_threshold: int = 100
    write_amplification_weight: int = 20

    # RepeatedErrorDetector
    error_window: timedelta = timedelta(minutes=5)
    error_threshold: int = 10
    error_weight: int = 12

    def tzinfo(self) -> ZoneInfo | None:
        if not self.business_timezone:
            return None
        try:
            return ZoneInfo(self.business_timezone)
        except (ZoneInfoNotFoundError, ValueError):
            return None


@dataclass
class DetectionContext:
    """Everything the detectors are allowed to look at."""

    call: ToolCall
    now: datetime
    config: DetectorConfig
    history: list[AuditEvent] = field(default_factory=list)
    """This actor's recent events, oldest first, already trimmed to the widest
    window any detector needs."""

    models_seen: frozenset[str] = frozenset()
    """Models this actor has previously been allowed to touch."""

    actor_event_count: int = 0
    """Lifetime event count for this actor, which may exceed ``len(history)``."""

    def within(self, window: timedelta) -> list[AuditEvent]:
        cutoff = self.now - window
        return [e for e in self.history if e.ts >= cutoff]


@runtime_checkable
class Detector(Protocol):
    name: str

    def window(self, config: DetectorConfig) -> timedelta:
        """How far back this detector needs to see."""

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        ...


class DeleteBurstDetector:
    """Several deletes in quick succession.

    Deleting records is the least reversible thing an agent can do, and real
    integrations delete rarely and one at a time. A rapid run of them is the
    signature of a loop that has lost its exit condition, or of an injected
    instruction being carried out enthusiastically.

    False positives: a genuine cleanup task. If you have one, give it its own
    actor identity so raising the threshold does not blind you everywhere else.
    """

    name = "delete_burst"

    def window(self, config: DetectorConfig) -> timedelta:
        return config.delete_burst_window

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        recent = [
            e
            for e in ctx.within(cfg.delete_burst_window)
            if e.operation is Operation.DELETE and e.decision.permits
        ]
        # The call being judged is a delete that has not been recorded yet.
        pending = 1 if ctx.call.operation is Operation.DELETE else 0
        total = len(recent) + pending
        if total < cfg.delete_burst_threshold:
            return []
        seconds = int(cfg.delete_burst_window.total_seconds())
        return [
            Signal(
                name=self.name,
                weight=cfg.delete_burst_weight,
                detail=(
                    f"{total} delete operations in {seconds}s "
                    f"(threshold {cfg.delete_burst_threshold})"
                ),
            )
        ]


class AllowlistProbingDetector:
    """Repeated attempts to reach models that are not allowed.

    One denied call is a bug or a confused agent. Several in a few minutes,
    especially across different models, is someone finding out what is
    reachable — the same shape as directory enumeration. This carries the
    heaviest weight in the default set, because unlike the others it has no
    benign high-volume explanation.

    False positives: an agent given a stale schema, retrying against models
    that were removed from the allowlist.
    """

    name = "allowlist_probing"

    def window(self, config: DetectorConfig) -> timedelta:
        return config.probe_window

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        blocked_codes = {
            "model_denied",
            "model_not_allowed",
            "model_not_writable",
            "model_not_deletable",
            "method_blocked",
            "method_private",
            "method_not_allowed",
            "sensitive_field",
        }
        denials = [
            e
            for e in ctx.within(cfg.probe_window)
            if e.decision is Decision.DENY
            and any(reason_code(r) in blocked_codes for r in e.reasons)
        ]
        if len(denials) < cfg.probe_threshold:
            return []
        distinct = {e.model for e in denials if e.model}
        minutes = int(cfg.probe_window.total_seconds() // 60)
        detail = (
            f"{len(denials)} denied access attempts in {minutes}m "
            f"across {len(distinct)} model(s)"
        )
        # Spreading attempts across many models looks far more like mapping the
        # database than hammering one model does, so it weighs more.
        weight = cfg.probe_weight + (5 * (len(distinct) - 1) if len(distinct) > 1 else 0)
        return [Signal(name=self.name, weight=weight, detail=detail)]


class OffHoursDetector:
    """Activity outside the window when a human would be around.

    On its own this means very little — it is weighted low deliberately. Its
    value is as a multiplier: a delete burst at 04:00 on a Sunday is a
    materially different event from the same burst on a Tuesday afternoon, and
    this is what makes the risk score reflect that.

    False positives: scheduled jobs, and any team spread across time zones.
    """

    name = "off_hours"

    def window(self, config: DetectorConfig) -> timedelta:
        return timedelta(0)

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        moment = ctx.call.ts
        tz = cfg.tzinfo()
        local = moment.astimezone(tz) if tz else moment.astimezone()

        start, end = cfg.business_hours
        in_hours = start <= local.time() <= end if start <= end else (
            # A window that wraps midnight, e.g. 22:00-06:00.
            local.time() >= start or local.time() <= end
        )
        in_days = local.weekday() in cfg.business_days

        if in_hours and in_days:
            return []
        why = []
        if not in_days:
            why.append(f"{_DAY_NAMES[local.weekday()]} is outside BUSINESS_DAYS")
        if not in_hours:
            why.append(
                f"{local.strftime('%H:%M')} is outside "
                f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')}"
            )
        return [
            Signal(name=self.name, weight=cfg.off_hours_weight, detail="; ".join(why))
        ]


class RateAnomalyDetector:
    """Call volume that spikes, either absolutely or against this actor's norm.

    Two separate conditions, reported separately because they mean different
    things. The absolute one catches a runaway loop. The relative one catches
    an actor that is quiet by nature suddenly getting busy — which is what a
    stolen token looks like, and which an absolute threshold tuned for your
    noisiest integration would never see.

    False positives: the first legitimate bulk run by an actor whose baseline
    was built from light traffic.
    """

    name = "rate_anomaly"

    def window(self, config: DetectorConfig) -> timedelta:
        return max(config.rate_window, config.rate_baseline_window)

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        recent = ctx.within(cfg.rate_window)
        count = len(recent) + 1  # include the call being judged
        signals: list[Signal] = []
        seconds = int(cfg.rate_window.total_seconds())

        if count > cfg.rate_threshold:
            signals.append(
                Signal(
                    name=self.name,
                    weight=cfg.rate_weight,
                    detail=f"{count} calls in {seconds}s (threshold {cfg.rate_threshold})",
                )
            )

        baseline_events = ctx.within(cfg.rate_baseline_window)
        if len(baseline_events) >= cfg.rate_baseline_min_events:
            windows = max(cfg.rate_baseline_window / cfg.rate_window, 1.0)
            expected = len(baseline_events) / windows
            if expected > 0 and count > expected * cfg.rate_baseline_multiplier:
                signals.append(
                    Signal(
                        name=f"{self.name}_relative",
                        weight=cfg.rate_weight,
                        detail=(
                            f"{count} calls in {seconds}s against a baseline of "
                            f"{expected:.1f} ({count / expected:.1f}x normal for this actor)"
                        ),
                    )
                )
        return signals


class MassReadDetector:
    """A large volume of records read over a short period.

    Exfiltration through a legitimate API does not look like an attack on any
    single call — each one is within the per-call cap and perfectly allowed.
    It only becomes visible when you add up what an actor has pulled, which is
    what this does. The per-call limit in :mod:`.policy` and this detector
    cover the two halves of the same problem.

    False positives: a genuine full sync or report run.
    """

    name = "mass_read"

    def window(self, config: DetectorConfig) -> timedelta:
        return config.mass_read_window

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        total = sum(
            e.affected_count or 0
            for e in ctx.within(cfg.mass_read_window)
            if e.operation is Operation.READ and e.decision.permits
        )
        if total < cfg.mass_read_threshold:
            return []
        minutes = int(cfg.mass_read_window.total_seconds() // 60)
        return [
            Signal(
                name=self.name,
                weight=cfg.mass_read_weight,
                detail=(
                    f"{total} records read in {minutes}m "
                    f"(threshold {cfg.mass_read_threshold})"
                ),
            )
        ]


class PrivilegeDriftDetector:
    """An actor touching a model it has never touched before.

    Integrations settle. After a few hundred calls, an actor's set of models is
    effectively fixed, and a new one appearing means its instructions changed —
    a deploy, a prompt edit, or an injection. Weighted low because the benign
    explanation is common; it earns its place by adding context to whatever
    else is firing at the same time.

    Suppressed until the actor has enough history to have a baseline at all,
    otherwise every call during warm-up is drift. Denied calls never teach the
    baseline, so being refused a model cannot normalise it.
    """

    name = "privilege_drift"

    def window(self, config: DetectorConfig) -> timedelta:
        return timedelta(0)  # works from the lifetime baseline, not the window

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        model = ctx.call.model
        if model is None or ctx.actor_event_count < cfg.drift_min_history:
            return []
        if model in ctx.models_seen:
            return []
        return [
            Signal(
                name=self.name,
                weight=cfg.drift_weight,
                detail=(
                    f"first access to {model!r} after {ctx.actor_event_count} calls "
                    f"against {len(ctx.models_seen)} other model(s)"
                ),
            )
        ]


class WriteAmplificationDetector:
    """One call that creates, writes or deletes an unusually large batch.

    Distinct from the per-call policy cap: that cap is a hard ceiling that
    refuses the call, while this flags batches well under the ceiling but far
    above routine. A write to 90 records is probably fine and probably worth
    knowing about. Flagging rather than refusing is the point — the cap already
    handles the cases worth refusing.

    False positives: legitimate bulk updates such as a price list revision.
    """

    name = "write_amplification"

    def window(self, config: DetectorConfig) -> timedelta:
        return timedelta(0)

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        call = ctx.call
        if not call.operation.mutates or call.record_count is None:
            return []
        if call.record_count <= cfg.write_amplification_threshold:
            return []
        return [
            Signal(
                name=self.name,
                weight=cfg.write_amplification_weight,
                detail=(
                    f"single {call.operation.value} affecting {call.record_count} records "
                    f"(flag threshold {cfg.write_amplification_threshold})"
                ),
            )
        ]


class RepeatedErrorDetector:
    """A run of failing calls.

    Healthy integrations mostly succeed. A burst of errors means the agent is
    guessing — wrong field names, malformed domains, invalid ids — which is
    both a reliability signal and, when the guesses are about schema, how
    someone maps a database they do not have documentation for.

    False positives: Odoo being down, or a migration that changed fields under
    a running agent. Both are things you want to be told about anyway.
    """

    name = "repeated_errors"

    def window(self, config: DetectorConfig) -> timedelta:
        return config.error_window

    def evaluate(self, ctx: DetectionContext) -> list[Signal]:
        cfg = ctx.config
        errors = [e for e in ctx.within(cfg.error_window) if e.outcome is Outcome.ERROR]
        if len(errors) < cfg.error_threshold:
            return []
        kinds = {e.error_type for e in errors if e.error_type}
        minutes = int(cfg.error_window.total_seconds() // 60)
        detail = f"{len(errors)} failed calls in {minutes}m"
        if kinds:
            detail += f" ({', '.join(sorted(kinds)[:3])})"
        return [Signal(name=self.name, weight=cfg.error_weight, detail=detail)]


def default_detectors() -> list[Detector]:
    """The detector set the server runs unless told otherwise.

    Ordered roughly by how much the signal is worth on its own, which is also
    the order they read best in on the dashboard.
    """
    return [
        AllowlistProbingDetector(),
        DeleteBurstDetector(),
        MassReadDetector(),
        WriteAmplificationDetector(),
        RateAnomalyDetector(),
        RepeatedErrorDetector(),
        PrivilegeDriftDetector(),
        OffHoursDetector(),
    ]
