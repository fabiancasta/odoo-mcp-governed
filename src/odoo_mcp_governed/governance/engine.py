"""The governance engine — the only path from a tool to Odoo.

Every call goes through :meth:`GovernanceEngine.review`, which is the single
place the three subsystems are combined:

1. :mod:`.policy` rules on whether the call is permitted at all.
2. :mod:`.detectors` describe what the call looks like in context.
3. The risk score turns those descriptions, plus the actor's recent history,
   into one number, and thresholds turn that number into a decision.

The ordering is not arbitrary. Policy runs first and its denial is final: no
risk score can make a forbidden call allowed, and a low score cannot override
the allowlist. Risk can only ever *narrow* what policy already permitted. A
system where a statistical score can widen permissions is a system where
tuning a threshold is a privilege escalation.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .audit import AuditLog
from .detectors import DetectionContext, Detector, DetectorConfig, default_detectors
from .events import AuditEvent, Decision, Operation, Outcome, Signal, ToolCall, utcnow
from .policy import PolicyEngine, PolicyVerdict, reason_code

RISK_BLOCK = "risk_block"


class GovernanceDenied(Exception):
    """Raised instead of reaching Odoo when a call is refused.

    Carries the full reasoning so the caller can tell the agent *why* — an
    agent told only "denied" will retry; one told "res.users is not in
    ALLOWED_MODELS" will stop.
    """

    def __init__(self, judgement: Judgement) -> None:
        self.judgement = judgement
        super().__init__(judgement.explain())


@dataclass(frozen=True)
class RiskConfig:
    throttle_threshold: int = 40
    """Score at which calls still succeed but are deliberately slowed."""

    block_threshold: int = 70
    """Score at which otherwise-permitted calls are refused."""

    half_life: timedelta = timedelta(minutes=15)
    """How fast past signals stop counting. Short enough that a one-off
    anomaly does not haunt an actor all day; long enough that an attacker
    cannot wait out the score in a coffee break."""

    window: timedelta = timedelta(hours=1)
    """How far back the score looks at all."""

    throttle_seconds: float = 2.0
    """Delay applied per call while an actor is throttled. The point is to
    turn a fast loop into a slow one, buying a human time to notice without
    breaking a correct integration that merely looks unusual."""

    max_score: int = 100
    """Ceiling on the score. Past the block threshold a bigger number decides
    nothing, and an unbounded one takes unboundedly long to decay."""

    cumulative_signals: frozenset[str] = frozenset({"delete_burst", "write_amplification"})
    """Signals where every occurrence is new evidence and must add up: the
    fifth delete in a burst is worse than the third. Every other signal
    describes a *state* — off-hours, a high rate, an unfamiliar model — that
    each call in that state reports again; those count once, at their
    strongest decayed weight, or ordinary use compounds into a block."""


@dataclass
class Judgement:
    """The outcome of reviewing a call, before it runs."""

    call: ToolCall
    decision: Decision
    policy: PolicyVerdict
    signals: tuple[Signal, ...] = ()
    risk_score: int = 0
    reasons: tuple[str, ...] = ()
    throttle_seconds: float = 0.0

    @property
    def permitted(self) -> bool:
        return self.decision.permits

    def explain(self) -> str:
        head = f"{self.call.describe()} -> {self.decision.value}"
        if self.reasons:
            head += " | " + "; ".join(self.reasons)
        if self.signals:
            head += " | signals: " + ", ".join(f"{s.name}({s.weight})" for s in self.signals)
        if self.risk_score:
            head += f" | risk {self.risk_score}"
        return head


class RiskScorer:
    """Turns signals plus history into a single decayed score per actor.

    Past signals are discounted by an exponential half-life. The reason the
    score is not simply "weights of the current call" is that the patterns
    worth catching are built out of individually unremarkable calls — the
    third delete in a row is only alarming because of the first two. Equally,
    the reason history decays is that an actor which tripped a detector last
    Tuesday should not be permanently degraded.
    """

    def __init__(self, config: RiskConfig) -> None:
        self.config = config

    def score(
        self, current: Sequence[Signal], history: Sequence[AuditEvent], now: datetime
    ) -> int:
        cfg = self.config
        half_life = cfg.half_life.total_seconds()
        cutoff = now - cfg.window
        cumulative = 0.0
        state: dict[str, float] = {}

        def add(signal: Signal, decay: float) -> None:
            nonlocal cumulative
            weight = signal.weight * decay
            if signal.name in cfg.cumulative_signals:
                cumulative += weight
            elif weight > state.get(signal.name, 0.0):
                state[signal.name] = weight

        for signal in current:
            add(signal, 1.0)

        for event in history:
            if event.ts < cutoff or not event.signals:
                continue
            # A call refused *because* of risk is a consequence of the score,
            # not new evidence. Letting it count would keep an actor that
            # retries after a block locked out for as long as it retries.
            if any(reason_code(r) == RISK_BLOCK for r in event.reasons):
                continue
            age = max((now - event.ts).total_seconds(), 0.0)
            decay = 0.5 ** (age / half_life) if half_life > 0 else 0.0
            for signal in event.signals:
                add(signal, decay)

        return min(int(round(cumulative + sum(state.values()))), cfg.max_score)


class GovernanceEngine:
    """Combines policy, detection, risk scoring and the audit log."""

    def __init__(
        self,
        audit: AuditLog,
        policy: PolicyEngine,
        *,
        detectors: list[Detector] | None = None,
        detector_config: DetectorConfig | None = None,
        risk_config: RiskConfig | None = None,
        now_fn: Callable[[], datetime] = utcnow,
    ) -> None:
        self.audit = audit
        self.policy = policy
        self.detectors = detectors if detectors is not None else default_detectors()
        self.detector_config = detector_config or DetectorConfig()
        self.risk = RiskScorer(risk_config or RiskConfig())
        self._now = now_fn
        self._actor_locks: dict[str, threading.Lock] = {}
        self._actor_locks_guard = threading.Lock()

    def _actor_lock(self, actor: str) -> threading.Lock:
        with self._actor_locks_guard:
            lock = self._actor_locks.get(actor)
            if lock is None:
                lock = self._actor_locks[actor] = threading.Lock()
            return lock

    # -- review ------------------------------------------------------------

    def review(self, call: ToolCall) -> Judgement:
        """Decide what happens to ``call``. Performs no Odoo access and no writes."""
        now = self._now()
        verdict = self.policy.evaluate(call)
        signals = self._collect_signals(call, now)
        history = self._history(call.actor, now, self.risk.config.window)
        score = self.risk.score(signals, history, now)

        reasons = list(verdict.reasons)
        cfg = self.risk.config

        if not verdict.allowed:
            decision = Decision.DENY
        elif score >= cfg.block_threshold:
            decision = Decision.DENY
            reasons.append(
                f"{RISK_BLOCK}: actor risk score {score} is at or above the block "
                f"threshold of {cfg.block_threshold}"
            )
        elif score >= cfg.throttle_threshold:
            decision = Decision.THROTTLE
            reasons.append(
                f"risk_throttle: actor risk score {score} is at or above the throttle "
                f"threshold of {cfg.throttle_threshold}"
            )
        elif signals:
            decision = Decision.ALLOW_FLAGGED
        else:
            decision = Decision.ALLOW

        return Judgement(
            call=call,
            decision=decision,
            policy=verdict,
            signals=tuple(signals),
            risk_score=score,
            reasons=tuple(reasons),
            throttle_seconds=cfg.throttle_seconds if decision is Decision.THROTTLE else 0.0,
        )

    def _collect_signals(self, call: ToolCall, now: datetime) -> list[Signal]:
        widest = max(
            (d.window(self.detector_config) for d in self.detectors),
            default=timedelta(0),
        )
        ctx = DetectionContext(
            call=call,
            now=now,
            config=self.detector_config,
            history=self._history(call.actor, now, widest),
            models_seen=frozenset(self.audit.store.models_seen(call.actor)),
            actor_event_count=self.audit.store.count_for_actor(call.actor),
        )
        signals: list[Signal] = []
        for detector in self.detectors:
            # One broken detector must not take the server down with it. A
            # governance layer that fails closed on its own bugs is a denial of
            # service; one that silently drops the detector is a blind spot.
            # So: drop the detector, and say so in the log.
            try:
                signals.extend(detector.evaluate(ctx))
            except Exception as exc:  # noqa: BLE001 - deliberate: see above
                signals.append(
                    Signal(
                        name="detector_error",
                        weight=0,
                        detail=f"{detector.name} raised {type(exc).__name__}: {exc}",
                    )
                )
        return signals

    def _history(self, actor: str, now: datetime, window: timedelta) -> list[AuditEvent]:
        if window <= timedelta(0):
            return []
        return self.audit.since(now - window, actor=actor)

    # -- recording ---------------------------------------------------------

    def record(
        self,
        judgement: Judgement,
        *,
        outcome: Outcome,
        affected_count: int | None = None,
        latency_ms: int = 0,
        error_type: str | None = None,
    ) -> AuditEvent:
        return self.audit.record(
            judgement.call,
            decision=judgement.decision,
            reasons=judgement.reasons,
            signals=judgement.signals,
            risk_score=judgement.risk_score,
            outcome=outcome,
            affected_count=affected_count,
            latency_ms=latency_ms,
            error_type=error_type,
        )

    # -- the wrapper tools actually use ------------------------------------

    @contextmanager
    def guard(self, call: ToolCall) -> Iterator[GuardedCall]:
        """Run a call under governance.

        Denied calls raise :class:`GovernanceDenied` *after* the denial is
        recorded — a refusal is itself evidence, and the probing detector is
        built entirely out of refusals, so losing them would blind it.

        The audit event is written once, after the outcome is known. That is a
        real tradeoff: if the process dies mid-call, the attempt leaves no
        trace. Recording intent before the call and outcome after would close
        that gap at the cost of doubling the log. For v1 the single event wins,
        and :meth:`self_check` verifies at startup that the log is writable so
        the common failure is caught before it matters rather than discovered
        during an incident.
        """
        # One governed call per actor at a time. Without this, an actor firing
        # ten deletes in parallel gets ten reviews that each see an empty
        # history — none has been recorded yet — and the burst detector never
        # fires. Concurrency would be a way around detection. Different actors
        # still run in parallel; only an actor's own stream is serialised, and
        # a throttle delay therefore slows that whole stream, as intended.
        with self._actor_lock(call.actor):
            judgement = self.review(call)

            if not judgement.permitted:
                self.record(judgement, outcome=Outcome.DENIED)
                raise GovernanceDenied(judgement)

            if judgement.throttle_seconds:
                time.sleep(judgement.throttle_seconds)

            guarded = GuardedCall(judgement=judgement)
            started = time.perf_counter()
            try:
                yield guarded
            except Exception as exc:
                self.record(
                    judgement,
                    outcome=Outcome.ERROR,
                    affected_count=guarded.affected_count,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    error_type=type(exc).__name__,
                )
                raise
            else:
                guarded.event = self.record(
                    judgement,
                    outcome=Outcome.OK,
                    affected_count=guarded.affected_count,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )

    def self_check(self) -> list[str]:
        """Startup sanity check. Returns warnings; raises only if unusable.

        Writing and verifying a real event is the only way to know the log
        works. A governance layer whose log silently fails is worse than no
        governance layer, because it reports success.
        """
        warnings = list(self.policy.config.validate())

        probe = ToolCall(
            actor="system",
            profile="-",
            tool="self_check",
            operation=Operation.ADMIN,
        )
        self.audit.record(probe, decision=Decision.ALLOW, outcome=Outcome.OK)
        status = self.audit.verify()
        if not status.intact:
            raise RuntimeError(f"audit log is not verifying at startup — {status.summary()}")

        if not self.audit.keyed:
            warnings.append(
                "audit chain is unkeyed: set AUDIT_HMAC_KEY so that someone with the "
                "database file alone cannot rewrite history undetected"
            )
        return warnings


@dataclass
class GuardedCall:
    """Handle yielded by :meth:`GovernanceEngine.guard`.

    The tool reports how many records it actually touched, which the detectors
    need and which is rarely knowable before the call: a search's result count
    is the whole point of running it.
    """

    judgement: Judgement
    affected_count: int | None = None
    event: AuditEvent | None = field(default=None, repr=False)

    def affected(self, count: int | None) -> None:
        self.affected_count = count

    @property
    def flagged(self) -> bool:
        return bool(self.judgement.signals)
