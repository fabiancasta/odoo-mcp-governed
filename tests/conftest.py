"""Shared fixtures and builders for the governance tests.

The tests drive a controllable clock rather than real time, because every
detector in the system is a statement about *when* things happened. Sleeping
to make a window elapse would make the suite slow and flaky; advancing a fake
clock makes it exact.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from odoo_mcp_governed.governance import (
    AuditLog,
    AuditStore,
    DetectorConfig,
    GovernanceEngine,
    Operation,
    PolicyConfig,
    PolicyEngine,
    RiskConfig,
    ToolCall,
)

# A Tuesday at 10:00 UTC — inside the default business window, so tests that
# are not about off-hours detection do not trip it by accident.
BASE_TIME = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """A clock the tests move by hand."""

    def __init__(self, start: datetime = BASE_TIME) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float = 0, minutes: float = 0, hours: float = 0) -> datetime:
        self.now += timedelta(seconds=seconds, minutes=minutes, hours=hours)
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store() -> AuditStore:
    return AuditStore(":memory:")


@pytest.fixture
def audit(store: AuditStore) -> AuditLog:
    return AuditLog(store)


@pytest.fixture
def policy_config() -> PolicyConfig:
    """A realistic, deliberately narrow permission set.

    Reads on partners and products, writes only on partners, deletes only on
    a scratch model. This asymmetry is what the policy tests exercise.
    """
    return PolicyConfig(
        allowed_models=frozenset(
            {"res.partner", "product.template", "sale.order", "mail.activity"}
        ),
        writable_models=frozenset({"res.partner", "mail.activity"}),
        deletable_models=frozenset({"mail.activity"}),
        max_records_per_call=500,
        allow_execute_method=True,
        execute_method_allowlist=frozenset({"action_confirm", "message_post"}),
    )


@pytest.fixture
def detector_config() -> DetectorConfig:
    """Default thresholds, but with the business timezone pinned to UTC.

    Without pinning, ``OffHoursDetector`` resolves the business window against
    the *host's* local time, so BASE_TIME would land inside business hours in
    London and outside it in Bogota — the suite would pass or fail depending
    on the developer's machine. Pinning it here keeps every other test free of
    an off-hours signal it never asked for; the off-hours tests set their own
    times explicitly.
    """
    return DetectorConfig(business_timezone="UTC")


@pytest.fixture
def engine(
    audit: AuditLog,
    policy_config: PolicyConfig,
    detector_config: DetectorConfig,
    clock: FakeClock,
) -> GovernanceEngine:
    return GovernanceEngine(
        audit=audit,
        policy=PolicyEngine(policy_config),
        detector_config=detector_config,
        # Throttling is a real ``time.sleep``, so the shared fixture sets it to
        # zero: otherwise any test that happens to push an actor over the
        # throttle threshold silently adds seconds to the suite. The fact that
        # throttling actually delays is covered by its own test instead.
        risk_config=RiskConfig(throttle_seconds=0.0),
        now_fn=clock,
    )


def make_call(
    clock: FakeClock,
    *,
    actor: str = "agent-a",
    tool: str = "search_records",
    operation: Operation = Operation.READ,
    model: str | None = "res.partner",
    method: str | None = None,
    record_count: int | None = None,
    fields: tuple[str, ...] = (),
    profile: str = "default",
) -> ToolCall:
    """Build a ToolCall stamped with the fake clock's current time."""
    return ToolCall(
        actor=actor,
        profile=profile,
        tool=tool,
        operation=operation,
        model=model,
        method=method,
        fields_touched=fields,
        record_count=record_count,
        arg_digest="test",
        ts=clock.now,
    )
